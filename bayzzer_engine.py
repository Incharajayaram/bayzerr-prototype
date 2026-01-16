import os
import time
import json
import logging
import random
import yaml
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional

from datalog_analysis.c_parser import CProgramParser
from datalog_analysis.derivation_graph import DerivationGraph
from bayesian_network.network_builder import BayesianNetworkBuilder
from bayesian_network.inference import BayesianInference
from fuzzer.directed_fuzzer import DirectedFuzzer, FuzzingResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BayzzerEngine")

@dataclass
class BugReport:
    """Represents a discovered unique bug."""
    target_line: int
    triggering_input: str  # hex or repr string
    time_found: float
    output: str

@dataclass
class CampaignStats:
    """Statistics for a fuzzing campaign."""
    total_time: float = 0.0
    rounds_run: int = 0
    unique_bugs: List[BugReport] = field(default_factory=list)
    targets_fuzzed: int = 0
    history: List[Dict] = field(default_factory=list)

class BayzzerEngine:
    """
    Main engine implementing the Bayzzer algorithm:
    Hybrid Fuzzing driven by Bayesian Network Analysis.
    """

    def __init__(self, c_file_path: str, work_dir: str = None, config_path: str = "config.yaml"):
        """
        Initialize the Bayzzer Engine.

        Args:
            c_file_path (str): Path to the C source file to analyze.
            work_dir (str, optional): Directory for temporary files. Defaults to current directory.
            config_path (str, optional): Path to YAML configuration file. Defaults to "config.yaml".
        """
        self.c_file_path = os.path.abspath(c_file_path)
        self.work_dir = work_dir or os.getcwd()
        self.config = self._load_config(config_path)
        
        # Components
        self.parser: Optional[CProgramParser] = None
        self.derivation_graph: Optional[DerivationGraph] = None
        self.bn_builder: Optional[BayesianNetworkBuilder] = None
        self.inference: Optional[BayesianInference] = None
        self.fuzzer = DirectedFuzzer(self.c_file_path, self.work_dir)
        
        # State
        self.alarms: List[str] = [] # List of alarm node IDs
        self.alarm_lines: Dict[str, int] = {} # Map alarm node ID -> line number
        self.stats = CampaignStats()
        
        # Config values
        self.reconstruction_interval = self.config.get('fuzzing', {}).get('reconstruction_interval', 5)
        self.initial_round_budget = self.config.get('fuzzing', {}).get('initial_round_budget', 10)

    def _load_config(self, path: str) -> dict:
        """Loads configuration from YAML file."""
        if os.path.exists(path):
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        return {}

    def analyze_program(self):
        """
        Step 1: Static Analysis & Bayesian Network Construction.
        Parses code, builds derivation graph, converts to BN.
        """
        logger.info(f"Starting analysis for {self.c_file_path}")
        
        # 1. Parse C code
        self.parser = CProgramParser()
        try:
            self.parser.parse_file(self.c_file_path)
        except Exception as e:
            logger.error(f"Parsing failed: {e}")
            raise
            
        # 2. Build Derivation Graph
        self.derivation_graph = DerivationGraph.from_parser(self.parser)
        self.derivation_graph.apply_rules()
        logger.info(f"Derivation Graph built: {len(self.derivation_graph.facts)} facts, {self.derivation_graph.rules_applied} rules applied.")
        
        # 3. Identify Alarms
        # Alarm(line) -> line number
        alarms = self.derivation_graph.get_alarms()
        self.alarms = alarms
        
        for alarm in alarms:
            # Alarm string format "Alarm(10)" or "Alarm(line)"
            # Extract content between parens
            try:
                content = alarm.split('(')[1].strip(')')
                line = int(content)
                self.alarm_lines[alarm] = line
            except (IndexError, ValueError):
                logger.warning(f"Could not extract line number from alarm: {alarm}")
        
        logger.info(f"Identified {len(self.alarms)} potential vulnerabilities (alarms).")

        # 4. Build Bayesian Network
        self.bn_builder = BayesianNetworkBuilder(self.derivation_graph)
        # Apply config params if available
        bn_config = self.config.get('bayesian_network', {})
        if 'prior_probability' in bn_config:
            self.bn_builder.prior_prob = bn_config['prior_probability']
        if 'rule_probability' in bn_config:
            self.bn_builder.rule_prob = bn_config['rule_probability']
            
        try:
            self.bn_builder.build_network()
            self.inference = BayesianInference(self.bn_builder)
            logger.info("Bayesian Network constructed successfully.")
        except Exception as e:
            logger.error(f"BN Construction failed: {e}")
            raise

    def prioritize_targets(self, alpha: float = 0.25) -> List[tuple]:
        """
        Ranks alarms by probability and selects top alpha fraction.
        
        Args:
            alpha (float): Fraction of targets to select (0.0 to 1.0).
            
        Returns:
            List[tuple]: List of (alarm_id, probability) tuples.
        """
        ranked_alarms = self.inference.rank_alarms() # List of (alarm_id, prob)
        
        # Log top probabilities
        top_5 = ranked_alarms[:5]
        logger.info(f"Top 5 targets by probability: {[(a, f'{p:.4f}') for a, p in top_5]}")
        
        num_to_select = max(1, int(len(ranked_alarms) * alpha))
        selected_targets = ranked_alarms[:num_to_select]
        
        return selected_targets

    def exploitation_round(self, targets: List[tuple], time_budget_per_target: float) -> List[tuple]:
        """
        Fuzzes the selected targets.
        
        Args:
            targets (List[tuple]): List of (alarm_id, prob).
            time_budget_per_target (float): Seconds to fuzz each target.
            
        Returns:
            List[tuple]: List of (alarm_id, FuzzingResult).
        """
        results = []
        for alarm_id, prob in targets:
            line = self.alarm_lines.get(alarm_id)
            if not line:
                continue
            
            logger.info(f"Fuzzing target {alarm_id} (line {line}) with prob {prob:.4f} for {time_budget_per_target:.1f}s")
            
            fuzz_result = self.fuzzer.fuzz_target(line, time_budget=time_budget_per_target)
            results.append((alarm_id, fuzz_result))
            
            self.stats.targets_fuzzed += 1
            
            if fuzz_result.crashed:
                logger.info(f"BUG FOUND at line {line}!")
                # Record bug
                bug = BugReport(
                    target_line=line,
                    triggering_input=fuzz_result.triggering_input.hex(),
                    time_found=self.stats.total_time + fuzz_result.time_to_exposure, # Approx
                    output=fuzz_result.output
                )
                # Check uniqueness (simple line check)
                if not any(b.target_line == line for b in self.stats.unique_bugs):
                    self.stats.unique_bugs.append(bug)

        return results

    def incorporate_feedback(self, results: List[tuple]):
        """
        Updates the BN based on fuzzing results.
        
        Args:
            results (List[tuple]): List of (alarm_id, FuzzingResult).
        """
        for alarm_id, result in results:
            if result.crashed:
                # Confirmed bug
                self.inference.update_with_feedback(alarm_id, True)
            elif not result.reached:
                # Failed to reach target -> Negative evidence
                # This helps Bayzzer focus on other reachable paths
                self.inference.update_with_feedback(alarm_id, False)
            else:
                # Reached but safe.
                # Don't penalize.
                pass

    def reconstruction(self):
        """
        Periodically clear negative evidence to allow retrying paths that might have been 
        missed due to limited fuzzing time (randomness).
        """
        logger.info("Reconstruction: Clearing negative evidence.")
        self.inference.reset_negative_evidence()

    def run_fuzzing_campaign(self, total_time: float, alpha: float = 0.25) -> CampaignStats:
        """
        Main fuzzing loop.
        
        Args:
            total_time (float): Total budget in seconds.
            alpha (float): Fraction of top targets to select.
            
        Returns:
            CampaignStats: Results of the campaign.
        """
        self.analyze_program()
        
        start_time = time.time()
        round_idx = 0
        
        beta = self.initial_round_budget
        
        while (time.time() - start_time) < total_time:
            round_idx += 1
            self.stats.rounds_run += 1
            
            # Reconstruction
            if round_idx % self.reconstruction_interval == 0:
                self.reconstruction()
            
            # Prioritize
            targets = self.prioritize_targets(alpha)
            
            if not targets:
                logger.warning("No targets found/remaining. Stopping.")
                break
            
            # Exploit
            # Adjust beta if running out of time
            remaining = total_time - (time.time() - start_time)
            # Ensure we don't exceed remaining time excessively
            current_beta = min(beta, remaining / len(targets)) if targets else beta
            if current_beta < 0.1: # Minimum viable time per target
                current_beta = remaining if remaining > 0 else 0.1
            
            fuzz_results = self.exploitation_round(targets, current_beta)
            
            # Feedback
            self.incorporate_feedback(fuzz_results)
            
            # Record History
            snapshot = {
                "round": round_idx,
                "time_elapsed": time.time() - start_time,
                "targets_count": len(targets),
                "bugs_found": len(self.stats.unique_bugs)
            }
            self.stats.history.append(snapshot)
            
            logger.info(f"Round {round_idx} complete. Bugs found so far: {len(self.stats.unique_bugs)}")

        self.stats.total_time = time.time() - start_time
        self.fuzzer.cleanup()
        return self.stats

    def save_results(self, output_file: str):
        """Saves campaign statistics to a JSON file."""
        data = asdict(self.stats)
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    # Simple manual run
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        engine = BayzzerEngine(target)
        engine.run_fuzzing_campaign(60)
    else:
        print("Usage: python bayzzer_engine.py <file.c>")