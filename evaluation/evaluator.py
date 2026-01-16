import time
import random
import logging
import copy
from bayzzer_engine import BayzzerEngine, CampaignStats

logger = logging.getLogger("Evaluator")

class BaselineEngine(BayzzerEngine):
    """
    Baseline engine that selects targets randomly instead of using BN prioritization.
    """
    def prioritize_targets(self, alpha=0.25):
        """
        Selects targets uniformly at random.
        """
        # We still need the list of all alarms/targets
        # In BayzzerEngine, self.alarms is the list of alarm IDs
        if not self.alarms:
            return []
            
        # Shuffle alarms
        shuffled = list(self.alarms)
        random.shuffle(shuffled)
        
        # Select random subset similar to alpha count
        num_to_select = max(1, int(len(shuffled) * alpha))
        selected_ids = shuffled[:num_to_select]
        
        # Return format expected: list of (alarm_id, prob)
        # We assign dummy probability 0.5
        return [(aid, 0.5) for aid in selected_ids]

    def analyze_program(self):
        # We still need analysis to find alarms/targets, but we don't strictly need BN
        # However, to be a fair comparison of "guidance", we should run the same static analysis overhead?
        # Or should baseline be faster?
        # Usually baseline is "random fuzzing", which doesn't do static analysis.
        # But `DirectedFuzzer` *needs* targets (lines) to compile instrumentation.
        # So we MUST parse and find alarms to know WHERE to fuzz.
        # So we run full analysis (including BN build to keep code simple, though we ignore BN).
        super().analyze_program()
        logger.info("Baseline: Analysis complete. Ignoring BN probabilities.")

class BayzzerEvaluator:
    def __init__(self, c_file_path):
        self.c_file_path = c_file_path

    def run_experiment(self, engine_cls, total_time, repetitions=3):
        aggregated_stats = []
        
        for i in range(repetitions):
            logger.info(f"Starting repetition {i+1}/{repetitions} for {engine_cls.__name__}")
            engine = engine_cls(self.c_file_path)
            stats = engine.run_fuzzing_campaign(total_time)
            aggregated_stats.append(stats)
            
        return aggregated_stats

    def compare_strategies(self, total_time=60, repetitions=3):
        """
        Runs both Bayzzer and Baseline and returns comparison data.
        """
        results = {}
        
        # Run Bayzzer
        logger.info("Running Bayzzer Strategy...")
        results['Bayzzer'] = self.run_experiment(BayzzerEngine, total_time, repetitions)
        
        # Run Baseline
        logger.info("Running Baseline (Random) Strategy...")
        results['Baseline'] = self.run_experiment(BaselineEngine, total_time, repetitions)
        
        return results

    @staticmethod
    def calculate_tte_metrics(stats_list):
        """
        Calculates average Time To Exposure (TTE) for unique bugs across repetitions.
        Returns: {bug_line: avg_tte}
        """
        bug_times = {} # line -> [times]
        
        for stats in stats_list:
            for bug in stats.unique_bugs:
                if bug.target_line not in bug_times:
                    bug_times[bug.target_line] = []
                bug_times[bug.target_line].append(bug.time_found)
                
        avg_tte = {}
        for line, times in bug_times.items():
            avg_tte[line] = sum(times) / len(times)
            
        return avg_tte
