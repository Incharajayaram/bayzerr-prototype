import os
import sys
import logging
from evaluation.evaluator import BayzzerEvaluator
from evaluation.visualizer import Visualizer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ExperimentRunner")

def run_experiments():
    test_programs_dir = "test_programs"
    programs = ["simple_overflow.c", "taint_flow.c"] # complex_flow might take too long for quick test
    
    output_dir = "results"
    viz = Visualizer(output_dir)
    
    # Settings
    time_budget = 30 # Seconds per run
    repetitions = 2  # Repetitions per strategy
    
    summary_data = {}
    
    for prog in programs:
        prog_path = os.path.join(test_programs_dir, prog)
        if not os.path.exists(prog_path):
            logger.warning(f"Program {prog} not found. Skipping.")
            continue
            
        logger.info(f"Running experiments on {prog}")
        
        evaluator = BayzzerEvaluator(prog_path)
        results = evaluator.compare_strategies(total_time=time_budget, repetitions=repetitions)
        
        summary_data[prog] = results
        
        # Visualize
        viz.plot_discovery_curve(results, filename=f"{prog}_discovery.png")
        viz.save_summary_table(results, filename=f"{prog}_summary.md")
        
    logger.info("Experiments complete. Results saved to 'results/' directory.")

if __name__ == "__main__":
    run_experiments()
