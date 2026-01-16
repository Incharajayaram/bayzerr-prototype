"""
Case Study: Running Bayzzer on a custom program.

This script demonstrates how to instantiate the engine programmatically,
configure it, and analyze the results.
"""

import os
import sys
# Add parent dir to path to import bayzzer
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from bayzzer_engine import BayzzerEngine

def run_case_study():
    target_file = os.path.join(os.path.dirname(__file__), 'custom_program.c')
    if not os.path.exists(target_file):
        print(f"Error: {target_file} not found.")
        return

    print(f"--- Running Bayzzer Case Study on {target_file} ---")
    
    # Initialize engine
    # We can pass a custom config path if needed
    engine = BayzzerEngine(target_file, config_path="../config.yaml")
    
    # Run campaign for 30 seconds
    print("Starting campaign (30s).")
    stats = engine.run_fuzzing_campaign(total_time=30, alpha=0.5)
    
    print("\n--- Results ---")
    print(f"Total Rounds: {stats.rounds_run}")
    print(f"Bugs Found: {len(stats.unique_bugs)}")
    
    for i, bug in enumerate(stats.unique_bugs):
        print(f"\nBug #{i+1}:")
        print(f"  Line: {bug.target_line}")
        print(f"  Time: {bug.time_found:.2f}s")
        print(f"  Input: {bug.triggering_input}")
        
    # Save results
    output_path = "case_study_results.json"
    engine.save_results(output_path)
    print(f"\nDetailed results saved to {output_path}")

if __name__ == "__main__":
    run_case_study()
