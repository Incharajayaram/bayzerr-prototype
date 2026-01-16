import argparse
import sys
import os
from bayzzer_engine import BayzzerEngine

def main():
    parser = argparse.ArgumentParser(description="Bayzzer: Bayesian-Guided Directed Fuzzing")
    parser.add_argument("--target", required=True, help="Path to C source file")
    parser.add_argument("--time", type=int, default=60, help="Total fuzzing time in seconds")
    parser.add_argument("--alpha", type=float, default=0.25, help="Fraction of top targets to fuzz (0.0-1.0)")
    parser.add_argument("--output", default="bayzzer_results.json", help="Output file for results")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"Error: File {args.target} not found.")
        sys.exit(1)
        
    print(f"Starting Bayzzer on {args.target}")
    print(f"Time Budget: {args.time}s, Alpha: {args.alpha}")
    
    try:
        engine = BayzzerEngine(args.target)
        stats = engine.run_fuzzing_campaign(args.time, args.alpha)
        
        print("\n=== Campaign Finished ===")
        print(f"Total Time: {stats.total_time:.2f}s")
        print(f"Rounds: {stats.rounds_run}")
        print(f"Targets Fuzzed: {stats.targets_fuzzed}")
        print(f"Unique Bugs Found: {len(stats.unique_bugs)}")
        
        for idx, bug in enumerate(stats.unique_bugs):
            print(f"\nBug #{idx+1}:")
            print(f"  Line: {bug.target_line}")
            print(f"  Found at: {bug.time_found:.2f}s")
            print(f"  Input (hex): {bug.triggering_input}")
            
        engine.save_results(args.output)
        
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
