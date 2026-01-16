import matplotlib.pyplot as plt
import os
import json
import networkx as nx

class Visualizer:
    def __init__(self, output_dir="results"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def plot_discovery_curve(self, results_dict, filename="discovery_curve.png"):
        """
        Plots the average number of bugs found over time for different strategies.
        results_dict: {'StrategyName': [CampaignStats, ...]}}
        """
        plt.figure(figsize=(10, 6))
        
        for strategy, stats_list in results_dict.items():
            # We need to average curves. 
            # Simple approach: Gather all (time, bug_count) points, sort by time.
            # Better: Discretize time buckets.
            
            all_points = []
            for stats in stats_list:
                # Reconstruct timeline: 
                # stats.history has snapshots.
                # Assuming snapshots are roughly periodic.
                # Or use stats.unique_bugs which has exact times.
                
                # Sort bugs by time
                sorted_bugs = sorted(stats.unique_bugs, key=lambda b: b.time_found)
                current_count = 0
                points = [(0,0)]
                for b in sorted_bugs:
                    current_count += 1
                    points.append((b.time_found, current_count))
                points.append((stats.total_time, current_count))
                all_points.append(points)
            
            # Plot each run as a thin line? Or interpolate?
            # Let's plot each run faintly, and the average bold?
            # For this prototype, just plot all runs.
            for i, points in enumerate(all_points):
                xs, ys = zip(*points)
                label = strategy if i == 0 else "_nolegend_"
                alpha = 1.0 if len(stats_list) == 1 else 0.5
                plt.step(xs, ys, label=label, alpha=alpha, where='post')

        plt.xlabel("Time (s)")
        plt.ylabel("Unique Bugs Found")
        plt.title("Bug Discovery over Time")
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.output_dir, filename))
        plt.close()

    def plot_probability_evolution(self, engine_stats, alarm_id, filename="prob_evolution.png"):
        """
        Plots probability of a specific target over rounds.
        Requires that CampaignStats history includes detailed target probabilities (which it currently doesn't).
        We need to modify BayzzerEngine to record this if we want to visualize it.
        For now, we'll skip or implement a placeholder.
        """
        pass

    def save_summary_table(self, results_dict, filename="summary.md"):
        """
        Generates a markdown table comparing metrics.
        """
        with open(os.path.join(self.output_dir, filename), 'w') as f:
            f.write("# Evaluation Summary\n\n")
            f.write("| Strategy | Avg Bugs Found | Avg Time (s) | Min TTE (s) | Max TTE (s) |\n")
            f.write("|---|---|---|---|---|")
            
            for strategy, stats_list in results_dict.items():
                bugs_counts = [len(s.unique_bugs) for s in stats_list]
                avg_bugs = sum(bugs_counts) / len(bugs_counts)
                
                total_times = [s.total_time for s in stats_list]
                avg_time = sum(total_times) / len(total_times)
                
                # TTE (Time To First Exposure)
                first_bug_times = []
                for s in stats_list:
                    if s.unique_bugs:
                        first_bug_times.append(min(b.time_found for b in s.unique_bugs))
                
                min_tte = min(first_bug_times) if first_bug_times else float('inf')
                avg_first_tte = sum(first_bug_times)/len(first_bug_times) if first_bug_times else float('inf')
                
                f.write(f"| {strategy} | {avg_bugs:.2f} | {avg_time:.2f} | {min_tte:.2f} | {avg_first_tte:.2f} |\n")
