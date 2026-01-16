import os
import pytest
from evaluation.evaluator import BayzzerEvaluator, BaselineEngine
from bayzzer_engine import CampaignStats, BugReport

class TestEvaluation:
    def test_metrics_calculation(self):
        # Create dummy stats
        stats1 = CampaignStats(total_time=10)
        stats1.unique_bugs.append(BugReport(10, "", 5.0, ""))
        
        stats2 = CampaignStats(total_time=10)
        stats2.unique_bugs.append(BugReport(10, "", 3.0, ""))
        
        avg_tte = BayzzerEvaluator.calculate_tte_metrics([stats1, stats2])
        
        assert 10 in avg_tte
        assert avg_tte[10] == 4.0 # (5+3)/2

    def test_baseline_engine(self):
        # Ensure BaselineEngine runs and selects targets randomly (or at least runs)
        cwd = os.getcwd()
        test_file = os.path.join(cwd, 'test_programs', 'simple_overflow.c')
        
        engine = BaselineEngine(test_file)
        engine.analyze_program()
        
        # Check prioritization
        targets = engine.prioritize_targets(alpha=0.5)
        # Should return list of (id, prob) where prob is 0.5
        assert isinstance(targets, list)
        if targets:
            assert targets[0][1] == 0.5

    def test_evaluator_interface(self):
        cwd = os.getcwd()
        test_file = os.path.join(cwd, 'test_programs', 'simple_overflow.c')
        evaluator = BayzzerEvaluator(test_file)
        
        # Short run
        results = evaluator.compare_strategies(total_time=5, repetitions=1)
        
        assert 'Bayzzer' in results
        assert 'Baseline' in results
        assert len(results['Bayzzer']) == 1
        assert len(results['Baseline']) == 1
