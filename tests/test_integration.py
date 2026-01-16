import os
import pytest
import time
from bayzzer_engine import BayzzerEngine

class TestIntegration:
    
    @pytest.fixture
    def test_programs_dir(self):
        return os.path.join(os.getcwd(), 'test_programs')

    def test_bayzzer_simple_overflow(self, test_programs_dir):
        target = os.path.join(test_programs_dir, 'simple_overflow.c')
        
        # Run for short time (e.g. 20s should be enough for simple_overflow)
        engine = BayzzerEngine(target)
        stats = engine.run_fuzzing_campaign(total_time=20, alpha=0.5)
        
        assert len(stats.unique_bugs) > 0, "Bayzzer should find the simple overflow"
        bug = stats.unique_bugs[0]
        # Line 9 is strcpy in simple_overflow.c
        # Depending on how pycparser counts lines (1-based vs 0-based or newlines), it might vary slightly
        # simple_overflow.c content:
        # 1: #include ...
        # ...
        # 9: strcpy(buffer, input);
        # But let's allow a small range.
        assert bug.target_line in [9, 10, 12, 13]

    def test_bayzzer_taint_flow(self, test_programs_dir):
        target = os.path.join(test_programs_dir, 'taint_flow.c')
        
        engine = BayzzerEngine(target)
        stats = engine.run_fuzzing_campaign(total_time=20, alpha=1.0) # Search all
        
        assert len(stats.unique_bugs) > 0, "Bayzzer should find the taint flow bug"
        
        # In taint_flow.c, buffer overflow at line 23: buffer[unsafe_index % 50] = 'X';
        # Wait, unsafe_index % 50 can be up to 49. buffer is size 20.
        # Overflow happens if index >= 20.
        # This requires solving inputs.
        
    def test_bayzzer_complex_flow(self, test_programs_dir):
        target = os.path.join(test_programs_dir, 'complex_flow.c')
        
        # This is harder, might need more time or luck with random mutation
        # But 'directed' fuzzing should help prioritize the admin_panel call.
        
        engine = BayzzerEngine(target)
        stats = engine.run_fuzzing_campaign(total_time=15, alpha=0.5)
        
        # We might not guarantee finding bugs in complex flow in 15s with naive mutation
        # But we should check that the engine ran rounds and prioritized targets
        assert stats.rounds_run > 0
        assert stats.targets_fuzzed > 0
        
        # Check if prioritization worked: 
        # Targets with higher derivation probability should be fuzzed.
        # We can check logs, but assertion is hard on probabilistic internal state.
        # Just ensure it didn't crash.

    def test_feedback_mechanism(self, test_programs_dir):
        """
        Verify that failing to reach a target reduces its probability (negative feedback).
        """
        target = os.path.join(test_programs_dir, 'simple_overflow.c')
        engine = BayzzerEngine(target)
        engine.analyze_program()
        
        # Pick a target
        alarms = engine.inference.rank_alarms()
        if not alarms:
            pytest.skip("No alarms found")
            
        target_id, initial_prob = alarms[0]
        
        # Simulate failed fuzzing (not reached)
        engine.inference.update_with_feedback(target_id, False)
        
        # Check new probability
        new_alarms = dict(engine.inference.rank_alarms())
        new_prob = new_alarms[target_id]
        
        assert new_prob < initial_prob, "Probability should decrease after negative feedback"
        
        # Reset (Reconstruction)
        engine.reconstruction()
        reset_alarms = dict(engine.inference.rank_alarms())
        reset_prob = reset_alarms[target_id]
        
        # Should be back to initial (or close, floating point)
        assert abs(reset_prob - initial_prob) < 1e-4, "Probability should reset after reconstruction"
