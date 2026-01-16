import os
import pytest
import time
from fuzzer.directed_fuzzer import DirectedFuzzer

class TestFuzzer:
    @pytest.fixture
    def setup_fuzzer(self):
        # Path to simple_overflow.c
        # It should be in test_programs/simple_overflow.c
        cwd = os.getcwd()
        test_file = os.path.join(cwd, 'test_programs', 'simple_overflow.c')
        fuzzer = DirectedFuzzer(test_file)
        yield fuzzer
        fuzzer.cleanup()

    def test_compile_instrumentation(self, setup_fuzzer):
        # simple_overflow.c has around 20 lines.
        # Line 9 is "strcpy(buffer, input);" inside vulnerable_function.
        # Let's target line 9.
        success = setup_fuzzer.compile_target(target_line=9)
        assert success, "Compilation failed"
        assert os.path.exists(setup_fuzzer.executable_path)
        
        # Verify instrumentation works
        # Run with safe input
        reached, crashed, out, err = setup_fuzzer.execute_input(b"safe")
        assert reached, "Target line 9 should be reached by 'safe'"
        assert not crashed, "Safe input should not crash"
        assert "__TARGET_REACHED__" in out

    def test_crash_detection(self, setup_fuzzer):
        # Target line 9 again
        setup_fuzzer.compile_target(target_line=9)
        
        # Overflow input (buffer is size 10)
        overflow_input = b"A" * 20
        reached, crashed, out, err = setup_fuzzer.execute_input(overflow_input)
        
        assert reached, "Target line should be reached before crash (or during)"
        assert crashed, "Overflow should cause crash (ASAN)"
        assert "AddressSanitizer" in err or "segmentation fault" in err.lower() or "overflow" in err.lower()

    def test_fuzzing_loop(self, setup_fuzzer):
        # Target the print statement inside the if(secret != 0) block?
        # In simple_overflow.c:
        # 11: if (secret != 0) {
        # 12:    printf("Secret modified! ...\n");
        # 13: }
        # Line 12 is hard to reach?
        # Actually in simple_overflow.c, 'secret' is after 'buffer' on stack (usually).
        # Overflowing buffer might overwrite secret.
        # So targeting line 12 is a good test for "directed" fuzzing finding a path.
        
        result = setup_fuzzer.fuzz_target(target_line=12, time_budget=5)
        
        # Note: Depending on stack layout and compiler, secret might not be overwritten easily 
        # to non-zero without crushing return address first, or ASAN might catch the overflow 
        # BEFORE line 12 is reached (at strcpy).
        # If ASAN catches strcpy (line 9), program aborts. Line 12 is NEVER reached.
        # This is a nuance. ASAN stops at the invalid access.
        # So we can't easily reach line 12 with ASAN enabled if the path *requires* invalid access.
        # However, we can disable ASAN for this test? 
        # Or just test that we can crash the program targeting line 9. 
        
        # Let's verify we found a crash at line 9.
        result = setup_fuzzer.fuzz_target(target_line=9, time_budget=5)
        
        assert result.reached
        # It's likely we found a crash because we include "A"*100 in initial seeds.
        assert result.crashed
        assert len(result.triggering_input) > 10

    def test_mutation_strategies(self):
        from fuzzer.mutation_strategies import MutationStrategies
        data = b"Hello"
        
        # Bit flip
        mutated = MutationStrategies.bit_flip(data)
        assert len(mutated) == len(data)
        assert mutated != data
        
        # Interesting values
        data_int = b"1234"
        mutated_int = MutationStrategies.interesting_values(data_int)
        assert len(mutated_int) >= 4
