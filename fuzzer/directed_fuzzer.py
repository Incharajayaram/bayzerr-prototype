import os
import subprocess
import time
import random
import string
import tempfile
import shutil
from dataclasses import dataclass
from fuzzer.mutation_strategies import MutationStrategies

@dataclass
class FuzzingResult:
    target_line: int
    reached: bool
    crashed: bool
    time_to_exposure: float
    triggering_input: bytes
    output: str

class DirectedFuzzer:
    """
    A simple directed fuzzer that targets specific lines in a C program.
    """

    def __init__(self, c_source_path, work_dir=None):
        self.c_source_path = os.path.abspath(c_source_path)
        self.work_dir = work_dir or os.getcwd()
        self.executable_path = None
        self.instrumented_source_path = None

    def compile_target(self, target_line):
        """
        Instruments the source code to detect if target_line is reached, 
        then compiles it with ASAN.
        
        Args:
            target_line (int): The line number (1-based) to target.
        """
        # 1. Read source
        with open(self.c_source_path, 'r') as f:
            lines = f.readlines()

        # 2. Inject instrumentation
        # Naive insertion: Insert *before* the target line.
        # We assume the target line is a statement.
        # "printf" is safe for most contexts (inside blocks).
        # We use a unique marker.
        marker = "__TARGET_REACHED__"
        injection = f'printf("{marker}\\n");fflush(stdout);\n'
        
        # Adjust line index (0-based)
        if 0 < target_line <= len(lines):
            # Insert before the line
            lines.insert(target_line - 1, injection)
        else:
            raise ValueError(f"Invalid target line: {target_line}")

        # 3. Write instrumented source
        basename = os.path.basename(self.c_source_path)
        self.instrumented_source_path = os.path.join(self.work_dir, f"instr_{basename}")
        with open(self.instrumented_source_path, 'w') as f:
            f.writelines(lines)

        # 4. Compile
        self.executable_path = os.path.join(self.work_dir, "fuzz_target.out")
        # Include fake_libc_include paths if needed, but for GCC compilation 
        # of the test programs (which use standard headers), we assume standard headers are available.
        # The test programs are simple standard C.
        
        cmd = [
            'gcc', 
            '-g', 
            '-fsanitize=address', 
            '-o', self.executable_path, 
            self.instrumented_source_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Compilation failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"Compilation error: {e}")
            return False
        
        return True

    def generate_initial_seeds(self, num_seeds=5):
        """Generates random initial inputs."""
        seeds = []
        for _ in range(num_seeds):
            # Generate random strings of length 1-20
            length = random.randint(1, 20)
            seed = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            seeds.append(seed.encode('utf-8'))
        return seeds

    def execute_input(self, input_data):
        """
        Executes the target program with the given input.
        
        Args:
            input_data (bytes): Input to pass as argv[1] or via stdin.
                                For our test programs, they mostly take argv[1].
                                We'll support argv[1] primarily.
        
        Returns:
            tuple: (reached_target, crashed, stdout, stderr)
        """
        if not self.executable_path or not os.path.exists(self.executable_path):
            raise RuntimeError("Target not compiled.")

        reached = False
        crashed = False
        stdout_output = ""
        stderr_output = ""

        try:
            # Decode input safely for argv
            try:
                # Remove null bytes as they terminate argv strings in C and cause issues in subprocess
                clean_input = input_data.replace(b'\x00', b'')
                arg_str = clean_input.decode('utf-8', errors='ignore')
            except:
                arg_str = ""
            
            # Run
            # We assume input is passed as first argument.
            # If stdin is needed, we'd pipe it.
            # test_programs/simple_overflow.c uses argv[1].
            
            result = subprocess.run(
                [self.executable_path, arg_str],
                capture_output=True,
                timeout=2 # Seconds
            )
            
            stdout_output = result.stdout.decode('utf-8', errors='replace')
            stderr_output = result.stderr.decode('utf-8', errors='replace')
            
            if "__TARGET_REACHED__" in stdout_output:
                reached = True
            
            if result.returncode != 0:
                # ASAN usually returns non-zero on error (often 1 or 23)
                # Check for ASAN report in stderr
                if "AddressSanitizer" in stderr_output:
                    crashed = True
                # Or segfault
                if result.returncode == -11: # SIGSEGV
                    crashed = True

        except subprocess.TimeoutExpired:
            # Infinite loops count as "crashes" or distinct failures, 
            # but for this we'll ignore or treat as crash.
            pass
        except Exception as e:
            print(f"Execution error: {e}")

        return reached, crashed, stdout_output, stderr_output

    def fuzz_target(self, target_line, time_budget=10):
        """
        Main fuzzing loop.
        
        Args:
            target_line (int): Line to target.
            time_budget (int): Seconds to run.
            
        Returns:
            FuzzingResult
        """
        if not self.compile_target(target_line):
            return FuzzingResult(target_line, False, False, 0, b"", "Compilation failed")

        start_time = time.time()
        population = self.generate_initial_seeds()
        
        # Add some specific seeds that might help
        population.append(b"A" * 100) # Overflow candidate
        population.append(b"10")      # Integer candidate
        population.append(b"-1")
        
        best_input = None
        reached_target = False
        crashed_target = False
        captured_output = ""
        
        iterations = 0
        
        while time.time() - start_time < time_budget:
            iterations += 1
            
            # Select parent
            parent = random.choice(population)
            
            # Mutate
            child = MutationStrategies.mutate(parent)
            
            # Execute
            reached, crashed, out, err = self.execute_input(child)
            
            if reached:
                reached_target = True
                best_input = child
                captured_output = out
                if crashed:
                    crashed_target = True
                    # If we crashed AND reached, this is gold. Stop?
                    # Or keep searching for simpler crash?
                    # Let's stop on first crash at target.
                    break
                else:
                    # We reached but didn't crash. 
                    # Maybe this is the bug location but logic didn't fail yet, 
                    # or we just reached the line.
                    # We keep it in population to mutate further from here.
                    population.append(child)
            
            if crashed and not reached:
                # Crashed elsewhere?
                pass
            
            # Limit population size
            if len(population) > 50:
                population = population[-50:] # Keep recent
                
        elapsed = time.time() - start_time
        
        return FuzzingResult(
            target_line=target_line,
            reached=reached_target,
            crashed=crashed_target,
            time_to_exposure=elapsed,
            triggering_input=best_input if best_input else b"",
            output=captured_output
        )

    def cleanup(self):
        """Removes temporary files."""
        if self.instrumented_source_path and os.path.exists(self.instrumented_source_path):
            os.remove(self.instrumented_source_path)
        if self.executable_path and os.path.exists(self.executable_path):
            os.remove(self.executable_path)
