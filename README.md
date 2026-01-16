# Bayzzer Prototype

**Bayzzer** is a hybrid fuzzing tool that uses Bayesian Networks to prioritize targets for directed fuzzing. By modeling program dependencies (control flow, data flow) as a probabilistic network, Bayzzer can identify "critical" code locations that are both likely to be reachable and likely to trigger vulnerabilities.

## Motivation

Traditional directed fuzzing often treats all targets equally or relies on static distance metrics that don't account for the *logical* difficulty of reaching a target. Bayzzer improves this by:
1.  **Modeling Dependencies**: Using Datalog rules to infer how taint flows through the program.
2.  **Probabilistic Guidance**: Calculating the probability of reaching a target based on the satisfiability of its derivation path.
3.  **Dynamic Feedback**: Updating these probabilities in real-time based on fuzzing outcomes (e.g., penalizing paths that prove hard to satisfy).

## Architecture

```
+----------------+      +------------------+      +------------------+
| C Source Code  | ---> |  Static Analysis | ---> | Derivation Graph |
+----------------+      | (Parser/Datalog) |      +------------------+
                                                          |
                                                          v
+----------------+      +------------------+      +------------------+
|    Fuzzer      | <--- | Bayesian Network | <--- |   BN Builder     |
| (Directed)     |      |   Inference      |      +------------------+
+----------------+      +------------------+
       |                         ^
       | Feedback (Reached/Crash)|
       +-------------------------+
```

## Installation

1.  **Prerequisites**:
    *   Python 3.10+
    *   GCC (with AddressSanitizer support)
    *   `pip`

2.  **Setup**:
    ```bash
    git clone https://github.com/yourusername/bayzzer-prototype.git
    cd bayzzer-prototype
    ./scripts/setup.sh
    ```

## Quick Start

Run Bayzzer on the provided simple test case:

```bash
python run_bayzzer.py --target test_programs/simple_overflow.c --time 60
```

### Expected Output
```text
Starting Bayzzer on test_programs/simple_overflow.c
Time Budget: 60s, Alpha: 0.25
...
Round 1 complete. Bugs found so far: 0
BUG FOUND at line 9!
...
=== Campaign Finished ===
Total Time: 60.05s
Rounds: 15
Targets Fuzzed: 45
Unique Bugs Found: 1

Bug #1:
  Line: 9
  Found at: 4.23s
  Input (hex): 41414141...
```

## Usage

```bash
usage: run_bayzzer.py [-h] --target TARGET [--time TIME] [--alpha ALPHA] [--output OUTPUT]

options:
  -h, --help       show this help message and exit
  --target TARGET  Path to C source file
  --time TIME      Total fuzzing time in seconds (default: 60)
  --alpha ALPHA    Fraction of top targets to fuzz (default: 0.25)
  --output OUTPUT  Output file for results (default: bayzzer_results.json)
```

## Adding New Programs

1.  Create a C file (e.g., `my_vuln.c`).
2.  Ensure it uses standard input methods (argv or stdin, currently argv supported primarily).
3.  Run: `python run_bayzzer.py --target my_vuln.c`.

See `examples/custom_program.c` for a template.

## Evaluation

To run the evaluation suite comparing Bayzzer against a random baseline:

```bash
python experiments/run_experiments.py
```

Results (plots and tables) will be saved in `results/`.

## Troubleshooting

*   **Compilation Failed**: Ensure `gcc` is in your PATH and supports `-fsanitize=address`.
*   **ImportError**: Run `pip install -r requirements.txt`.
*   **No Bugs Found**: Try increasing the `--time` budget or `--alpha` (to fuzz more targets). Complex constraints might require longer fuzzing sessions.