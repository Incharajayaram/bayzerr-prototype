# Bayzzer Prototype

A prototype fuzzing tool based on Bayesian program analysis.

## Project Structure

- `bayesian_network/`: Contains modules for Bayesian network construction and inference.
  - `network_builder.py`: Logic to build the network.
  - `inference.py`: Inference engine.
  - `feedback_processor.py`: Processes feedback from fuzzing runs.
- `datalog_analysis/`: Static analysis components.
  - `taint_analysis.py`: Taint tracking logic.
  - `derivation_graph.py`: Graph derivation for analysis.
- `fuzzer/`: The core fuzzing logic (under development).
- `test_programs/`: C programs used for testing the fuzzer capabilities.
  - `simple_overflow.c`: A basic buffer overflow example.
  - `taint_flow.c`: Demonstrates taint propagation.
  - `complex_flow.c`: Features more complex control flow and multiple inputs.
- `tests/`: Python unit tests for the project.

## Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

## Usage

(Instructions to be added as the prototype develops)
