# Contributing to Bayzzer

Thank you for your interest in contributing to Bayzzer! We welcome contributions from everyone.

## Getting Started

1.  Fork the repository.
2.  Clone your fork: `git clone https://github.com/yourname/bayzzer-prototype.git`
3.  Install dependencies: `./scripts/setup.sh`

## Code Style

*   We use Python 3.10+.
*   Follow PEP 8 guidelines.
*   Run tests before submitting: `./scripts/run_all_tests.sh`

## GSoC Candidates

If you are looking at this project for GSoC, here are some areas for improvement:
*   **Real-world Parsing**: Replace `pycparser` with `tree-sitter` or `clang` bindings.
*   **Binary Fuzzing**: Integrate with AFL++ or QEMU user mode.
*   **Scalability**: Optimize the Bayesian Network inference for graphs with >10k nodes.
*   **Visualization**: Create a real-time web dashboard for the fuzzing campaign.

## Submitting Pull Requests

1.  Create a new branch: `git checkout -b feature/my-feature`
2.  Commit your changes.
3.  Push to the branch.
4.  Open a Pull Request.
