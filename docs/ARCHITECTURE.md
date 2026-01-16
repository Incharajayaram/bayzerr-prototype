# Architecture

This document details the software architecture of the Bayzzer prototype.

## Overview

Bayzzer operates in a continuous loop of **Analysis -> Prioritization -> Exploitation -> Feedback**.

## Components

### 1. Static Analysis (`datalog_analysis/`)
*   **`CProgramParser`**: Uses `pycparser` to build an AST of the C code. It extracts:
    *   **Input Sources**: Variables reading from argv/stdin.
    *   **Assignments**: Data flow edges (e.g., `x = y`).
    *   **Memory Operations**: Potential sinks (e.g., `strcpy`, array access).
*   **`DerivationGraph`**: Converts the parsed artifacts into a graph of logical facts (`Input`, `Flow`, `Memory`) and applies Datalog-style inference rules to connect them. The result is a graph where edges represent logical derivation.

### 2. Bayesian Network (`bayesian_network/`)
*   **`BayesianNetworkBuilder`**: Transforms the Derivation Graph into a Bayesian Network (DAG).
    *   **Facts** become Bernoulli random variables.
    *   **Rules** become conditional probability distributions (Noisy-AND).
    *   Cycles in the derivation graph (recursion) are broken to ensure DAG property required by `pgmpy`.
*   **`BayesianInference`**: Wraps `pgmpy`'s Variable Elimination engine to compute marginal probabilities $P(Alarm=True)$ for all potential vulnerability sites.

### 3. Fuzzer (`fuzzer/`)
*   **`DirectedFuzzer`**:
    *   **Instrumentation**: Injects `printf` markers at specific target lines.
    *   **Compilation**: Compiles using GCC with AddressSanitizer (ASAN).
    *   **Execution**: Runs the binary with mutated inputs.
    *   **Feedback**: Reports back `(reached, crashed)` status.
*   **`MutationStrategies`**: Implements random mutation operators (bit flips, splicing, etc.).

### 4. Orchestration (`bayzzer_engine.py`)
*   **`BayzzerEngine`**: Manages the loop.
    *   Calls Analysis.
    *   Queries BN for top targets.
    *   Delegates to Fuzzer.
    *   Updates BN evidence based on results.
    *   Handles "Reconstruction" (resetting evidence).

## Data Flow

1.  `source.c` -> **Parser** -> AST info.
2.  AST info -> **DerivationGraph** -> Graph of Facts/Rules.
3.  Graph -> **BNBuilder** -> Bayesian Network.
4.  **Inference** -> List of `(AlarmID, Probability)`.
5.  Top Targets -> **Fuzzer** -> `FuzzingResult(reached, crashed)`.
6.  Result -> **Inference** (Evidence Update).
7.  Repeat.

## Design Decisions

*   **Python vs C++**: Python was chosen for rapid prototyping of the logic and graph manipulation. The fuzzer shells out to the compiled C binary for execution speed.
*   **pgmpy**: Used for standard BN inference. While slower than custom optimized C++ implementations, it provides correctness and flexibility for this prototype.
*   **Instrumentation**: Source-based instrumentation (via simple printf injection) was chosen over binary instrumentation (like Pin or DynamoRIO) for simplicity and portability in this prototype context.
*   **Datalog Rules**: Hardcoded basic taint rules (`Input->Taint`, `Taint+Flow->Taint`) were sufficient for the test suite. A production version would use a full Datalog solver (like Soufflé).

## Simplifications from Paper

*   **Context Sensitivity**: The prototype uses context-insensitive analysis (does not distinguish function call sites).
*   **Full Datalog**: We implement a simplified fixpoint iteration rather than a full logical solver.
*   **Feedback Granularity**: We primarily use binary feedback (reached/not reached) rather than continuous probability adjustments based on distance.