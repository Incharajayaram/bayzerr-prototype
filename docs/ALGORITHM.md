# Algorithm Details

Bayzzer adapts the approach described in "Bayesian-Network-based Directed Fuzzing" (generic title for the concept). The core algorithm combines static analysis with probabilistic reasoning.

## 1. Datalog Derivation

We define three core predicates:
*   `Taint(v)`: Variable `v` is controlled by attacker input.
*   `Flow(src, dst)`: Data flows from `src` to `dst`.
*   `Memory(v, loc)`: Variable `v` is used in a memory operation at `loc`.
*   `Alarm(loc)`: A potential vulnerability exists at `loc`.

Inference Rules:
1.  **Source**: `Taint(v) :- Input(v)`
2.  **Propagation**: `Taint(dst) :- Taint(src) ^ Flow(src, dst)`
3.  **Sink**: `Alarm(loc) :- Taint(v) ^ Memory(v, loc)`

## 2. Bayesian Network Construction

The derivation graph serves as the template for the BN.

### Node Types
*   **Fact Nodes** (e.g., `Taint(a)`): Boolean variables representing whether the fact holds true.
*   **Rule Nodes** (e.g., `R2_application`): Boolean variables representing whether a specific rule instance fired successfully.

### Probabilities
*   **Prior**: Base facts (like `Input` or `Flow`) are assigned a high prior probability (0.9) representing our confidence in the static analysis.
*   **Rule Conditional Probability Tables (CPTs)**: Modeled as **Noisy-AND**.
    *   For a rule $R: H \leftarrow B_1 \wedge ... \wedge B_n$:
    *   $P(R=True | B_1=T, ..., B_n=T) = p_{rule}$ (usually 0.9).
    *   $P(R=True | \text{any } B_i=F) = 0$.
*   **Fact CPTs**: Modeled as **Deterministic OR**.
    *   For a fact $F$ derived by rules $R_1, ..., R_k$:
    *   $P(F=True | \text{any } R_i=T) = 1.0$.

## 3. Feedback Loop

Bayzzer uses **Dynamic Feedback** to refine the static model.

### Negative Feedback
When the fuzzer fails to reach a target `Alarm(L)` after a budget $\beta$:
*   This suggests one of the premises (control flow or data dependency) is false or hard to satisfy.
*   Action: Set Evidence `Alarm(L) = False`.
*   Impact: This propagates backwards in the network. If `Alarm(L)` depended on `Taint(x)`, the probability of `Taint(x)` decreases. This naturally deprioritizes other alarms that also depend on `Taint(x)`, effectively pruning "hard" branches of the program.

### Positive Feedback
When the fuzzer reaches `Alarm(L)`:
*   Action: Set Evidence `Alarm(L) = True` (conceptually, or we confirm the bug).
*   In this prototype, if a crash occurs, we mark it as found. If reached but safe, we typically leave evidence unset (neutral) or set weak positive evidence, to avoid penalizing valid paths.

### Reconstruction
Randomness in fuzzing means "failure to reach" isn't proof of unreachability.
*   Every $N$ rounds, we clear all negative evidence.
*   This allows the system to retry high-value targets that were unlucky in previous rounds.

## Pseudocode

```python
G = BuildDerivationGraph(Program)
BN = BuildBayesianNetwork(G)

while Time < Budget:
    # 1. Inference
    Probs = Query(BN, P(Alarm=True | Evidence))
    
    # 2. Prioritization
    Targets = SelectTop(Probs, alpha)
    
    # 3. Exploitation
    for T in Targets:
        Result = Fuzz(T, beta)
        
        if Result.Crashed:
            ReportBug(T)
            Evidence[T] = True
        elif not Result.Reached:
            Evidence[T] = False  # Negative Feedback
            
    # 4. Reconstruction
    if Round % N == 0:
        ClearNegativeEvidence(Evidence)
```
