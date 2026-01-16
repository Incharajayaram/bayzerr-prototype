import pytest
import math
import networkx as nx
from datalog_analysis.derivation_graph import DerivationGraph
from bayesian_network.network_builder import BayesianNetworkBuilder
from bayesian_network.inference import BayesianInference

class TestBayesianNetwork:
    
    @pytest.fixture
    def simple_chain_graph(self):
        """
        Creates a simple graph:
        Input(a) -> R1 -> Taint(a)
        Taint(a), Flow(a,b) -> R2 -> Taint(b)
        Taint(b), Memory(b,s) -> R3 -> Alarm(s)
        """
        dg = DerivationGraph()
        
        # Facts
        input_a = dg.add_fact('Input', 'a')
        taint_a = dg.add_fact('Taint', 'a')
        flow_ab = dg.add_fact('Flow', 'a', 'b')
        taint_b = dg.add_fact('Taint', 'b')
        mem_bs = dg.add_fact('Memory', 'b', 's')
        alarm_s = dg.add_fact('Alarm', 's')
        
        # Rules
        # R1: Taint(a) :- Input(a)
        dg.add_rule_application('R1', [input_a], taint_a)
        
        # R2: Taint(b) :- Taint(a), Flow(a,b)
        dg.add_rule_application('R2', [taint_a, flow_ab], taint_b)
        
        # R3: Alarm(s) :- Taint(b), Memory(b,s)
        dg.add_rule_application('R3', [taint_b, mem_bs], alarm_s)
        
        return dg

    def test_simple_chain_probability(self, simple_chain_graph):
        builder = BayesianNetworkBuilder(simple_chain_graph)
        builder.build_network()
        inference = BayesianInference(builder)
        
        results = inference.compute_alarm_probabilities()
        alarm_node = [n for n in simple_chain_graph.facts if n.startswith('Alarm')][0]
        prob = results[alarm_node]
        
        # Expected calculation:
        # P(Input(a)) = 0.9
        # P(Flow) = 0.9, P(Memory) = 0.9 (Roots)
        
        # P(R1_fired) = P(Input) * 0.9 = 0.9 * 0.9 = 0.81
        # P(Taint(a)) = P(R1_fired) = 0.81
        
        # P(R2_fired) = P(Taint(a)) * P(Flow) * 0.9 
        #             = 0.81 * 0.9 * 0.9 = 0.6561
        # P(Taint(b)) = P(R2_fired) = 0.6561
        
        # P(R3_fired) = P(Taint(b)) * P(Memory) * 0.9
        #             = 0.6561 * 0.9 * 0.9 = 0.531441
        # P(Alarm) = P(R3_fired) = 0.531441
        
        assert math.isclose(prob, 0.531441, rel_tol=1e-4)

    def test_multiple_derivations(self):
        """
        Test OR logic.
        Input(a) -> R1 -> Taint(a)
        Input(b) -> R1 -> Taint(b)
        
        Taint(c) derived from Taint(a) OR Taint(b) (via hypothetical flows)
        """
        dg = DerivationGraph()
        inp_a = dg.add_fact('Input', 'a')
        inp_b = dg.add_fact('Input', 'b')
        taint_a = dg.add_fact('Taint', 'a')
        taint_b = dg.add_fact('Taint', 'b')
        taint_c = dg.add_fact('Taint', 'c')
        
        dg.add_rule_application('R1', [inp_a], taint_a)
        dg.add_rule_application('R1', [inp_b], taint_b)
        
        # Fake rules deriving c from a and b
        # Rule A: Taint(c) :- Taint(a)
        dg.add_rule_application('RA', [taint_a], taint_c)
        # Rule B: Taint(c) :- Taint(b)
        dg.add_rule_application('RB', [taint_b], taint_c)
        
        builder = BayesianNetworkBuilder(dg)
        builder.build_network()
        inference = BayesianInference(builder)
        
        # P(Taint(a)) = 0.81 (same as before)
        # P(Taint(b)) = 0.81
        
        # P(RuleA) = P(Taint(a)) * 0.9 = 0.729
        # P(RuleB) = P(Taint(b)) * 0.9 = 0.729
        
        # P(Taint(c)) = 1 - (1 - P(RuleA)) * (1 - P(RuleB))
        #             = 1 - (1 - 0.729)^2
        #             = 1 - (0.271)^2
        #             = 1 - 0.073441
        #             = 0.926559
        
        # We query taint_c directly, treating it like an alarm for test
        # Need to expose query method or mock inference
        # We can just check internal inference query manually
        
        res = inference.inference_engine.query(variables=[taint_c], evidence={})
        prob = res.values[1]
        
        assert math.isclose(prob, 0.926559, rel_tol=1e-4)

    def test_evidence_propagation(self, simple_chain_graph):
        builder = BayesianNetworkBuilder(simple_chain_graph)
        builder.build_network()
        inference = BayesianInference(builder)
        
        alarm_node = [n for n in simple_chain_graph.facts if n.startswith('Alarm')][0]
        taint_a = [n for n in simple_chain_graph.facts if n.startswith('Taint(a)')][0]
        
        # Set Taint(a) = False. This should break the chain.
        inference.update_with_feedback(taint_a, False)
        
        results = inference.compute_alarm_probabilities()
        assert results[alarm_node] == 0.0
        
        # Set Taint(a) = True.
        inference.update_with_feedback(taint_a, True)
        results = inference.compute_alarm_probabilities()
        
        # If Taint(a) is certain (1.0):
        # P(Taint(b)) = 1.0 * P(Flow=0.9) * 0.9 = 0.81
        # P(Alarm) = 0.81 * P(Mem=0.9) * 0.9 = 0.6561
        
        assert math.isclose(results[alarm_node], 0.6561, rel_tol=1e-4)

    def test_cycle_breaking(self):
        """
        Test that cycles are broken and BN construction doesn't fail.
        A <-> B
        """
        dg = DerivationGraph()
        fact_a = dg.add_fact('Fact', 'A')
        fact_b = dg.add_fact('Fact', 'B')
        
        # A -> rule -> B
        dg.add_rule_application('R1', [fact_a], fact_b)
        # B -> rule -> A
        dg.add_rule_application('R2', [fact_b], fact_a)
        
        builder = BayesianNetworkBuilder(dg)
        try:
            builder.build_network()
        except Exception as e:
            pytest.fail(f"Cycle breaking failed: {e}")
            
        assert builder.bn_model is not None
        assert nx.is_directed_acyclic_graph(builder.bn_model)
