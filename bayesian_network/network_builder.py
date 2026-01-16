import networkx as nx
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
import itertools

class BayesianNetworkBuilder:
    """
    Converts a DerivationGraph into a Bayesian Network (BN) using pgmpy.
    
    The translation follows these principles:
    1. Nodes in the BN represent Facts (tuples) or Rule Applications from the derivation graph.
    2. Fact Nodes are Bernoulli variables (True/False).
    3. Rule Application Nodes are Bernoulli variables representing the successful firing of a rule.
    4. Probabilities:
       - Root Facts (EDB): Prior probability = 0.9
       - Rule Nodes: P(Rule=T | Premises=T) = 0.9 (Noise factor)
                     P(Rule=T | Any Premise=F) = 0.0 (Strict AND)
       - Derived Facts (IDB): P(Fact=T | Any Incoming Rule=T) = 1.0 (Deterministic OR)
    """

    def __init__(self, derivation_graph):
        """
        Args:
            derivation_graph (DerivationGraph): The source graph.
        """
        self.dg = derivation_graph
        self.bn_model = None
        self.evidence = {}
        
        # Parameters from paper
        self.prior_prob = 0.9
        self.rule_prob = 0.9

    def build_network(self):
        """
        Constructs the Bayesian Network structure and CPDs.
        
        Returns:
            pgmpy.models.DiscreteBayesianNetwork: The constructed BN.
        """
        # 1. Create structure
        # Copy nodes and edges from DerivationGraph
        # We need to ensure it's a DAG.
        
        temp_graph = nx.DiGraph(self.dg.graph)
        
        # Cycle removal: Remove back-edges
        # Simple heuristic: Perform DFS, remove edges pointing to ancestors currently in recursion stack.
        # However, networkx has built-in feedback edge set algorithms or we can just iterate simple cycles.
        # Since cycles might be complex, we'll use a standard approach:
        # If not DAG, break cycles.
        if not nx.is_directed_acyclic_graph(temp_graph):
            # Find cycle edges and remove them. 
            # Note: Removing edges might break logic (a rule needs all premises). 
            # If we remove a premise->rule edge, that rule effectively becomes useless (always False).
            # This is acceptable for breaking infinite recursion in static analysis context.
            cycles = list(nx.simple_cycles(temp_graph))
            for cycle in cycles:
                # Break the cycle by removing the edge from the last node to the first
                u, v = cycle[-1], cycle[0]
                if temp_graph.has_edge(u, v):
                    temp_graph.remove_edge(u, v)
            
            # Re-check
            if not nx.is_directed_acyclic_graph(temp_graph):
                # Fallback: drastic measure, remove feedback arcs
                # (For now assume simple cycle breaking worked)
                pass

        self.bn_model = DiscreteBayesianNetwork(temp_graph.edges())
        # Add nodes that might be isolated (roots/leaves) if not in edges
        self.bn_model.add_nodes_from(temp_graph.nodes())

        # 2. Create CPDs
        cpds = []
        for node in self.bn_model.nodes():
            node_type = self.dg.graph.nodes[node]['type']
            parents = list(self.bn_model.get_parents(node))
            
            cpd = None
            if not parents:
                # Root Node (EDB Fact or isolated)
                # P(True) = 0.9
                cpd = TabularCPD(variable=node, variable_card=2, 
                                 values=[[1 - self.prior_prob], [self.prior_prob]])
            
            elif node_type == 'rule':
                # Rule Node: AND logic on parents (Premises) + Noise
                # P(Rule=T | P1...Pk) = 0.9 IF all Pi=T, else 0
                cpd = self._create_rule_cpd(node, parents)
                
            elif node_type == 'fact':
                # Derived Fact Node: OR logic on parents (Rule Applications)
                # P(Fact=T | R1...Rm) = 1.0 IF any Ri=T, else 0
                # Note: If a fact is both EDB (root) and Derived? 
                # In our graph construction, EDB facts (Input, Flow, Memory) don't have parents. 
                # Derived facts (Taint, Alarm) have parents.
                # Exception: Flow facts are static, never derived. Taints are derived.
                # So this separation holds.
                cpd = self._create_or_cpd(node, parents)
            
            if cpd:
                cpds.append(cpd)
        
        self.bn_model.add_cpds(*cpds)
        
        # Verify model (optional, can be slow)
        # self.bn_model.check_model()
        
        return self.bn_model

    def _create_rule_cpd(self, node, parents):
        """
        Creates a CPD for a Rule node (Noisy AND).
        """
        num_parents = len(parents)
        # Table size 2^k
        # We iterate through all combinations of parent states (0 or 1)
        # The columns in TabularCPD correspond to the cartesian product of parents' states
        # sorted by the order of parents in the list.
        # itertools.product([0, 1], repeat=k) yields (0,0..), (0,0..1), etc.
        # The last parent toggles fastest.
        
        values_0 = [] # Prob of False
        values_1 = [] # Prob of True
        
        # pgmpy expects values as flattened list of probabilities for each state
        # order: P(Node=0 | parents_config_0), P(Node=0 | parents_config_1)...
        
        for config in itertools.product([0, 1], repeat=num_parents):
            # config is tuple of states for parents
            # If all are 1 (True), then Prob(True) = rule_prob
            if all(c == 1 for c in config):
                p_true = self.rule_prob
            else:
                p_true = 0.0
            
            values_1.append(p_true)
            values_0.append(1.0 - p_true)
            
        return TabularCPD(variable=node, variable_card=2, 
                          values=[values_0, values_1],
                          evidence=parents,
                          evidence_card=[2]*num_parents)

    def _create_or_cpd(self, node, parents):
        """
        Creates a CPD for a Derived Fact node (Deterministic OR).
        """
        num_parents = len(parents)
        values_0 = []
        values_1 = []
        
        for config in itertools.product([0, 1], repeat=num_parents):
            # If any parent is 1, output is 1
            if any(c == 1 for c in config):
                p_true = 1.0
            else:
                p_true = 0.0
            
            values_1.append(p_true)
            values_0.append(1.0 - p_true)
            
        return TabularCPD(variable=node, variable_card=2, 
                          values=[values_0, values_1],
                          evidence=parents,
                          evidence_card=[2]*num_parents)

    def set_evidence(self, variable, value):
        """
        Sets evidence for a variable.
        Args:
            variable (str): Node ID.
            value (bool): Observed state.
        """
        self.evidence[variable] = 1 if value else 0

    def clear_evidence(self, variable=None):
        if variable:
            if variable in self.evidence:
                del self.evidence[variable]
        else:
            self.evidence = {}

    def get_structure(self):
        return list(self.bn_model.edges())
