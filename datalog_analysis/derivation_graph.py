import networkx as nx
from pycparser import c_ast

class DerivationGraph:
    """
    Constructs and analyzes a derivation graph for taint analysis using Datalog-style rules.
    
    Nodes represent logical facts (tuples) or rule applications.
    Edges represent dependencies (premises -> rule -> conclusion).
    
    The graph implements the following Datalog rules:
    R1: Taint(v) :- Input(v)
        - If v is an input variable, it is tainted.
    R2: Taint(v2) :- Taint(v1), Flow(v1, v2)
        - Taint propagates along data flow edges.
    R3: Alarm(s) :- Taint(v), Memory(v, s)
        - If a tainted variable v is used in a memory operation at statement s, raise an alarm.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.facts = set()  # Set of fact identifiers to avoid duplicates
        self.rules_applied = 0
        
        # Known memory-unsafe functions to map to Memory facts
        # Maps function name to list of argument indices that are 'sinks' or critical memory uses
        self.memory_sink_functions = {
            'strcpy': [1],   # src argument (index 1) controls the copy amount indirectly or content
            'strcat': [1],
            'memcpy': [1],
            'sprintf': range(1, 10), # arguments > 0 are formatted into buffer
            'printf': range(1, 10),  # format string attacks
        }

    @classmethod
    def from_parser(cls, parser):
        """
        Builds the initial graph from parsed program artifacts (Extensional Database - EDB).
        
        Args:
            parser (CProgramParser): A parser instance that has analyzed a file.
        
        Returns:
            DerivationGraph: Initialized graph with EDB facts.
        """
        dg = cls()
        
        # 1. Add Input facts: Input(v)
        # Represents sources of untrusted data
        for src in parser.get_input_sources():
            dg.add_fact('Input', src)

        # 2. Add Flow facts: Flow(v1, v2)
        # Represents data dependency from v1 to v2
        for v1, v2 in parser.get_data_flows():
            dg.add_fact('Flow', v1, v2)

        # 3. Add Memory facts: Memory(v, s)
        # Represents that variable v is used in a sensitive memory operation at line s
        
        # From explicit operations (e.g., array access buf[i])
        for op in parser.get_memory_operations():
            # If we access array[index], and 'index' is tainted, it's bad.
            # op['index'] holds the variable name of the index if resolved
            var_name = op.get('index')
            if isinstance(var_name, str):
                dg.add_fact('Memory', var_name, op['line'])

        # From function calls (sinks)
        for call in parser.function_calls:
            name = call['name']
            if name in dg.memory_sink_functions:
                indices = dg.memory_sink_functions[name]
                for idx, arg in enumerate(call['args']):
                    if idx not in indices and idx not in list(indices):
                        continue
                        
                    # Extract variable name from argument AST
                    var_name = None
                    if isinstance(arg, c_ast.ID):
                        var_name = arg.name
                    elif isinstance(arg, c_ast.UnaryOp) and arg.op == '&' and isinstance(arg.expr, c_ast.ID):
                        # Handle &x passed to function
                        var_name = arg.expr.name
                    elif isinstance(arg, c_ast.Cast):
                        # Handle (char*)x
                        if isinstance(arg.expr, c_ast.ID):
                             var_name = arg.expr.name

                    if var_name:
                         dg.add_fact('Memory', var_name, call['line'])

        return dg

    def add_fact(self, type_name, *args):
        """Adds a fact node to the graph if it doesn't exist."""
        # Create a canonical ID for the fact: Type(arg1, arg2)
        fact_id = f"{type_name}({', '.join(map(str, args))})"
        if fact_id not in self.facts:
            self.facts.add(fact_id)
            self.graph.add_node(fact_id, type='fact', predicate=type_name, args=args)
        return fact_id

    def add_rule_application(self, rule_name, premises, conclusion):
        """
        Adds a rule application node connecting premises to conclusion.
        
        Args:
            rule_name (str): Name of the rule (e.g., 'R1').
            premises (list): List of fact_ids used as premises.
            conclusion (str): The fact_id derived.
        
        Returns:
            bool: True if this is a new derivation, False otherwise.
        """
        # Unique ID for this specific application instance to avoid re-adding
        premise_key = "_".join(sorted(premises))
        rule_node_id = f"Rule_{rule_name}_[{premise_key}]->{conclusion}"
        
        if rule_node_id in self.graph:
            return False
        
        self.graph.add_node(rule_node_id, type='rule', rule=rule_name)
        
        for p in premises:
            self.graph.add_edge(p, rule_node_id)
        
        self.graph.add_edge(rule_node_id, conclusion)
        self.rules_applied += 1
        return True

    def apply_rules(self):
        """
        Iteratively applies Datalog rules until a fixpoint is reached (no new facts derived).
        """
        changed = True
        while changed:
            changed = False
            # Snapshot of current facts to iterate over
            current_facts = list(self.facts)
            
            # Index facts by predicate for O(1) access to lists
            facts_by_type = {'Input': [], 'Taint': [], 'Flow': [], 'Memory': [], 'Alarm': []}
            for f in current_facts:
                pred = self.graph.nodes[f]['predicate']
                if pred in facts_by_type:
                    facts_by_type[pred].append(f)
            
            # R1: Taint(v) :- Input(v)
            for inp in facts_by_type['Input']:
                v = self.graph.nodes[inp]['args'][0]
                
                conclusion = self.add_fact('Taint', v)
                if self.add_rule_application('R1', [inp], conclusion):
                    changed = True

            # R2: Taint(v2) :- Taint(v1), Flow(v1, v2)
            for t in facts_by_type['Taint']:
                v1 = self.graph.nodes[t]['args'][0]
                
                # Find matching flows starting with v1
                # Optimization: In a larger system, we'd index Flow by first arg.
                # Here we iterate all flows (usually small number).
                for f in facts_by_type['Flow']:
                    f_v1, f_v2 = self.graph.nodes[f]['args']
                    if f_v1 == v1:
                        conclusion = self.add_fact('Taint', f_v2)
                        if self.add_rule_application('R2', [t, f], conclusion):
                            changed = True

            # R3: Alarm(s) :- Taint(v), Memory(v, s)
            for t in facts_by_type['Taint']:
                v = self.graph.nodes[t]['args'][0]
                
                for m in facts_by_type['Memory']:
                    m_v, s = self.graph.nodes[m]['args']
                    if m_v == v:
                        conclusion = self.add_fact('Alarm', s)
                        if self.add_rule_application('R3', [t, m], conclusion):
                            changed = True

    def get_alarms(self):
        """Returns a list of all Alarm fact nodes."""
        return [n for n in self.facts if n.startswith('Alarm')]

    def get_derivation_path(self, alarm_node):
        """
        Returns the derivation path (subgraph) for a specific alarm.
        """
        if alarm_node not in self.graph:
            return []
            
        ancestors = nx.ancestors(self.graph, alarm_node)
        path = list(ancestors) + [alarm_node]
        return path

    def to_dict(self):
        """Exports the graph structure as a dictionary suitable for serialization."""
        return nx.node_link_data(self.graph)

    def visualize(self, output_file):
        """
        Visualizes the graph using graphviz/pydot if available.
        """
        try:
            # Try to write using pydot
            pydot_graph = nx.drawing.nx_pydot.to_pydot(self.graph)
            pydot_graph.write_png(output_file)
        except Exception as e:
            # Fallback
            print(f"Visualization failed (Graphviz might be missing): {e}")
            with open(output_file + '.log', 'w') as f:
                f.write(str(self.graph.nodes(data=True)))
                f.write('\n')
                f.write(str(self.graph.edges()))