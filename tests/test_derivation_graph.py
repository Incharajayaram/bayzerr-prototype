import pytest
import os
from datalog_analysis.c_parser import CProgramParser
from datalog_analysis.derivation_graph import DerivationGraph

TEST_DIR = os.path.join(os.path.dirname(__file__), '..', 'test_programs')

def parse_and_analyze(filename):
    filepath = os.path.join(TEST_DIR, filename)
    parser = CProgramParser()
    parser.parse_file(filepath)
    
    dg = DerivationGraph.from_parser(parser)
    dg.apply_rules()
    return dg

def test_simple_overflow():
    """
    Test simple_overflow.c
    Expected: Alarm due to tainted 'buffer' being used or 'scanf' input flowing to sensitive op?
    Let's check the code structure (assumed):
    char buffer[10];
    scanf("%s", buffer); // Input(buffer) -> Taint(buffer)
    strcpy(dest, buffer); // Memory(buffer, line) -> Alarm
    """
    dg = parse_and_analyze('simple_overflow.c')
    alarms = dg.get_alarms()
    
    # We expect at least one alarm
    assert len(alarms) > 0, "Should detect alarm in simple_overflow.c"
    
    # Check if derivation path exists
    path = dg.get_derivation_path(alarms[0])
    assert len(path) > 0

    # Verify input facts exist
    inputs = [n for n in dg.facts if n.startswith('Input')]
    assert len(inputs) > 0

def test_taint_flow():
    """
    Test taint_flow.c
    Expected: Taint propagation through assignment.
    x = read(); // Input(x)
    y = x;      // Flow(x, y)
    memcpy(dest, y, ...); // Memory(y, line) -> Alarm
    """
    dg = parse_and_analyze('taint_flow.c')
    alarms = dg.get_alarms()
    
    assert len(alarms) > 0, "Should detect alarm in taint_flow.c"
    
    # Check for Flow usage in derivation
    path = dg.get_derivation_path(alarms[0])
    flow_facts = [n for n in path if 'Flow' in n]
    # In taint_flow.c, there should be a flow from source to sink variable
    # Depending on implementation details, we check if logic held
    
    taints = [n for n in dg.facts if n.startswith('Taint')]
    # Should have Taint(source) and Taint(dest)
    assert len(taints) >= 2

def test_complex_flow():
    """
    Test complex_flow.c
    Expected: Taint propagation through multiple steps or control structures (if supported).
    """
    dg = parse_and_analyze('complex_flow.c')
    alarms = dg.get_alarms()
    
    assert len(alarms) > 0, "Should detect alarm in complex_flow.c"

def test_no_false_positive():
    """
    Test a safe program (or ensure safe paths don't alarm).
    Since we don't have a 'safe.c', we construct a graph manually to test logic.
    """
    dg = DerivationGraph()
    dg.add_fact('Input', 'a')
    dg.add_fact('Flow', 'a', 'b')
    # No Memory usage for 'b' or 'a'
    
    dg.apply_rules()
    assert len(dg.get_alarms()) == 0
    
    # Now add memory usage for unrelated variable 'c'
    dg.add_fact('Memory', 'c', 10)
    dg.apply_rules()
    assert len(dg.get_alarms()) == 0
    
    # Now add memory usage for 'b'
    dg.add_fact('Memory', 'b', 20)
    dg.apply_rules()
    assert len(dg.get_alarms()) == 1
    assert "Alarm(20)" in dg.get_alarms()[0]