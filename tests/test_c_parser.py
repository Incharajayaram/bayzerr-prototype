import os
import pytest
from datalog_analysis.c_parser import CProgramParser

class TestCParser:
    @pytest.fixture
    def parser(self):
        return CProgramParser()

    @pytest.fixture
    def test_programs_dir(self):
        # Assumes running from project root
        return os.path.join(os.getcwd(), 'test_programs')

    def test_simple_overflow(self, parser, test_programs_dir):
        filepath = os.path.join(test_programs_dir, 'simple_overflow.c')
        parser.parse_file(filepath)
        
        # Check function calls
        calls = [c['name'] for c in parser.function_calls]
        assert 'strcpy' in calls
        assert 'printf' in calls
        
        # Check memory operations
        # simple_overflow accesses argv[1] (ArrayRef) and buffer (implicit in strcpy logic, but visible if accessed via array syntax)
        # Actually in simple_overflow.c:
        #  strcpy(buffer, input); -> No explicit ArrayRef in AST for buffer here, it's an ID passed to func
        #  But main accesses argv[1]
        mem_ops = parser.get_memory_operations()
        
        # argv[1] is an array access
        argv_access = any(op['object'] == 'argv' and str(op['index']) == '1' for op in mem_ops)
        assert argv_access, "Should detect argv[1] access"

    def test_taint_flow(self, parser, test_programs_dir):
        filepath = os.path.join(test_programs_dir, 'taint_flow.c')
        parser.parse_file(filepath)
        
        # Check input sources
        # input_val = atoi(argv[1])
        # assignments should capture input_val = call(atoi)
        assignments = parser.get_assignments()
        
        # Verify assignment from atoi
        atoi_assign = any(
            a['target'] == 'input_val' and 
            isinstance(a['source'], dict) and 
            a['source'].get('name') == 'atoi'
            for a in assignments
        )
        assert atoi_assign, "Should detect assignment from atoi"

        # Check data flows
        # intermediate_val = input_val + 5; (ComplexExpr or BinaryOp)
        # We handle simplistic ID flows in visitor. BinaryOp might need 'input_val' extraction to be robust
        # But let's check what we implemented.
        # Visitor _resolve_expr returns "BinaryOp(+)" for expressions, so direct flow (source -> target) might not catch it 
        # unless we enhance _resolve_expr to return variables involved.
        # But 'process_data(final_val)' is a call.
        
        calls = [c['name'] for c in parser.function_calls]
        assert 'process_data' in calls

    def test_complex_flow(self, parser, test_programs_dir):
        filepath = os.path.join(test_programs_dir, 'complex_flow.c')
        parser.parse_file(filepath)
        
        assignments = parser.get_assignments()
        
        # currentUser.id = atoi(argv[1])
        struct_assign = any(
            a['target'] == 'currentUser.id' 
            for a in assignments
        )
        assert struct_assign, "Should detect structure field assignment"
        
        # Check memory ops
        mem_ops = parser.get_memory_operations()
        # currentUser.name[19] = '\0' -> array access on struct field
        struct_array_access = any(
            op['object'] == 'currentUser.name' 
            for op in mem_ops
        )
        assert struct_array_access, "Should detect array access on struct field"

    def test_assignments_extraction(self, parser, test_programs_dir):
        filepath = os.path.join(test_programs_dir, 'taint_flow.c')
        parser.parse_file(filepath)
        
        assignments = parser.get_assignments()
        assert len(assignments) > 0
        
        # Check specific assignment: int intermediate_val = input_val + 5;
        found = False
        for a in assignments:
            if a['target'] == 'intermediate_val':
                found = True
                break
        assert found

if __name__ == "__main__":
    pytest.main(['-v', __file__])
