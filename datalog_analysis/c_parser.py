import os
import sys
from pycparser import parse_file, c_ast, c_parser

class CProgramParser:
    """
    Parses C source code and extracts semantic information for taint analysis.
    
    Attributes:
        filepath (str): Path to the C file.
        ast (c_ast.FileAST): The parsed AST.
    """
    
    def __init__(self):
        self.filepath = None
        self.ast = None
        self.input_functions = {'scanf', 'gets', 'fgets', 'read', 'fread', 'atoi', 'atol', 'atof'}
        
        # Extracted data
        self.function_calls = []  # List of dicts
        self.assignments = []     # List of (target, source) tuples
        self.memory_ops = []      # List of dicts
        self.data_flows = []      # List of (source_var, target_var) tuples based on assignments

    def parse_file(self, filepath):
        """
        Parses a C file using pycparser.
        
        Args:
            filepath (str): Path to the C file to parse.
            
        Raises:
            Exception: If parsing fails.
        """
        self.filepath = filepath
        self._reset_data()
        
        # Determine path to fake_libc_include
        current_dir = os.path.dirname(os.path.abspath(__file__))
        fake_libc_path = os.path.join(current_dir, 'fake_libc_include')
        
        cpp_args = ['-E', f'-I{fake_libc_path}']
        
        try:
            self.ast = parse_file(filepath, use_cpp=True, cpp_path='cpp', cpp_args=cpp_args)
        except Exception as e:
            # Fallback: try parsing without CPP if simple enough (might fail on macros)
            print(f"Warning: CPP failed ({e}), attempting raw parse...")
            # Note: parse_file without use_cpp doesn't support headers well.
            # We re-raise for now as our test programs rely on headers.
            raise e
            
        self._analyze()

    def _reset_data(self):
        self.function_calls = []
        self.assignments = []
        self.memory_ops = []
        self.data_flows = []

    def _analyze(self):
        """Runs the AST visitor to extract information."""
        if not self.ast:
            return
            
        visitor = AnalysisVisitor(self)
        visitor.visit(self.ast)

    def get_input_sources(self):
        """
        Identifies variables that receive data from known input functions.
        
        Returns:
            list: Variables (names) that are potential taint sources.
        """
        sources = []
        for call in self.function_calls:
            if call['name'] in self.input_functions:
                # Handle cases like x = atoi(argv[1])
                # This is handled via assignments checking if source is a call
                pass
            
            # Handle cases like scanf("%s", buffer) -> buffer is source
            # Simplistic heuristic: pointer arguments to input functions are sources
            if call['name'] == 'scanf' and len(call['args']) > 1:
                # Skip format string, look at other args
                for arg in call['args'][1:]:
                    if isinstance(arg, c_ast.UnaryOp) and arg.op == '&':
                        # &x -> x is source
                         if isinstance(arg.expr, c_ast.ID):
                             sources.append(arg.expr.name)
                    elif isinstance(arg, c_ast.ID):
                        # buffer -> buffer is source
                        sources.append(arg.name)
        
        # Add sources from assignments where RHS is an input call (e.g. x = atoi(...))
        for target, source in self.assignments:
             if isinstance(source, dict) and source.get('type') == 'call':
                 if source.get('name') in self.input_functions:
                     sources.append(target)
        
        # Add main(argc, argv) arguments as sources if they are used
        # (This would require scope analysis, for now we skip implicit main args as 'sources' 
        # unless explicit access is detected, but simple heuristic: argv is a source)
        return list(set(sources))

    def get_assignments(self):
        """
        Returns list of assignments detected.
        
        Returns:
            list: List of {'target': str, 'source': str/dict, 'line': int}
        """
        return self.assignments

    def get_memory_operations(self):
        """
        Returns list of array accesses and pointer dereferences.
        
        Returns:
            list: List of dicts describing the operation.
        """
        return self.memory_ops

    def get_data_flows(self):
        """
        Returns potential data flow edges derived from assignments.
        
        Returns:
            list: List of (source_var, target_var)
        """
        return self.data_flows


class AnalysisVisitor(c_ast.NodeVisitor):
    def __init__(self, parser_instance):
        self.parser = parser_instance

    def visit_FuncCall(self, node):
        func_name = ''
        if isinstance(node.name, c_ast.ID):
            func_name = node.name.name
        
        args = []
        if node.args:
            for arg in node.args.exprs:
                args.append(arg)
        
        call_info = {
            'name': func_name,
            'args': args,
            'line': node.coord.line if node.coord else 0,
            'type': 'call'
        }
        self.parser.function_calls.append(call_info)
        
        # Visit arguments to capture nested calls/ops
        if node.args:
            self.visit(node.args)

    def visit_Assignment(self, node):
        target = self._get_name(node.lvalue)
        source = self._resolve_expr(node.rvalue)
        
        if target:
            self.parser.assignments.append({
                'target': target,
                'source': source,
                'line': node.coord.line if node.coord else 0
            })
            
            # If source is a simple ID, record flow
            if isinstance(source, str):
                self.parser.data_flows.append((source, target))
            elif isinstance(source, dict) and source.get('type') == 'call':
                # Flow from function return to target
                pass 

        self.generic_visit(node)

    def visit_Decl(self, node):
        # Handle declarations with initialization: int x = y;
        if node.init:
            target = node.name
            source = self._resolve_expr(node.init)
            if target:
                self.parser.assignments.append({
                    'target': target,
                    'source': source,
                    'line': node.coord.line if node.coord else 0
                })
                if isinstance(source, str):
                    self.parser.data_flows.append((source, target))
        
        self.generic_visit(node)

    def visit_ArrayRef(self, node):
        name = self._get_name(node.name)
        index = self._resolve_expr(node.subscript)
        
        self.parser.memory_ops.append({
            'type': 'array_access',
            'object': name,
            'index': index,
            'line': node.coord.line if node.coord else 0
        })
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        # Handle pointer dereference *ptr
        if node.op == '*':
            target = self._get_name(node.expr)
            self.parser.memory_ops.append({
                'type': 'pointer_deref',
                'object': target,
                'line': node.coord.line if node.coord else 0
            })
        self.generic_visit(node)

    def _get_name(self, node):
        """Helper to extract variable name from node."""
        if isinstance(node, c_ast.ID):
            return node.name
        elif isinstance(node, c_ast.StructRef):
            base = self._get_name(node.name)
            field = self._get_name(node.field)
            return f"{base}.{field}" if base and field else None
        elif isinstance(node, c_ast.ArrayRef):
             # For array assignment like buf[i] = x, return buf
             return self._get_name(node.name)
        elif isinstance(node, c_ast.UnaryOp) and node.op == '*':
             return self._get_name(node.expr)
        return None

    def _resolve_expr(self, node):
        """Helper to resolve expression to a simple representation."""
        if isinstance(node, c_ast.ID):
            return node.name
        elif isinstance(node, c_ast.Constant):
            return node.value
        elif isinstance(node, c_ast.FuncCall):
            func_name = ''
            if isinstance(node.name, c_ast.ID):
                func_name = node.name.name
            return {'type': 'call', 'name': func_name}
        elif isinstance(node, c_ast.BinaryOp):
            return f"BinaryOp({node.op})"
        elif isinstance(node, c_ast.ArrayRef):
            return f"{self._get_name(node.name)}[]"
        return "ComplexExpr"

if __name__ == "__main__":
    # Example Usage
    parser = CProgramParser()
    import sys
    if len(sys.argv) > 1:
        try:
            parser.parse_file(sys.argv[1])
            print(f"Parsed {sys.argv[1]}")
            print("Input Sources:", parser.get_input_sources())
            print("Assignments:", len(parser.get_assignments()))
            print("Memory Ops:", len(parser.get_memory_operations()))
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Usage: python c_parser.py <file.c>")
