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
        self.assignments = []     # List of dicts
        self.memory_ops = []      # List of dicts
        self.data_flows = []      # List of (source_var, target_var) tuples based on assignments
        self.main_args = []       # List of arguments to main function
        self.function_defs = {}   # Map function name -> list of parameter names

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
        self.main_args = []
        self.function_defs = {}

    def _analyze(self):
        """Runs the AST visitor to extract information."""
        if not self.ast:
            return
            
        visitor = AnalysisVisitor(self)
        visitor.visit(self.ast)
        
        self._post_process_calls()

    def _post_process_calls(self):
        """Generates implicit flows from function calls to function parameters."""
        for call in self.function_calls:
            name = call['name']
            if name in self.function_defs:
                params = self.function_defs[name]
                args = call['args']
                
                # Match args to params by position
                for i, arg_expr in enumerate(args):
                    if i < len(params):
                        param_name = params[i]
                        # Resolve argument to a variable name
                        # We use a helper from visitor logic essentially, but simplified here
                        # We need a way to resolve expr from the AST node 'arg_expr'
                        # We can reuse the visitor's _resolve_expr logic if we make it static or part of parser?
                        # Or just instantiate a visitor temporarily or move logic to parser.
                        # Let's move _resolve_expr to CProgramParser as a static/helper or method.
                        source_vars = self._extract_vars_from_node(arg_expr)
                        for src in source_vars:
                            self.data_flows.append((src, param_name))

    def _extract_vars_from_node(self, node):
        """Helper to extract variables, duplicated from Visitor logic for use in post-processing."""
        # Simple extraction logic
        vars_found = []
        if isinstance(node, c_ast.ID):
            vars_found.append(node.name)
        elif isinstance(node, c_ast.BinaryOp):
            vars_found.extend(self._extract_vars_from_node(node.left))
            vars_found.extend(self._extract_vars_from_node(node.right))
        elif isinstance(node, c_ast.UnaryOp):
            vars_found.extend(self._extract_vars_from_node(node.expr))
        elif isinstance(node, c_ast.ArrayRef):
            # Resolve array access to the array name for coarse-grained taint
            name = self._get_name_from_node(node.name)
            if name:
                vars_found.append(name)
        elif isinstance(node, c_ast.Cast):
            vars_found.extend(self._extract_vars_from_node(node.expr))
        return vars_found

    def _get_name_from_node(self, node):
        if isinstance(node, c_ast.ID):
            return node.name
        elif isinstance(node, c_ast.ArrayRef):
             return self._get_name_from_node(node.name)
        return None

    def get_input_sources(self):
        """
        Identifies variables that receive data from known input functions.
        
        Returns:
            list: Variables (names) that are potential taint sources.
        """
        sources = []
        for call in self.function_calls:
            if call['name'] in self.input_functions:
                pass
            
            if call['name'] == 'scanf' and len(call['args']) > 1:
                for arg in call['args'][1:]:
                    if isinstance(arg, c_ast.UnaryOp) and arg.op == '&':
                         if isinstance(arg.expr, c_ast.ID):
                             sources.append(arg.expr.name)
                    elif isinstance(arg, c_ast.ID):
                        sources.append(arg.name)
        
        for assignment in self.assignments:
             target = assignment['target']
             source = assignment['source']
             if isinstance(source, dict) and source.get('type') == 'call':
                 if source.get('name') in self.input_functions:
                     sources.append(target)
        
        sources.extend(self.main_args)
        
        return list(set(sources))

    def get_assignments(self):
        return self.assignments

    def get_memory_operations(self):
        return self.memory_ops

    def get_data_flows(self):
        return self.data_flows


class AnalysisVisitor(c_ast.NodeVisitor):
    def __init__(self, parser_instance):
        self.parser = parser_instance

    def visit_FuncDef(self, node):
        func_name = node.decl.name
        params = []
        if node.decl.type.args:
             for param in node.decl.type.args.params:
                 if isinstance(param, c_ast.Decl):
                     params.append(param.name)
        
        self.parser.function_defs[func_name] = params

        if func_name == 'main':
             self.parser.main_args.extend(params)
        
        self.generic_visit(node)

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
            'args': args, # Store raw AST nodes for post-processing
            'line': node.coord.line if node.coord else 0,
            'type': 'call'
        }
        self.parser.function_calls.append(call_info)
        
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
            
            sources = self._extract_vars(node.rvalue)
            for s in sources:
                self.parser.data_flows.append((s, target))

        self.generic_visit(node)

    def visit_Decl(self, node):
        if node.init:
            target = node.name
            source = self._resolve_expr(node.init)
            if target:
                self.parser.assignments.append({
                    'target': target,
                    'source': source,
                    'line': node.coord.line if node.coord else 0
                })
                
                sources = self._extract_vars(node.init)
                for s in sources:
                    self.parser.data_flows.append((s, target))
        
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
        if node.op == '*':
            target = self._get_name(node.expr)
            self.parser.memory_ops.append({
                'type': 'pointer_deref',
                'object': target,
                'line': node.coord.line if node.coord else 0
            })
        self.generic_visit(node)

    def _get_name(self, node):
        if isinstance(node, c_ast.ID):
            return node.name
        elif isinstance(node, c_ast.StructRef):
            base = self._get_name(node.name)
            field = self._get_name(node.field)
            return f"{base}.{field}" if base and field else None
        elif isinstance(node, c_ast.ArrayRef):
             return self._get_name(node.name)
        elif isinstance(node, c_ast.UnaryOp) and node.op == '*':
             return self._get_name(node.expr)
        elif isinstance(node, c_ast.Cast):
             return self._get_name(node.expr)
        return None

    def _extract_vars(self, node):
        # Uses the parser's helper method to avoid duplication
        return self.parser._extract_vars_from_node(node)

    def _resolve_expr(self, node):
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
            # Simplify: treat array ref as the array variable itself
            return self._get_name(node.name) 
        return "ComplexExpr"

if __name__ == "__main__":
    parser = CProgramParser()
    import sys
    if len(sys.argv) > 1:
        try:
            parser.parse_file(sys.argv[1])
            print(f"Parsed {sys.argv[1]}")
            print("Input Sources:", parser.get_input_sources())
            print("Data Flows:", parser.get_data_flows())
            print("Memory Ops:", parser.get_memory_operations())
        except Exception as e:
            print(f"Error: {e}")
