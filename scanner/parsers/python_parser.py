import ast


def parse_python_code(code: str):
    """
    Parse Python source code and return its AST tree.
    """
    try:
        tree = ast.parse(code)
        return tree
    except SyntaxError as error:
        return {
            "error": "Invalid Python code",
            "message": str(error)
        }