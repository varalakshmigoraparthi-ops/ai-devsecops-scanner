import ast
from python_parser import parse_python_code


code = """
x = 10
print(x)
"""

tree = parse_python_code(code)

print(ast.dump(tree, indent=4))

