import ast


def detect_path_traversal(code: str):

    findings = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):

        if isinstance(node, ast.Call):

            if isinstance(node.func, ast.Name):
                function_name = node.func.id

                if function_name in ["open", "read"]:

                    for arg in node.args:

                        if isinstance(arg, ast.Name):

                            findings.append({
                                "type": "Path Traversal",
                                "severity": "HIGH",
                                "cwe": "CWE-22",
                                "line": node.lineno,
                                "message": (
                                    "Possible path traversal detected because "
                                    "a variable is used as a file path."
                                )
                            })

    return findings