import ast


def detect_sql_injection(code: str):
    findings = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):

        # Detect SQL query created using string concatenation
        if isinstance(node, ast.Assign):

            if isinstance(node.value, ast.BinOp):
                if isinstance(node.value.op, ast.Add):

                    if isinstance(node.targets[0], ast.Name):
                        variable_name = node.targets[0].id

                        if any(
                            keyword in variable_name.lower()
                            for keyword in ["query", "sql", "statement"]
                        ):
                            findings.append({
                                "type": "SQL Injection",
                                "severity": "HIGH",
                                "cwe": "CWE-89",
                                "line": node.lineno,
                                "message": "Possible SQL injection detected because SQL query is constructed using string concatenation."
                            })

    return findings