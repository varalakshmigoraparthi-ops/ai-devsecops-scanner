import ast


def detect_xss(code: str):
    findings = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    # Keep track of variables that receive user input
    user_input_variables = set()

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            if isinstance(node.value, ast.Call):

                if (
                    isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "input"
                ):
                    for target in node.targets:

                        if isinstance(target, ast.Name):
                            user_input_variables.add(target.id)

    # Look for user input being combined with HTML
    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            if isinstance(node.value, ast.BinOp):

                source = ast.get_source_segment(
                    code,
                    node.value
                ) or ""

                contains_user_input = any(
                    isinstance(child, ast.Name)
                    and child.id in user_input_variables
                    for child in ast.walk(node.value)
                )

                contains_html = (
                    "<" in source
                    or ">" in source
                    or "html" in source.lower()
                )

                if contains_user_input and contains_html:

                    findings.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "cwe": "CWE-79",
                        "line": node.lineno,
                        "message": (
                            "Possible XSS vulnerability detected because "
                            "user-controlled input is concatenated into "
                            "HTML content without proper output encoding."
                        )
                    })

    return findings