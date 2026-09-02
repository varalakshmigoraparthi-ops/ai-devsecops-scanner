import ast


DANGEROUS_FUNCTIONS = {
    "system",
    "popen",
    "run",
    "call",
    "check_call",
    "check_output"
}


def detect_command_injection(code: str):
    findings = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):

        if isinstance(node, ast.Call):

            if isinstance(node.func, ast.Attribute):

                function_name = node.func.attr

                if function_name in DANGEROUS_FUNCTIONS:

                    if node.args:
                        argument = node.args[0]

                        # Detect user-controlled or variable input
                        if isinstance(argument, ast.Name):

                            findings.append({
                                "type": "Command Injection",
                                "severity": "CRITICAL",
                                "cwe": "CWE-78",
                                "line": node.lineno,
                                "message": (
                                    "Possible command injection detected because "
                                    "a variable is passed to a potentially dangerous "
                                    "system command."
                                )
                            })

    return findings