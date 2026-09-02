import ast
import re


SECRET_PATTERNS = [
    r"api[_-]?key",
    r"secret[_-]?key",
    r"password",
    r"passwd",
    r"token",
    r"access[_-]?key",
]


def detect_hardcoded_secrets(code: str):
    findings = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            for target in node.targets:

                if isinstance(target, ast.Name):

                    variable_name = target.id.lower()

                    if any(
                        re.search(pattern, variable_name)
                        for pattern in SECRET_PATTERNS
                    ):

                        if isinstance(node.value, ast.Constant):

                            if isinstance(node.value.value, str):

                                findings.append({
                                    "type": "Hardcoded Secret",
                                    "severity": "CRITICAL",
                                    "cwe": "CWE-798",
                                    "line": node.lineno,
                                    "message": (
                                        "Possible hardcoded secret detected. "
                                        "Sensitive credentials should not be stored "
                                        "directly in source code."
                                    )
                                })

    return findings