from scanner.engine import scan_code


def test_vulnerable_code_detection():
    code = """
import os

username = input("Enter username: ")
filename = input("Enter filename: ")
command = input("Enter command: ")

query = "SELECT * FROM users WHERE username = '" + username + "'"

os.system(command)

API_KEY = "sk_test_123456789"

html = "<h1>" + username + "</h1>"

with open(filename, "r") as file:
    data = file.read()
"""

    findings = scan_code(code)

    assert len(findings) == 5

    vulnerability_types = {
        finding["type"]
        for finding in findings
    }

    assert "SQL Injection" in vulnerability_types
    assert "Command Injection" in vulnerability_types
    assert "Hardcoded Secret" in vulnerability_types
    assert "Cross-Site Scripting (XSS)" in vulnerability_types
    assert "Path Traversal" in vulnerability_types