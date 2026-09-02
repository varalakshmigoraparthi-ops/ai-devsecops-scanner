from scanner.engine import scan_code


vulnerable_code = """
import os
from markupsafe import Markup

API_KEY = "my-secret-key"

user_id = input("Enter ID: ")
query = "SELECT * FROM users WHERE id = " + user_id

user_input = input("Enter command: ")
os.system(user_input)

name = input("Enter name: ")
result = Markup(name)
"""


findings = scan_code(vulnerable_code)

print("\nSecurity Scan Results")
print("=" * 50)

for finding in findings:
    print(f"Type     : {finding['type']}")
    print(f"Severity : {finding['severity']}")
    print(f"CWE      : {finding['cwe']}")
    print(f"Line     : {finding['line']}")
    print(f"Message  : {finding['message']}")
    print("-" * 50)