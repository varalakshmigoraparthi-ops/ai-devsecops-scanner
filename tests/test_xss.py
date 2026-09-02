from scanner.rules.xss import detect_xss


vulnerable_code = """
from markupsafe import Markup

user_input = input("Enter your name: ")
result = Markup(user_input)
"""

findings = detect_xss(vulnerable_code)

for finding in findings:
    print(finding)