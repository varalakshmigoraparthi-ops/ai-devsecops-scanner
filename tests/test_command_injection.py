from scanner.rules.command_injection import detect_command_injection


vulnerable_code = """
import os

user_input = input("Enter command: ")
os.system(user_input)
"""

findings = detect_command_injection(vulnerable_code)

for finding in findings:
    print(finding)