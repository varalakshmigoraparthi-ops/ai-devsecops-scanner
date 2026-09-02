from scanner.rules.secrets import detect_hardcoded_secrets


vulnerable_code = """
API_KEY = "my-super-secret-api-key"
PASSWORD = "admin123"
"""

findings = detect_hardcoded_secrets(vulnerable_code)

for finding in findings:
    print(finding)