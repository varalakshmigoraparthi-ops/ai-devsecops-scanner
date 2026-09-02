from scanner.rules.sql_injection import detect_sql_injection


vulnerable_code = """
user_id = input("Enter user id: ")
query = "SELECT * FROM users WHERE id = " + user_id
"""

findings = detect_sql_injection(vulnerable_code)

for finding in findings:
    print(finding)
    