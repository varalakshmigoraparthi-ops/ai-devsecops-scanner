from ai.analyzer import analyze_finding


finding = {
    "type": "SQL Injection",
    "severity": "HIGH",
    "cwe": "CWE-89",
    "line": 6
}


result = analyze_finding(finding)

print("\nAI Security Analysis")
print("=" * 50)

print(f"Vulnerability : {result['type']}")
print(f"Severity      : {result['severity']}")
print(f"CWE           : {result['cwe']}")
print(f"Line          : {result['line']}")

print("\nWhy is it vulnerable?")
print(result["why"])

print("\nRisk:")
print(result["risk"])

print("\nRecommendation:")
print(result["recommendation"])