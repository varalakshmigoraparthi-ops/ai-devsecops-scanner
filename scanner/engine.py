from scanner.rules.sql_injection import detect_sql_injection
from scanner.rules.command_injection import detect_command_injection
from scanner.rules.secrets import detect_hardcoded_secrets
from scanner.rules.xss import detect_xss

from scanner.rules.path_traversal import detect_path_traversal
def scan_code(code: str):
    findings = []

    findings.extend(detect_sql_injection(code))
    findings.extend(detect_command_injection(code))
    findings.extend(detect_hardcoded_secrets(code))
    findings.extend(detect_xss(code))
    findings.extend(detect_path_traversal(code))
    return findings