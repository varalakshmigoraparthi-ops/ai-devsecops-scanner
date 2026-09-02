def analyze_finding(finding):
    vulnerability_type = finding.get("type")
    severity = finding.get("severity")
    cwe = finding.get("cwe")
    line = finding.get("line")

    explanations = {
        "SQL Injection": {
            "why": (
                "The SQL query appears to be constructed using user-controlled "
                "input. This can allow an attacker to modify the SQL query."
            ),
            "risk": (
                "An attacker may access, modify, or delete database information."
            ),
            "recommendation": (
                "Use parameterized queries or prepared statements instead of "
                "concatenating user input into SQL queries."
            )
        },

        "Command Injection": {
            "why": (
                "A variable is passed to a system command that may execute "
                "operating-system commands."
            ),
            "risk": (
                "An attacker may execute unauthorized commands on the server."
            ),
            "recommendation": (
                "Avoid passing untrusted input directly to system commands. "
                "Use safe APIs and validate allowed input."
            )
        },

        "Hardcoded Secret": {
            "why": (
                "A sensitive value such as an API key or password is directly "
                "stored inside the source code."
            ),
            "risk": (
                "Attackers who obtain the source code may gain access to "
                "protected services or systems."
            ),
            "recommendation": (
                "Store secrets in environment variables or a secure secret "
                "management system."
            )
        },

        "Cross-Site Scripting (XSS)": {
            "why": (
                "User-controlled data may be rendered without proper output "
                "encoding."
            ),
            "risk": (
                "An attacker may inject malicious JavaScript into a web page "
                "and execute it in another user's browser."
            ),
            "recommendation": (
                "Validate input and properly encode or sanitize output before "
                "rendering user-controlled data."
            )
        },

        "Path Traversal": {
            "why": (
                "The file path is directly constructed using user-controlled "
                "input. An attacker may use path traversal sequences such as "
                "'../' to access files outside the intended directory."
            ),
            "risk": (
                "An attacker may read sensitive files from the server, including "
                "configuration files, credentials, or application secrets."
            ),
            "recommendation": (
                "Validate and sanitize file paths. Restrict file access to an "
                "allowed directory and use safe path resolution techniques."
            )
        }
    }

    details = explanations.get(
        vulnerability_type,
        {
            "why": "A potential security vulnerability was detected.",
            "risk": "The vulnerability may be exploitable by an attacker.",
            "recommendation": "Review the code and apply secure coding practices."
        }
    )

    return {
        "type": vulnerability_type,
        "severity": severity,
        "cwe": cwe,
        "line": line,
        "why": details["why"],
        "risk": details["risk"],
        "recommendation": details["recommendation"]
    }