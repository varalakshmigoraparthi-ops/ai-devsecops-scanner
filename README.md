\# AI DevSecOps Scanner



AI-powered DevSecOps scanner that analyzes Python source code for security vulnerabilities, classifies severity and CWE, and provides AI-based risk explanations and remediation recommendations.



\## 🚀 Features



\- Upload and scan Python `.py` files

\- Static code security analysis

\- Detects common security vulnerabilities

\- Severity classification

\- CWE identification

\- AI-style security explanations

\- Risk analysis

\- Remediation recommendations

\- Scan history stored in SQLite database

\- FastAPI backend

\- Simple web-based frontend



\## 🔐 Vulnerabilities Detected



The scanner currently detects:



| Vulnerability | Severity | CWE |

|---|---|---|

| SQL Injection | High | CWE-89 |

| Command Injection | Critical | CWE-78 |

| Hardcoded Secret | Critical | CWE-798 |

| Cross-Site Scripting (XSS) | High | CWE-79 |

| Path Traversal | High | CWE-22 |



\## 🛠️ Tech Stack



\- Python 3

\- FastAPI

\- Uvicorn

\- SQLAlchemy

\- SQLite

\- Python AST

\- HTML

\- CSS

\- JavaScript



\## 📁 Project Structure



```text

ai-devsecops-scanner/

│

├── ai/

│   └── analyzer.py

│

├── backend/

│   └── app/

│       ├── api/

│       │   ├── frontend/

│       │   │   ├── index.html

│       │   │   ├── script.js

│       │   │   └── style.css

│       │   ├── scan.py

│       │   └── ...

│       ├── database/

│       ├── models/

│       └── main.py

│

├── scanner/

│   ├── engine.py

│   └── rules/

│       ├── sql\_injection.py

│       ├── command\_injection.py

│       ├── secrets.py

│       ├── xss.py

│       └── path\_traversal.py

│

├── tests/

│   └── vulnerable\_all.py

│

├── .gitignore

└── README.md

