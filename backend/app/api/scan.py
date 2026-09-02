from fastapi import APIRouter, UploadFile, File, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanner.engine import scan_code
from ai.analyzer import analyze_finding

from backend.app.database.database import get_db
from backend.app.models.scan import ScanResult


router = APIRouter()


class ScanRequest(BaseModel):
    code: str


@router.post("/scan")
def scan(
    request: ScanRequest,
    db: Session = Depends(get_db)
):
    findings = scan_code(request.code)

    analyzed_findings = []

    for finding in findings:
        analysis = analyze_finding(finding)
        analyzed_findings.append(analysis)

    return {
        "total_findings": len(analyzed_findings),
        "findings": analyzed_findings
    }


@router.post("/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    if not file.filename.endswith(".py"):
        return {
            "error": "Only Python (.py) files are supported."
        }

    content = await file.read()
    code = content.decode("utf-8")

    findings = scan_code(code)

    analyzed_findings = []

    # Remove previous results for the same file
    db.query(ScanResult).filter(
        ScanResult.filename == file.filename
    ).delete(synchronize_session=False)

    for finding in findings:
        analysis = analyze_finding(finding)

        analyzed_findings.append(analysis)

        scan_result = ScanResult(
            filename=file.filename,
            vulnerability_type=analysis["type"],
            severity=analysis["severity"],
            cwe=analysis["cwe"],
            line=analysis["line"],
            why=analysis["why"],
            risk=analysis["risk"],
            recommendation=analysis["recommendation"]
        )

        db.add(scan_result)

    db.commit()

    return {
        "filename": file.filename,
        "total_findings": len(analyzed_findings),
        "findings": analyzed_findings
    }


@router.get("/scan-history")
def scan_history(db: Session = Depends(get_db)):

    results = (
        db.query(ScanResult)
        .order_by(ScanResult.id.desc())
        .all()
    )

    return {
        "total_scans": len(results),
        "history": [
            {
                "id": result.id,
                "filename": result.filename,
                "vulnerability_type": result.vulnerability_type,
                "severity": result.severity,
                "cwe": result.cwe,
                "line": result.line,
                "why": result.why,
                "risk": result.risk,
                "recommendation": result.recommendation
            }
            for result in results
        ]
    }


    
@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    results = db.query(ScanResult).all()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    vulnerability_counts = {}

    for result in results:
        severity = result.severity.upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

        vulnerability_type = result.vulnerability_type

        if vulnerability_type not in vulnerability_counts:
            vulnerability_counts[vulnerability_type] = 0

        vulnerability_counts[vulnerability_type] += 1

    return {
        "total_vulnerabilities": len(results),
        "severity_counts": severity_counts,
        "vulnerability_counts": vulnerability_counts
    }