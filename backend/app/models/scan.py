from sqlalchemy import Column, Integer, String, Text

from backend.app.database.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    cwe = Column(String(20), nullable=False)
    line = Column(Integer, nullable=False)
    why = Column(Text, nullable=False)
    risk = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)