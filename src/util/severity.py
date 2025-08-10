from typing import List
import re
from cvss import CVSS3, CVSS2
from state.state import Severity

RATING = [(9.0, Severity.CRITICAL),
          (7.0, Severity.HIGH),
          (4.0, Severity.MEDIUM),
          (0.1, Severity.LOW),
          (0.0, Severity.NONE)]

def _bucket(score: float) -> Severity:
    for threshold, label in RATING:
        if score >= threshold:
            return label
    return Severity.UNKNOWN

VECTOR_RE = re.compile(r"CVSS:")

def severity_of(osv_obj: dict) -> Severity:
    """
    Collapse OSV `severity[]` entries into CRITICAL/HIGH/MEDIUM/LOW.
    """
    if "severity" not in osv_obj:
        return Severity.UNKNOWN

    severities: List[Severity] = []
    for item in osv_obj["severity"]:
        t, s = item.get("type"), item.get("score", "")
        if t.startswith("CVSS"):                
            if VECTOR_RE.match(s):
                try:
                    base = (CVSS3(s).scores()[0] if t != "CVSS_V2" else CVSS2(s).scores()[0])
                except Exception:
                    continue
            else:                                
                try:
                    base = float(s)
                except ValueError:
                    continue
            severities.append(_bucket(base))
        else:                                    
            if s in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}:
                severities.append(s)

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for level in order:
        if level in severities:
            return level
    return Severity.UNKNOWN