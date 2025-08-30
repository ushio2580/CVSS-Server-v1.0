"""
Utility functions to calculate CVSS v3.1 base scores and severities.

This module provides a function to compute the base score from a set
of metric values.  It also constructs the vector string according to
the specification.  Only base metrics are supported in this MVP.

References:
  https://www.first.org/cvss/specification-document
"""

import math
from typing import Dict, Tuple


def round_up(value: float) -> float:
    """Round up a CVSS score to one decimal place."""
    return math.ceil(value * 10) / 10.0


def severity_from_score(score: float) -> str:
    """Return the qualitative severity for a base score."""
    if score == 0.0:
        return "None"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    return "Critical"


def build_vector(metrics: Dict[str, str]) -> str:
    """Build a vector string from metric values."""
    defaults = {
        "AV": "L",
        "AC": "H",
        "PR": "N",
        "UI": "N",
        "S": "U",
        "C": "N",
        "I": "N",
        "A": "N",
    }
    m = {**defaults, **{k.upper(): v.upper() for k, v in metrics.items()}}
    parts = [
        "CVSS:3.1",
        f"AV:{m['AV']}",
        f"AC:{m['AC']}",
        f"PR:{m['PR']}",
        f"UI:{m['UI']}",
        f"S:{m['S']}",
        f"C:{m['C']}",
        f"I:{m['I']}",
        f"A:{m['A']}",
    ]
    return "/".join(parts)


def calculate_base_score(metrics: Dict[str, str]) -> Tuple[float, str, str]:
    """Calculate the CVSS v3.1 base score.

    Args:
        metrics: Mapping of metric abbreviations to values (e.g.
            {"AV": "N", "AC": "L", ...}).  Missing keys use defaults.

    Returns:
        Tuple containing (base_score, severity_string, vector_string).
    """
    m = {k.upper(): v.upper() for k, v in metrics.items() if v}
    m.setdefault("AV", "L")
    m.setdefault("AC", "H")
    m.setdefault("PR", "N")
    m.setdefault("UI", "N")
    m.setdefault("S", "U")
    m.setdefault("C", "N")
    m.setdefault("I", "N")
    m.setdefault("A", "N")

    av_vals = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_vals = {"L": 0.77, "H": 0.44}
    pr_vals = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    ui_vals = {"N": 0.85, "R": 0.62}
    impact_vals = {"N": 0.0, "L": 0.22, "H": 0.56}

    av = av_vals.get(m["AV"], 0.55)
    ac = ac_vals.get(m["AC"], 0.44)
    scope = m["S"] if m["S"] in ("U", "C") else "U"
    pr = pr_vals[scope].get(m["PR"], 0.85)
    ui = ui_vals.get(m["UI"], 0.85)
    c = impact_vals.get(m["C"], 0.0)
    i = impact_vals.get(m["I"], 0.0)
    a = impact_vals.get(m["A"], 0.0)

    exploitability = 8.22 * av * ac * pr * ui
    impact = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "C":
        impact_subscore = 7.52 * (impact - 0.029) - 3.25 * ((impact - 0.02) ** 15)
    else:
        impact_subscore = 6.42 * impact
    if impact <= 0:
        base_score = 0.0
    else:
        raw = impact_subscore + exploitability
        if scope == "C":
            raw *= 1.08
        base_score = round_up(min(raw, 10))

    severity = severity_from_score(base_score)
    vector = build_vector(m)
    return base_score, severity, vector