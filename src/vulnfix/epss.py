"""EPSS-aware vulnerability prioritisation.

CVSS tells you how bad a vuln *could* be. EPSS tells you how likely it
is to actually be exploited in the wild. This module combines them,
adds asset-exposure and patch-availability signals, and produces a
ranked list with a plain-English fix-first rationale.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Vuln:
    cve: str
    cvss: float                   # 0..10, base score
    epss: float                   # 0..1, probability of exploit in next 30 days
    exposed_internet: bool
    in_kev: bool = False          # CISA Known Exploited Vulnerabilities
    patch_available: bool = True
    asset_criticality: float = 0.5  # 0..1; caller-defined (crown-jewel = 1.0)
    affected_assets: int = 1


@dataclass(frozen=True)
class RankedVuln:
    vuln: Vuln
    risk: float
    tier: str                     # "fix-now" | "fix-soon" | "monitor" | "accept"
    rationale: str


def rank(vuln: Vuln) -> RankedVuln:
    # Normalise CVSS to 0..1.
    c = max(0.0, min(1.0, vuln.cvss / 10))
    # Weighted risk; EPSS gets a sizeable voice.
    risk = 0.35 * c + 0.35 * vuln.epss + 0.2 * vuln.asset_criticality
    if vuln.exposed_internet:
        risk += 0.1
    if vuln.in_kev:
        risk = min(1.0, risk + 0.15)
    if not vuln.patch_available:
        risk *= 0.9  # Slightly damp — you can't fix it yet.

    risk = min(1.0, risk)

    if vuln.in_kev or (risk >= 0.75 and vuln.patch_available):
        tier = "fix-now"
    elif risk >= 0.55:
        tier = "fix-soon"
    elif risk >= 0.3:
        tier = "monitor"
    else:
        tier = "accept"

    return RankedVuln(vuln=vuln, risk=round(risk, 3), tier=tier, rationale=_explain(vuln, risk, tier))


def rank_many(vulns: Iterable[Vuln]) -> list[RankedVuln]:
    return sorted((rank(v) for v in vulns), key=lambda r: r.risk, reverse=True)


def _explain(v: Vuln, risk: float, tier: str) -> str:
    bits: list[str] = []
    bits.append(f"CVSS {v.cvss:.1f}")
    bits.append(f"EPSS {v.epss:.2%}")
    if v.in_kev:
        bits.append("in CISA KEV")
    if v.exposed_internet:
        bits.append("internet-exposed")
    if not v.patch_available:
        bits.append("no patch yet")
    bits.append(f"{v.affected_assets} asset" + ("s" if v.affected_assets != 1 else ""))
    verb = {
        "fix-now": "Fix now",
        "fix-soon": "Fix this sprint",
        "monitor": "Monitor",
        "accept": "Accept risk",
    }[tier]
    return f"{verb}: {', '.join(bits)}."


def slo_window_hours(tier: str) -> int:
    """Suggested time-to-patch SLO per tier."""
    return {
        "fix-now": 24,
        "fix-soon": 24 * 14,
        "monitor": 24 * 60,
        "accept": 0,
    }.get(tier, 24 * 30)
