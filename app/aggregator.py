import asyncio
import httpx
from datetime import datetime, timezone

from app.detector import IndicatorType
from app.services.virustotal import query_virustotal
from app.services.alienvault import query_alienvault
from app.services.whois_lookup import query_whois


async def aggregate(value: str, kind: IndicatorType) -> dict:
    async with httpx.AsyncClient() as client:
        vt_task = query_virustotal(client, value, kind)
        otx_task = query_alienvault(client, value, kind)
        whois_task = query_whois(value, kind)

        vt, otx, whois = await asyncio.gather(vt_task, otx_task, whois_task)

    # Compute a consolidated risk score (0-100)
    score = _compute_risk(vt, otx)

    return {
        "indicator": value,
        "type": kind.value,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": score,
        "results": {
            "virustotal": vt,
            "alienvault": otx,
            "whois": whois,
        },
    }


def _compute_risk(vt: dict, otx: dict) -> int:
    score = 0
    # Process VirusTotal contributions (up to 60 points)
    if isinstance(vt, dict) and vt.get("stats") and isinstance(vt["stats"], dict):
        stats = vt["stats"]
        numeric_vals = [v for v in stats.values() if isinstance(v, (int, float))]
        total = sum(numeric_vals) or 1
        mal = 0
        for key in ["malicious", "suspicious"]:
            val = stats.get(key, 0)
            if isinstance(val, (int, float)):
                mal += val
        score += int((mal / total) * 60)

    # Process AlienVault contributions (up to 40 points, 2 points per pulse count)
    if isinstance(otx, dict) and otx.get("pulse_count"):
        count = otx["pulse_count"]
        if isinstance(count, (int, float)):
            score += min(int(count * 2), 40)

    return min(score, 100)
