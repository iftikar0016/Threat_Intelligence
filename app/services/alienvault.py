import base64
import httpx
from app.config import settings
from app.detector import IndicatorType

OTX_BASE = "https://otx.alienvault.com/api/v1"


def _headers():
    h = {"accept": "application/json"}
    if settings.otx_api_key:
        h["X-OTX-API-KEY"] = settings.otx_api_key
    return h


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().strip("=")


async def query_alienvault(client: httpx.AsyncClient, value: str, kind: IndicatorType) -> dict:
    try:
        if kind == IndicatorType.IP:
            url = f"{OTX_BASE}/indicators/IPv4/{value}/general"
        elif kind == IndicatorType.DOMAIN:
            url = f"{OTX_BASE}/indicators/domain/{value}/general"
        elif kind == IndicatorType.URL:
            url = f"{OTX_BASE}/indicators/url/{_b64url(value)}/general"
        elif kind == IndicatorType.HASH:
            url = f"{OTX_BASE}/indicators/file/{value.lower()}/general"
        else:
            return {"source": "alienvault", "enabled": False, "error": "unsupported type"}

        r = await client.get(url, headers=_headers(), timeout=15.0)
        if r.status_code == 404:
            return {"source": "alienvault", "enabled": True, "found": False}
        r.raise_for_status()
        data = r.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
        if not isinstance(pulses, list):
            pulses = []

        formatted_pulses = []
        for p in pulses[:20]:
            if isinstance(p, dict):
                formatted_pulses.append({
                    "name": p.get("name"),
                    "description": (p.get("description") or "")[:300],
                    "tags": p.get("tags", []),
                    "created": p.get("created"),
                    "adversary": p.get("adversary"),
                    "id": p.get("id"),
                })

        return {
            "source": "alienvault",
            "enabled": True,
            "found": True,
            "pulse_count": pulse_info.get("count", 0) if isinstance(pulse_info, dict) else 0,
            "pulses": formatted_pulses,
            "reputation": data.get("reputation"),
        }
    except Exception as e:
        return {"source": "alienvault", "enabled": True, "error": str(e)}
