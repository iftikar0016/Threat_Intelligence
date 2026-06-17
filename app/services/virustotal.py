import httpx
from app.config import settings
from app.detector import url_id_for_vt, IndicatorType

VT_BASE = "https://www.virustotal.com/api/v3"


def _headers():
    api_key = settings.vt_api_key.strip() if settings.vt_api_key else ""
    return {"x-apikey": api_key, "accept": "application/json"}


async def query_virustotal(client: httpx.AsyncClient, value: str, kind: IndicatorType) -> dict:
    api_key = settings.vt_api_key.strip() if settings.vt_api_key else ""
    if not api_key or api_key.startswith("your_"):
        return {"source": "virustotal", "enabled": False, "error": "no API key configured"}

    try:
        if kind == IndicatorType.URL:
            url = f"{VT_BASE}/urls/{url_id_for_vt(value)}"
        elif kind == IndicatorType.HASH:
            url = f"{VT_BASE}/files/{value.lower()}"
        elif kind == IndicatorType.DOMAIN:
            url = f"{VT_BASE}/domains/{value}"
        elif kind == IndicatorType.IP:
            url = f"{VT_BASE}/ip_addresses/{value}"
        else:
            return {"source": "virustotal", "enabled": False, "error": "unsupported type"}

        r = await client.get(url, headers=_headers(), timeout=15.0)
        if r.status_code == 404:
            return {"source": "virustotal", "enabled": True, "found": False}
        r.raise_for_status()
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})

        # Extract malicious verdicts safely
        results = attrs.get("last_analysis_results", {})
        malicious_vendors = []
        if isinstance(results, dict):
            for k, v in results.items():
                if v and isinstance(v, dict) and v.get("category") == "malicious":
                    malicious_vendors.append({"vendor": k, "result": v.get("result")})

        return {
            "source": "virustotal",
            "enabled": True,
            "found": True,
            "permalink": f"https://www.virustotal.com/gui/{'url' if kind == IndicatorType.URL else 'search'}/{value}",
            "stats": last_analysis,
            "malicious_vendors": malicious_vendors[:25],
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "tags": attrs.get("tags", []),
        }
    except Exception as e:
        return {"source": "virustotal", "enabled": True, "error": str(e)}
