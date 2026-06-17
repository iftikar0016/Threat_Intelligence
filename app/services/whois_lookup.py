import asyncio
import logging
import whois
from app.detector import IndicatorType, domain_from_url

logger = logging.getLogger("whois")


async def query_whois(value: str, kind: IndicatorType) -> dict:
    # Determine domain
    if kind == IndicatorType.DOMAIN:
        domain = value
    elif kind == IndicatorType.URL:
        domain = domain_from_url(value)
        if not domain:
            return {"source": "whois", "enabled": True, "error": "no hostname in URL"}
    elif kind == IndicatorType.IP:
        return {"source": "whois", "enabled": False, "error": "IP WHOIS lookup not supported by standard WHOIS client"}
    elif kind == IndicatorType.HASH:
        return {"source": "whois", "enabled": False, "error": "not applicable for hashes"}
    else:
        return {"source": "whois", "enabled": False, "error": "unsupported type"}

    try:
        # python-whois is blocking, so run it in a separate thread
        record = await asyncio.to_thread(whois.whois, domain)
        if not record or not getattr(record, "domain_name", None):
            return {
                "source": "whois",
                "enabled": True,
                "found": False,
                "error": f"No WHOIS record found for domain: {domain}"
            }

        # Helper to safely serialize fields that might be lists or datetimes
        def safe_str(val):
            if val is None:
                return None
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val)

        return {
            "source": "whois",
            "enabled": True,
            "found": True,
            "domain_name": safe_str(record.get("domain_name")),
            "registrar": safe_str(record.get("registrar")),
            "creation_date": safe_str(record.get("creation_date")),
            "expiration_date": safe_str(record.get("expiration_date")),
            "updated_date": safe_str(record.get("updated_date")),
            "name_servers": safe_str(record.get("name_servers")),
            "emails": safe_str(record.get("emails")),
            "org": safe_str(record.get("org")),
            "country": safe_str(record.get("country")),
        }
    except Exception as e:
        logger.warning("WHOIS failed for %s: %s", domain, e)
        return {"source": "whois", "enabled": True, "error": str(e)}
