import asyncio
import logging
import socket

logger = logging.getLogger(__name__)

RECORD_TYPES = {
    "A": socket.AF_INET,
    "AAAA": socket.AF_INET6,
    "CNAME": None,
    "MX": None,
    "NS": None,
    "TXT": None,
    "SOA": None,
}


async def _resolve_a(hostname: str) -> list[str]:
    return await _resolve_with_socket(hostname, socket.AF_INET)


async def _resolve_aaaa(hostname: str) -> list[str]:
    return await _resolve_with_socket(hostname, socket.AF_INET6)


async def _resolve_with_socket(hostname: str, family: int) -> list[str]:
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None, socket.getaddrinfo, hostname, None, family, socket.SOCK_STREAM
        )
        return list(set(info[4][0] for info in infos if info[4][0]))
    except socket.gaierror:
        return []
    except Exception as e:
        logger.debug("DNS resolve error for %s: %s", hostname, e)
        return []


async def _resolve_ns(hostname: str) -> list[str]:
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _query_ns, hostname)
        return result
    except Exception as e:
        logger.debug("NS lookup error for %s: %s", hostname, e)
        return []


def _query_ns(hostname: str) -> list[str]:
    try:
        return socket.gethostbyname_ex(hostname)[0]
    except Exception:
        return []


async def _resolve_mx(domain: str) -> list[dict]:
    results = []
    try:
        loop = asyncio.get_running_loop()
        records = await loop.run_in_executor(None, _query_mx, domain)
        results.extend(records)
    except Exception as e:
        logger.debug("MX lookup error for %s: %s", domain, e)
    return results


def _query_mx(domain: str) -> list[dict]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        return [{"exchange": str(r.exchange), "preference": r.preference} for r in answers]
    except ImportError:
        pass
    except Exception:
        pass
    return []


async def _resolve_txt(domain: str) -> list[str]:
    records = []
    try:
        loop = asyncio.get_running_loop()
        spf = await loop.run_in_executor(None, _query_txt, domain)
        records.extend(spf)
    except Exception as e:
        logger.debug("TXT lookup error for %s: %s", domain, e)
    return records


def _query_txt(domain: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT")
        return [" ".join(r.strings.decode() if isinstance(r.strings, bytes) else r.strings for r in answer.strings) for answer in answers]
    except ImportError:
        pass
    except Exception:
        pass
    return []


async def _resolve_cname(hostname: str) -> list[str]:
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _query_cname, hostname)
        return result
    except Exception as e:
        logger.debug("CNAME lookup error for %s: %s", hostname, e)
        return []


def _query_cname(hostname: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "CNAME")
        return [str(r.target) for r in answers]
    except ImportError:
        pass
    except Exception:
        pass
    return []


async def _resolve_soa(domain: str) -> dict | None:
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _query_soa, domain)
        return result
    except Exception as e:
        logger.debug("SOA lookup error for %s: %s", domain, e)
        return None


def _query_soa(domain: str) -> dict | None:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "SOA")
        soa = answers[0]
        return {
            "mname": str(soa.mname),
            "rname": str(soa.rname),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum": soa.minimum,
        }
    except ImportError:
        pass
    except Exception:
        pass
    return None


async def enumerate_dns(domain: str) -> dict:
    results = {}

    a_records, aaaa_records, ns_records, mx_records, txt_records, cname_records, soa_record = await asyncio.gather(
        _resolve_a(domain),
        _resolve_aaaa(domain),
        _resolve_ns(domain),
        _resolve_mx(domain),
        _resolve_txt(domain),
        _resolve_cname(domain),
        _resolve_soa(domain),
    )

    if a_records:
        results["A"] = a_records
    if aaaa_records:
        results["AAAA"] = aaaa_records
    if ns_records:
        results["NS"] = ns_records
    if mx_records:
        results["MX"] = mx_records
    if txt_records:
        results["TXT"] = txt_records
    if cname_records:
        results["CNAME"] = cname_records
    if soa_record:
        results["SOA"] = soa_record

    return {
        "domain": domain,
        "records": results,
        "record_count": len(results),
        "has_a": "A" in results,
        "has_aaaa": "AAAA" in results,
        "has_mx": "MX" in results,
        "has_ns": "NS" in results,
        "has_txt": "TXT" in results,
        "has_cname": "CNAME" in results,
        "has_soa": "SOA" in results,
    }
