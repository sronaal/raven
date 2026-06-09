import asyncio
import logging
import re

logger = logging.getLogger(__name__)


async def _resolve_txt(domain: str) -> list[str]:
    try:
        import dns.resolver
        loop = asyncio.get_running_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "TXT")
        )
        return [" ".join(r.strings.decode() if isinstance(r.strings, bytes) else r.strings for r in answer.strings) for answer in answers]
    except ImportError:
        pass
    except Exception:
        pass
    return []


def _parse_spf(txt_records: list[str]) -> dict | None:
    for record in txt_records:
        if record.startswith("v=spf1"):
            mechanisms = re.findall(r'(?:\s|^)([a-z]+(?::[^\s]+)?)', record)
            return {
                "raw": record,
                "all_mechanism": None,
                "includes": [m.split(":")[1] for m in mechanisms if m.startswith("include:")],
                "ip4": [m.split(":")[1] for m in mechanisms if m.startswith("ip4:")],
                "ip6": [m.split(":")[1] for m in mechanisms if m.startswith("ip6:")],
                "exists": [m.split(":")[1] for m in mechanisms if m.startswith("exists:")],
                "redirect": [m.split(":")[1] for m in mechanisms if m.startswith("redirect=")],
            }
    return None


def _parse_dkim(txt_records: list[str]) -> list[dict]:
    dkim_records = []
    for record in txt_records:
        if record.startswith("v=DKIM1"):
            tags = {}
            for part in record.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            dkim_records.append({
                "raw": record,
                "version": tags.get("v"),
                "public_key_type": tags.get("k"),
                "public_key": tags.get("p"),
                "service_type": tags.get("s"),
                "flags": tags.get("t"),
            })
    return dkim_records


async def _check_dkim_record(domain: str, selector: str = "default") -> dict | None:
    try:
        import dns.resolver
        dkim_domain = f"{selector}._domainkey.{domain}"
        loop = asyncio.get_running_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(dkim_domain, "TXT")
        )
        records = [" ".join(r.strings.decode() if isinstance(r.strings, bytes) else r.strings for r in answer.strings) for answer in answers]
        parsed = _parse_dkim(records)
        if parsed:
            return {"selector": selector, "records": parsed}
    except ImportError:
        pass
    except Exception:
        pass
    return None


def _parse_dmarc(txt_records: list[str]) -> dict | None:
    for record in txt_records:
        if record.startswith("v=DMARC1"):
            tags = {}
            for part in record.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            return {
                "raw": record,
                "version": tags.get("v"),
                "policy": tags.get("p"),
                "subdomain_policy": tags.get("sp"),
                "aggregate_uri": tags.get("rua"),
                "forensic_uri": tags.get("ruf"),
                "percentage": tags.get("pct"),
                "reporting_interval": tags.get("ri"),
                "alignment_spf": tags.get("aspf"),
                "alignment_dkim": tags.get("adkim"),
                "failure_options": tags.get("fo"),
            }
    return None


async def check_email_security(domain: str) -> dict:
    txt_records = await _resolve_txt(domain)

    spf = _parse_spf(txt_records)
    dmarc = _parse_dmarc(txt_records)

    dkim_selectors = ["default", "google", "dkim", "mail", "selector1", "selector2", "s1", "s2"]
    dkim_tasks = [_check_dkim_record(domain, s) for s in dkim_selectors]
    dkim_results = await asyncio.gather(*dkim_tasks)
    dkim = [r for r in dkim_results if r is not None]

    spf_passed = spf is not None
    dkim_passed = len(dkim) > 0
    dmarc_passed = dmarc is not None

    score = 0
    if spf_passed:
        score += 35
    if dkim_passed:
        score += 35
    if dmarc_passed:
        score += 30

    dmarc_policy = None
    dmarc_policy_strength = "none"
    if dmarc:
        dmarc_policy = dmarc.get("policy")
        if dmarc_policy == "reject":
            dmarc_policy_strength = "strong"
        elif dmarc_policy == "quarantine":
            dmarc_policy_strength = "moderate"

    risk = "low"
    if not spf_passed and not dkim_passed:
        risk = "high"
    elif not dmarc_passed:
        risk = "medium"

    return {
        "domain": domain,
        "score": score,
        "risk": risk,
        "spf": {
            "present": spf_passed,
            "record": spf["raw"] if spf else None,
            "includes": spf["includes"] if spf else [],
            "all_mechanism": spf["all_mechanism"] if spf else None,
        } if spf else {"present": False},
        "dkim": {
            "present": dkim_passed,
            "records": dkim,
        },
        "dmarc": {
            "present": dmarc_passed,
            "record": dmarc["raw"] if dmarc else None,
            "policy": dmarc_policy,
            "policy_strength": dmarc_policy_strength,
        } if dmarc else {"present": False},
    }
