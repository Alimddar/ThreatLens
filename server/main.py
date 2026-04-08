"""
ThreatLens API — Phase 3 Backend
FastAPI server that:
  1. Receives an extracted email payload from the Chrome extension.
  2. Scans every embedded URL in parallel against VirusTotal.
  3. Runs full SOC intelligence: WHOIS, crt.sh, DNS (SPF/DMARC/MX), GeoIP,
     MalwareBazaar, AbuseIPDB, URLScan.io, PhishTank, URLhaus, ThreatFox.
  4. Computes MD5 / SHA-1 / SHA-256 hashes of the email body.
  5. Passes all findings to Claude (claude-sonnet-4-6) for plain-English analysis.
  6. Returns a structured DeepAnalysisResponse to the extension popup.

Run:
    source venv/bin/activate
    uvicorn main:app --reload --port 8000

Environment variables required in .env:
    VIRUS_TOTAL_API_KEY=<your_key>
    ANTHROPIC_API_KEY=<your_key>
    ABUSEIPDB_API_KEY=<your_key>      # optional
    URLSCAN_API_KEY=<your_key>        # optional
    # URLhaus and ThreatFox require NO API key
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import socket
from typing import Any, Optional

import anthropic
import httpx
import whois
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── .env loader ───────────────────────────────────────────────────────────────

def _read_env_file(path: str = ".env") -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                result[key.strip()] = val.strip()
    except FileNotFoundError:
        pass
    return result


def get_key(name: str) -> str:
    if val := os.environ.get(name, ""):
        return val
    return _read_env_file().get(name, "")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="ThreatLens API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── Request Models ─────────────────────────────────────────────────────────────

class Sender(BaseModel):
    name:  str
    email: str

class EmailPayload(BaseModel):
    sender:    Sender
    subject:   str
    body:      str
    links:     list[str]
    linkCount: int
    wordCount: int

# ── Response Models ────────────────────────────────────────────────────────────

class LinkScan(BaseModel):
    url:           str
    malicious:     int  = 0
    suspicious:    int  = 0
    harmless:      int  = 0
    undetected:    int  = 0
    total:         int  = 0
    is_malicious:  bool = False
    is_suspicious: bool = False
    status:        str  = "ok"

class WhoisInfo(BaseModel):
    domain:       str
    registrar:    Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date:  Optional[str] = None
    country:      Optional[str] = None
    age_days:     Optional[int] = None
    is_new:       bool = False   # < 30 days old
    error:        Optional[str] = None

class CertInfo(BaseModel):
    domain:      str
    cert_count:  int  = 0
    oldest_cert: Optional[str] = None
    newest_cert: Optional[str] = None
    issuers:     list[str] = []
    error:       Optional[str] = None

class HashInfo(BaseModel):
    md5:    str
    sha1:   str
    sha256: str

class MalwareBazaarResult(BaseModel):
    queried:    bool  = False
    found:      bool  = False
    file_type:  Optional[str] = None
    tags:       list[str] = []
    threat_name: Optional[str] = None
    error:      Optional[str] = None

class GeoRepInfo(BaseModel):
    ip:           Optional[str] = None
    country:      Optional[str] = None
    city:         Optional[str] = None
    org:          Optional[str] = None
    is_tor:       bool = False
    is_proxy:     bool = False
    abuse_score:  Optional[int] = None   # AbuseIPDB 0-100
    abuse_reports: Optional[int] = None
    error:        Optional[str] = None

class DnsInfo(BaseModel):
    domain:     str
    auth_domain: Optional[str] = None
    has_spf:    bool = False
    has_dmarc:  bool = False
    mx_records: list[str] = []
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    error:      Optional[str] = None

class UrlScanResult(BaseModel):
    url:          str
    scan_id:      Optional[str] = None
    result_url:   Optional[str] = None
    screenshot:   Optional[str] = None
    malicious:    bool = False
    status:       str  = "submitted"
    error:        Optional[str] = None

class PhishTankResult(BaseModel):
    url:          str
    is_phishing:  bool = False
    verified:     bool = False
    phish_id:     Optional[str] = None
    error:        Optional[str] = None

class UrlhausResult(BaseModel):
    url:          str
    status:       str  = "not_found"   # "online" | "offline" | "not_found" | "error"
    threat:       Optional[str] = None  # e.g. "malware_download"
    tags:         list[str] = []
    date_added:   Optional[str] = None
    is_malicious: bool = False
    error:        Optional[str] = None

class ThreatFoxResult(BaseModel):
    indicator:    str
    ioc_type:     str   # "domain" | "ip:port" | "url" | "md5_hash" | "sha256_hash"
    hit:          bool  = False
    malware:      Optional[str] = None
    confidence:   Optional[int] = None   # 0-100
    first_seen:   Optional[str] = None
    tags:         list[str] = []
    error:        Optional[str] = None

class AiAnalysis(BaseModel):
    threat_level:       str
    confidence:         float
    summary:            str
    key_findings:       list[str]
    recommended_action: str

class DeepAnalysisResponse(BaseModel):
    # Core AI assessment
    ai:          AiAnalysis
    # Hashes
    hashes:      HashInfo
    # Per-link data
    link_scans:  list[LinkScan]
    # Domain intelligence (keyed by domain)
    whois_info:  list[WhoisInfo]         = []
    cert_info:   list[CertInfo]          = []
    dns_info:    list[DnsInfo]           = []
    # URL feeds
    urlscan:     list[UrlScanResult]     = []
    phishtank:   list[PhishTankResult]   = []
    # IP / geo / rep
    geo_rep:     list[GeoRepInfo]        = []
    # Hash lookups
    malware_bazaar: list[MalwareBazaarResult] = []
    # Threat intel (abuse.ch — no key required)
    urlhaus:     list[UrlhausResult]     = []
    threatfox:   list[ThreatFoxResult]   = []

# Legacy response model for /analyze backward compat
class AnalysisResponse(BaseModel):
    threat_level:       str
    confidence:         float
    summary:            str
    key_findings:       list[str]
    recommended_action: str
    link_scans:         list[LinkScan]

# ── Helpers ────────────────────────────────────────────────────────────────────

def normalize_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain or None


_MULTIPART_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.tr",
}
_TRUSTED_ROOT_DOMAINS = {
    "google.com",
    "gmail.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "youtube.com",
    "spotify.com",
    "scdn.co",
    "microsoft.com",
    "office.com",
    "live.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
}


def get_registered_domain(domain: Optional[str]) -> Optional[str]:
    domain = normalize_domain(domain)
    if not domain:
        return None

    labels = domain.split(".")
    if len(labels) <= 2:
        return domain

    suffix = ".".join(labels[-2:])
    if suffix in _MULTIPART_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_trusted_domain(domain: Optional[str]) -> bool:
    root = get_registered_domain(domain)
    return bool(root and root in _TRUSTED_ROOT_DOMAINS)


def extract_domain(url: str) -> Optional[str]:
    try:
        parsed = httpx.URL(url)
        return normalize_domain(parsed.host)
    except Exception:
        return None


def compute_hashes(text: str) -> HashInfo:
    data = text.encode("utf-8")
    return HashInfo(
        md5    = hashlib.md5(data).hexdigest(),
        sha1   = hashlib.sha1(data).hexdigest(),
        sha256 = hashlib.sha256(data).hexdigest(),
    )

# ── VirusTotal ─────────────────────────────────────────────────────────────────

def url_to_vt_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def classify_vt_scan(url: str, malicious: int, suspicious: int, harmless: int) -> tuple[bool, bool]:
    domain = extract_domain(url)
    trusted = is_trusted_domain(domain)

    if malicious >= 2:
        return True, True

    if malicious == 1:
        if trusted and suspicious == 0 and harmless >= 5:
            return False, False
        return False, True

    if suspicious >= 2:
        return False, True

    return False, False


async def vt_scan_single(client: httpx.AsyncClient, url: str) -> LinkScan:
    headers = {"x-apikey": get_key("VIRUS_TOTAL_API_KEY"), "accept": "application/json"}
    vt_id   = url_to_vt_id(url)
    try:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{vt_id}",
            headers=headers, timeout=8.0,
        )
        if resp.status_code == 200:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            mal  = stats.get("malicious",  0)
            susp = stats.get("suspicious", 0)
            harm = stats.get("harmless",   0)
            unde = stats.get("undetected", 0)
            is_malicious, is_suspicious = classify_vt_scan(url, mal, susp, harm)
            return LinkScan(
                url=url, malicious=mal, suspicious=susp,
                harmless=harm, undetected=unde,
                total=mal+susp+harm+unde,
                is_malicious=is_malicious, is_suspicious=is_suspicious, status="ok",
            )
        if resp.status_code == 404:
            await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                content=f"url={httpx.URL(url)}", timeout=6.0,
            )
            return LinkScan(url=url, status="first_scan")
        return LinkScan(url=url, status=f"http_{resp.status_code}")
    except httpx.TimeoutException:
        return LinkScan(url=url, status="timeout")
    except Exception as exc:
        return LinkScan(url=url, status=f"error: {str(exc)[:60]}")


async def vt_scan_all(urls: list[str]) -> list[LinkScan]:
    if not urls:
        return []
    async with httpx.AsyncClient() as client:
        return await asyncio.gather(*[vt_scan_single(client, u) for u in urls[:10]])

# ── WHOIS ──────────────────────────────────────────────────────────────────────

async def get_whois(domain: str) -> WhoisInfo:
    try:
        def _whois():
            return whois.whois(domain)
        data = await asyncio.to_thread(_whois)
        creation = data.creation_date
        expiry   = data.expiration_date
        # whois can return list or single value
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiry, list):
            expiry = expiry[0]

        age_days = None
        is_new   = False
        if creation:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if hasattr(creation, "tzinfo") and creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (now - creation).days
            is_new   = age_days < 30

        country = data.country
        if isinstance(country, list):
            country = country[0] if country else None

        registrar = data.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        return WhoisInfo(
            domain        = domain,
            registrar     = str(registrar)[:100] if registrar else None,
            creation_date = str(creation)[:30]   if creation  else None,
            expiry_date   = str(expiry)[:30]      if expiry    else None,
            country       = str(country)[:10]     if country   else None,
            age_days      = age_days,
            is_new        = is_new,
        )
    except Exception as exc:
        return WhoisInfo(domain=domain, error=str(exc)[:120])

# ── crt.sh ─────────────────────────────────────────────────────────────────────

async def get_crtsh(client: httpx.AsyncClient, domain: str) -> CertInfo:
    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=10.0,
            headers={"User-Agent": "ThreatLens/3.0"},
        )
        if resp.status_code != 200:
            return CertInfo(domain=domain, error=f"HTTP {resp.status_code}")

        entries = resp.json()
        if not isinstance(entries, list):
            return CertInfo(domain=domain, cert_count=0)

        issuers  = list({e.get("issuer_name", "")[:60] for e in entries if e.get("issuer_name")})[:5]
        dates    = [e.get("not_before", "") for e in entries if e.get("not_before")]
        dates_exp= [e.get("not_after", "")  for e in entries if e.get("not_after")]

        return CertInfo(
            domain      = domain,
            cert_count  = len(entries),
            oldest_cert = min(dates)[:10]     if dates     else None,
            newest_cert = max(dates_exp)[:10] if dates_exp else None,
            issuers     = issuers,
        )
    except Exception as exc:
        return CertInfo(domain=domain, error=str(exc)[:120])

# ── DNS (Google DoH) ───────────────────────────────────────────────────────────

async def get_dns_info(client: httpx.AsyncClient, domain: str) -> DnsInfo:
    async def doh_query(name: str, rtype: str) -> list[str]:
        try:
            r = await client.get(
                "https://dns.google/resolve",
                params={"name": name, "type": rtype},
                timeout=6.0,
            )
            if r.status_code != 200:
                return []
            data = r.json()
            return [a["data"] for a in data.get("Answer", []) if "data" in a]
        except Exception:
            return []

    try:
        async def query_dns(target_domain: str) -> tuple[Optional[str], Optional[str], list[str]]:
            spf_records   = await doh_query(target_domain, "TXT")
            dmarc_records = await doh_query(f"_dmarc.{target_domain}", "TXT")
            mx_records    = await doh_query(target_domain, "MX")
            spf_txt   = next((r for r in spf_records   if "v=spf1"   in r), None)
            dmarc_txt = next((r for r in dmarc_records if "v=DMARC1" in r), None)
            mx_hosts  = [r.split(" ", 1)[-1].rstrip(".") for r in mx_records][:5]
            return spf_txt, dmarc_txt, mx_hosts

        auth_domain = domain
        spf_txt, dmarc_txt, mx_hosts = await query_dns(domain)

        base_domain = get_registered_domain(domain)
        if base_domain and base_domain != domain and (spf_txt is None or dmarc_txt is None):
            base_spf, base_dmarc, base_mx = await query_dns(base_domain)
            if spf_txt is None and base_spf is not None:
                spf_txt = base_spf
                auth_domain = base_domain
            if dmarc_txt is None and base_dmarc is not None:
                dmarc_txt = base_dmarc
                auth_domain = base_domain
            if not mx_hosts and base_mx:
                mx_hosts = base_mx

        return DnsInfo(
            domain       = domain,
            auth_domain  = auth_domain,
            has_spf      = spf_txt is not None,
            has_dmarc    = dmarc_txt is not None,
            mx_records   = mx_hosts,
            spf_record   = spf_txt[:120]   if spf_txt   else None,
            dmarc_record = dmarc_txt[:120] if dmarc_txt else None,
        )
    except Exception as exc:
        return DnsInfo(domain=domain, error=str(exc)[:120])

# ── GeoIP + AbuseIPDB ──────────────────────────────────────────────────────────

async def get_geo_rep(client: httpx.AsyncClient, domain: str) -> GeoRepInfo:
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception:
        return GeoRepInfo(error=f"DNS resolution failed for {domain}")

    try:
        geo_resp = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,org,proxy,hosting"},
            timeout=6.0,
        )
        geo = geo_resp.json() if geo_resp.status_code == 200 else {}
    except Exception:
        geo = {}

    info = GeoRepInfo(
        ip       = ip,
        country  = geo.get("country"),
        city     = geo.get("city"),
        org      = geo.get("org"),
        is_proxy = geo.get("proxy", False) or geo.get("hosting", False),
    )

    abuse_key = get_key("ABUSEIPDB_API_KEY")
    if abuse_key:
        try:
            abuse_resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": abuse_key, "Accept": "application/json"},
                timeout=6.0,
            )
            if abuse_resp.status_code == 200:
                d = abuse_resp.json().get("data", {})
                info.abuse_score   = d.get("abuseConfidenceScore")
                info.abuse_reports = d.get("totalReports")
        except Exception:
            pass

    return info

# ── MalwareBazaar ──────────────────────────────────────────────────────────────

async def check_malware_bazaar(client: httpx.AsyncClient, sha256: str) -> MalwareBazaarResult:
    try:
        resp = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return MalwareBazaarResult(queried=True, error=f"HTTP {resp.status_code}")

        data = resp.json()
        if data.get("query_status") == "hash_not_found":
            return MalwareBazaarResult(queried=True, found=False)

        if data.get("query_status") == "ok" and data.get("data"):
            entry = data["data"][0]
            return MalwareBazaarResult(
                queried     = True,
                found       = True,
                file_type   = entry.get("file_type"),
                tags        = entry.get("tags") or [],
                threat_name = entry.get("signature"),
            )
        return MalwareBazaarResult(queried=True, found=False)
    except Exception as exc:
        return MalwareBazaarResult(queried=True, error=str(exc)[:120])

# ── URLScan.io ─────────────────────────────────────────────────────────────────

async def urlscan_submit(client: httpx.AsyncClient, url: str) -> UrlScanResult:
    key = get_key("URLSCAN_API_KEY")
    if not key:
        return UrlScanResult(url=url, status="no_key")
    try:
        resp = await client.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": key, "Content-Type": "application/json"},
            content=json.dumps({"url": url, "visibility": "unlisted"}),
            timeout=8.0,
        )
        if resp.status_code in (200, 201):
            d = resp.json()
            return UrlScanResult(
                url        = url,
                scan_id    = d.get("uuid"),
                result_url = d.get("result"),
                status     = "submitted",
            )
        return UrlScanResult(url=url, status=f"http_{resp.status_code}")
    except Exception as exc:
        return UrlScanResult(url=url, error=str(exc)[:120], status="error")

# ── PhishTank ──────────────────────────────────────────────────────────────────

async def check_phishtank(client: httpx.AsyncClient, url: str) -> PhishTankResult:
    try:
        resp = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url":    base64.b64encode(url.encode()).decode(),
                "format": "json",
                "app_key": "",
            },
            headers={"User-Agent": "ThreatLens/3.0 phishtank-python/1.0"},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return PhishTankResult(url=url, error=f"HTTP {resp.status_code}")

        data = resp.json()
        result = data.get("results", {})
        return PhishTankResult(
            url         = url,
            is_phishing = result.get("in_database", False) and result.get("valid", False),
            verified    = result.get("verified", False),
            phish_id    = str(result.get("phish_id")) if result.get("phish_id") else None,
        )
    except Exception as exc:
        return PhishTankResult(url=url, error=str(exc)[:120])

# ── URLhaus (abuse.ch) — no key required ──────────────────────────────────────

async def check_urlhaus(client: httpx.AsyncClient, url: str) -> UrlhausResult:
    """Checks a URL against the URLhaus malware distribution database."""
    try:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"User-Agent": "ThreatLens/3.0"},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return UrlhausResult(url=url, error=f"HTTP {resp.status_code}")

        data = resp.json()
        query_status = data.get("query_status", "")

        if query_status == "no_results":
            return UrlhausResult(url=url, status="not_found")

        if query_status == "is_host":
            # URL is tracked — extract details
            url_status   = data.get("url_status", "unknown")
            threat       = data.get("threat")
            tags         = data.get("tags") or []
            date_added   = (data.get("date_added") or "")[:10]
            is_malicious = url_status == "online"
            return UrlhausResult(
                url          = url,
                status       = url_status,
                threat       = threat,
                tags         = tags,
                date_added   = date_added,
                is_malicious = is_malicious,
            )

        return UrlhausResult(url=url, status="not_found")

    except Exception as exc:
        return UrlhausResult(url=url, error=str(exc)[:120])


# ── ThreatFox (abuse.ch) — no key required ────────────────────────────────────

async def check_threatfox(client: httpx.AsyncClient, indicator: str, ioc_type: str) -> ThreatFoxResult:
    """
    Queries ThreatFox for a domain, IP, URL, or hash IOC.
    ioc_type hint: 'domain' | 'ip' | 'url' | 'hash'
    """
    try:
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": indicator},
            headers={"User-Agent": "ThreatLens/3.0"},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return ThreatFoxResult(indicator=indicator, ioc_type=ioc_type,
                                   error=f"HTTP {resp.status_code}")

        data        = resp.json()
        query_status = data.get("query_status", "")

        if query_status == "no_result":
            return ThreatFoxResult(indicator=indicator, ioc_type=ioc_type, hit=False)

        if query_status == "ok" and data.get("data"):
            entry = data["data"][0]
            tags  = entry.get("tags") or []
            return ThreatFoxResult(
                indicator  = indicator,
                ioc_type   = ioc_type,
                hit        = True,
                malware    = entry.get("malware_printable") or entry.get("malware"),
                confidence = entry.get("confidence_level"),
                first_seen = (entry.get("first_seen") or "")[:10],
                tags       = tags,
            )

        return ThreatFoxResult(indicator=indicator, ioc_type=ioc_type, hit=False)

    except Exception as exc:
        return ThreatFoxResult(indicator=indicator, ioc_type=ioc_type, error=str(exc)[:120])

# ── PII Sanitizer ──────────────────────────────────────────────────────────────

# Patterns that should never reach an external AI model.
# URLs and email addresses are intentionally kept — they're the threat signals.
_CARD_NUMBER_PATTERN = re.compile(r'\b(?:\d[ -]?){13,19}\b')
_PII_RULES: list[tuple[re.Pattern, str]] = [
    # Social Security Number  (US)
    (re.compile(r'\b\d{3}[- ]\d{2}[- ]\d{4}\b'), "[SSN]"),
    # Contextual IBAN labels only — avoids redacting random uppercase IDs
    (re.compile(r'(?i)\b(iban)\b\s*[:#-]?\s*[A-Z]{2}\d{2}[A-Z0-9 ]{10,30}\b'), r'\1: [IBAN]'),
    # Routing / account labels only
    (re.compile(r'(?i)\b(routing(?:\s+number)?|aba)\b\s*[:#-]?\s*\d{9}\b'), r'\1: [ROUTING_NUMBER]'),
    (re.compile(r'(?i)\b(account(?:\s+number)?)\b\s*[:#-]?\s*\d{4,17}\b'), r'\1: [ACCOUNT_NUMBER]'),
    # CVV / CVC codes
    (re.compile(r'(?i)\b(cvv|cvc|cvv2|cvc2|security code)\b\s*[:\-]?\s*\d{3,4}\b'), r'\1: [CVV]'),
    # Phone numbers  (various international formats)
    (re.compile(r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), "[PHONE]"),
    # Inline passwords / secrets / tokens / API keys
    (re.compile(
        r'(?i)(password|passwd|pwd|passphrase|secret|token|api[_\-]?key|'
        r'access[_\-]?key|private[_\-]?key)\s*[:=]\s*\S+'),
     r'\1: [REDACTED]'),
    # Passport numbers only when explicitly labeled
    (re.compile(r'(?i)\b(passport(?:\s+(?:no|number))?)\b\s*[:#-]?\s*[A-Z0-9]{6,12}\b'), r'\1: [PASSPORT]'),
    # Date of birth only when explicitly labeled
    (re.compile(r'(?i)\b(date of birth|dob|birth date)\b\s*[:#-]?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b'),
     r'\1: [DATE_OF_BIRTH]'),
]


def _is_likely_card_number(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _redact_card_number(match: re.Match) -> str:
    value = match.group(0)
    return "[CARD_NUMBER]" if _is_likely_card_number(value) else value


def sanitize_for_ai(text: str) -> str:
    """
    Removes PII and credentials from email body before sending to Claude.
    URLs and email addresses are preserved — they are the threat indicators.
    """
    text = _CARD_NUMBER_PATTERN.sub(_redact_card_number, text)
    for pattern, replacement in _PII_RULES:
        text = pattern.sub(replacement, text)
    return text


# ── Claude Analysis ────────────────────────────────────────────────────────────

def build_vt_summary(scans: list[LinkScan]) -> str:
    if not scans:
        return "No URLs were found in this email."
    lines = [f"Total URLs scanned: {len(scans)}"]
    for s in scans:
        if s.is_malicious:
            lines.append(f"  MALICIOUS ({s.malicious}/{s.total} engines) — {s.url}")
        elif s.is_suspicious:
            lines.append(f"  SUSPICIOUS ({s.suspicious}/{s.total} engines) — {s.url}")
        elif s.status == "first_scan":
            lines.append(f"  FIRST SCAN (no cached data) — {s.url}")
        elif s.status == "ok":
            lines.append(f"  CLEAN ({s.harmless}/{s.total} engines) — {s.url}")
        else:
            lines.append(f"  UNKNOWN (status: {s.status}) — {s.url}")
    return "\n".join(lines)


def build_intel_summary(
    sender_domain: Optional[str],
    whois_list:   list[WhoisInfo],
    dns_list:     list[DnsInfo],
    geo_list:     list[GeoRepInfo],
    urlhaus_list: list[UrlhausResult],
    tf_list:      list[ThreatFoxResult],
    phish_list:   list[PhishTankResult],
    mb_results:   list[MalwareBazaarResult],
) -> str:
    lines = []
    sender_domain = normalize_domain(sender_domain)

    sender_whois = next(
        (w for w in whois_list if normalize_domain(w.domain) == sender_domain and not w.error),
        None,
    )
    sender_dns = next(
        (d for d in dns_list if normalize_domain(d.domain) == sender_domain and not d.error),
        None,
    )

    if sender_whois:
        flag = " [NEW DOMAIN < 30 days]" if sender_whois.is_new else ""
        lines.append(
            f"Sender WHOIS {sender_whois.domain}: registrar={sender_whois.registrar}, "
            f"age={sender_whois.age_days}d, country={sender_whois.country}{flag}"
        )

    if sender_dns:
        auth_scope = f" via {sender_dns.auth_domain}" if sender_dns.auth_domain and sender_dns.auth_domain != sender_dns.domain else ""
        lines.append(
            f"Sender DNS {sender_dns.domain}{auth_scope}: "
            f"SPF={'yes' if sender_dns.has_spf else 'MISSING'}, "
            f"DMARC={'yes' if sender_dns.has_dmarc else 'MISSING'}, "
            f"MX={sender_dns.mx_records}"
        )

    for w in whois_list:
        if w.error or normalize_domain(w.domain) == sender_domain or not w.is_new:
            continue
        lines.append(
            f"Link WHOIS {w.domain}: registrar={w.registrar}, age={w.age_days}d, "
            f"country={w.country} [NEW DOMAIN < 30 days]"
        )

    for g in geo_list:
        if g.error:
            continue
        flags = []
        if g.is_tor:
            flags.append("TOR")
        if g.abuse_score and g.abuse_score >= 60:
            flags.append(f"ABUSE SCORE: {g.abuse_score}")
        if not flags:
            continue
        lines.append(f"GeoIP {g.ip}: {g.country}, {g.org} [{' | '.join(flags)}]")

    for u in urlhaus_list:
        if u.is_malicious or u.status in ("online", "offline"):
            lines.append(f"URLhaus: {u.url} — status={u.status}, threat={u.threat}, tags={u.tags}")

    for t in tf_list:
        if t.hit:
            lines.append(f"ThreatFox: {t.indicator} — malware={t.malware}, confidence={t.confidence}%, tags={t.tags}")

    for p in phish_list:
        if p.is_phishing:
            lines.append(f"PhishTank: {p.url} confirmed phishing (verified={p.verified})")

    for m in mb_results:
        if m.found:
            lines.append(f"MalwareBazaar: hash found! type={m.file_type}, threat={m.threat_name}, tags={m.tags}")

    return "\n".join(lines) if lines else "No additional intelligence flags."


def analyze_with_claude(
    payload: EmailPayload,
    scans: list[LinkScan],
    hashes: HashInfo,
    intel_summary: str,
) -> dict:
    client = anthropic.Anthropic(api_key=get_key("ANTHROPIC_API_KEY"))

    vt_block      = build_vt_summary(scans)
    body_excerpt  = sanitize_for_ai(payload.body)[:2500]   # PII stripped before AI
    sender_domain = normalize_domain(payload.sender.email.split("@")[-1] if "@" in payload.sender.email else None)

    prompt = f"""You are ThreatLens, an AI cybersecurity analyst embedded in a Chrome extension.
Your audience is non-technical executives who need clear, actionable guidance — no jargon.

Analyze the following email, VirusTotal results, and SOC intelligence, then respond ONLY with valid JSON.

━━━ EMAIL ━━━
From:     {payload.sender.name} <{payload.sender.email}>
Sender domain: {sender_domain or "unknown"}
Subject:  {payload.subject}
Words:    {payload.wordCount}
Links:    {payload.linkCount}

Body (excerpt):
{body_excerpt}

━━━ VIRUSTOTAL URL SCAN RESULTS ━━━
{vt_block}

━━━ SOC INTELLIGENCE ━━━
{intel_summary}

━━━ EMAIL BODY HASHES ━━━
MD5:    {hashes.md5}
SHA-1:  {hashes.sha1}
SHA-256:{hashes.sha256}

━━━ REQUIRED JSON RESPONSE FORMAT ━━━
{{
  "threat_level": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": <float 0.0–1.0>,
  "summary": "<2–3 sentence plain-English explanation>",
  "key_findings": [
    "<specific finding 1>",
    "<specific finding 2>",
    "<specific finding 3>"
  ],
  "recommended_action": "<one clear sentence>"
}}

Rules:
- Redaction placeholders such as [CARD_NUMBER], [PHONE], [IBAN], [PASSPORT], and [DATE_OF_BIRTH] are privacy filters, not threat indicators.
- threat_level MALICIOUS only if concrete evidence supports it: any VT scan is malicious, PhishTank confirms phishing, MalwareBazaar hit, URLhaus reports an active malicious URL, or there are multiple strong phishing indicators tied to this email.
- threat_level SUSPICIOUS if suspicious VT, new domain (<30 days), urgency language, ThreatFox/URLhaus hits.
- threat_level SAFE only if all checks clean and no red flags.
- CRITICAL: If you determine the email is from a legitimate company or is a genuine onboarding/marketing email, you MUST return SAFE ("No threat detected"). Do NOT mark it SUSPICIOUS just because it uses click-trackers, lacks SPF/DMARC, or has a single low-consensus suspicious security hit.
- Do NOT mark the email SUSPICIOUS solely because of missing SPF/DMARC.
- Do NOT mark the email MALICIOUS solely because of sanitized placeholders, common account-security wording, clean link-tracking URLs, or cloud/hosting infrastructure used by major providers.
- If evidence is weak, mixed, or incomplete, prefer SUSPICIOUS over MALICIOUS.
- Keep summary under 60 words. No jargon.
- key_findings must be specific to THIS email.
- recommended_action: one decisive sentence.
"""

    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}],
    )

    raw   = msg.content[0].text.strip()
    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"Claude returned no JSON: {raw[:200]}")
    return json.loads(raw[start:end])


def calibrate_ai_analysis(
    payload: EmailPayload,
    analysis: dict,
    scans: list[LinkScan],
    whois_list: list[WhoisInfo],
    dns_list: list[DnsInfo],
    urlhaus_list: list[UrlhausResult],
    tf_list: list[ThreatFoxResult],
    pt_list: list[PhishTankResult],
    mb_result: MalwareBazaarResult,
) -> dict:
    calibrated = dict(analysis)
    level = str(calibrated.get("threat_level", "SUSPICIOUS")).upper()
    if level not in {"SAFE", "SUSPICIOUS", "MALICIOUS"}:
        level = "SUSPICIOUS"

    try:
        confidence = float(calibrated.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    sender_domain = normalize_domain(payload.sender.email.split("@")[-1] if "@" in payload.sender.email else None)
    sender_root = get_registered_domain(sender_domain)
    sender_whois = next(
        (w for w in whois_list if normalize_domain(w.domain) == sender_domain and not w.error),
        None,
    )
    sender_dns = next(
        (d for d in dns_list if normalize_domain(d.domain) == sender_domain and not d.error),
        None,
    )
    trusted_sender = is_trusted_domain(sender_domain)
    trusted_or_related_links = [
        s for s in scans
        if (
            is_trusted_domain(extract_domain(s.url)) or
            get_registered_domain(extract_domain(s.url)) == sender_root
        )
    ]

    confirmed_malicious = (
        any(s.is_malicious for s in scans) or
        any(p.is_phishing for p in pt_list) or
        any(u.is_malicious for u in urlhaus_list) or
        mb_result.found
    )
    link_suspicious = any(s.is_suspicious for s in scans)
    suspicious_signals = (
        link_suspicious or
        any(t.hit for t in tf_list) or
        any(u.status in ("online", "offline") for u in urlhaus_list) or
        bool(sender_whois and sender_whois.is_new)
    )
    all_links_clean = all(
        s.status in ("ok", "first_scan") and not s.is_malicious and not s.is_suspicious
        for s in scans
    )
    feeds_clean = (
        not any(p.is_phishing for p in pt_list) and
        not any(t.hit for t in tf_list) and
        not any(u.status in ("online", "offline") for u in urlhaus_list) and
        not mb_result.found
    )
    sender_is_clean = bool(
        sender_whois and
        not sender_whois.is_new
    )
    only_weak_trusted_link_noise = bool(trusted_or_related_links) and all(
        not s.is_malicious and s.is_suspicious for s in trusted_or_related_links
    ) and all(
        (s in trusted_or_related_links) or (not s.is_malicious and not s.is_suspicious)
        for s in scans
    )

    if trusted_sender and only_weak_trusted_link_noise:
        suspicious_signals = False
        link_suspicious = False

    # We trust the LLM's semantic analysis for zero-day phishing without external IOC hits.
    # However, if external threat intel CONFIRMS it's malicious, we upgrade it.
    if confirmed_malicious and level != "MALICIOUS":
        level = "MALICIOUS"
        confidence = max(confidence, 0.90)

    calibrated["threat_level"] = level
    calibrated["confidence"] = max(0.0, min(confidence, 1.0))
    if not isinstance(calibrated.get("key_findings"), list):
        calibrated["key_findings"] = []
    return calibrated

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":               "ok",
        "version":              "3.0.0",
        "vt_configured":        bool(get_key("VIRUS_TOTAL_API_KEY")),
        "anthropic_configured": bool(get_key("ANTHROPIC_API_KEY")),
        "abuseipdb_configured": bool(get_key("ABUSEIPDB_API_KEY")),
        "urlscan_configured":   bool(get_key("URLSCAN_API_KEY")),
        "urlhaus_enabled":      True,   # no key required
        "threatfox_enabled":    True,   # no key required
    }


@app.post("/deep-analyze", response_model=DeepAnalysisResponse)
async def deep_analyze(payload: EmailPayload):
    """
    Full SOC intelligence endpoint.
    Runs VirusTotal + WHOIS + crt.sh + DNS + GeoIP + AbuseIPDB +
    MalwareBazaar + URLScan + PhishTank + URLhaus + ThreatFox in parallel,
    then synthesises with Claude.
    """
    if not get_key("VIRUS_TOTAL_API_KEY"):
        raise HTTPException(500, "VIRUS_TOTAL_API_KEY not set.")
    if not get_key("ANTHROPIC_API_KEY"):
        raise HTTPException(500, "ANTHROPIC_API_KEY not set.")

    # ── 1. Hashes ──────────────────────────────────────────────────────────
    hashes = compute_hashes(payload.body)

    # ── 2. Unique domains from links ───────────────────────────────────────
    # Also include sender domain
    sender_domain = normalize_domain(payload.sender.email.split("@")[-1] if "@" in payload.sender.email else None)
    link_domains  = list({d for u in payload.links if (d := extract_domain(u))})
    if sender_domain and sender_domain not in link_domains:
        link_domains.insert(0, sender_domain)
    link_domains = link_domains[:8]   # cap to avoid rate limits

    # ── 3. Parallel async fetch ────────────────────────────────────────────
    async with httpx.AsyncClient() as client:
        tasks: dict[str, Any] = {}

        # VirusTotal
        tasks["vt"] = vt_scan_all(payload.links)

        # Per-domain tasks
        for d in link_domains:
            tasks[f"crt_{d}"] = get_crtsh(client, d)
            tasks[f"dns_{d}"] = get_dns_info(client, d)
            tasks[f"geo_{d}"] = get_geo_rep(client, d)
            tasks[f"tf_{d}"]  = check_threatfox(client, d, "domain")

        # Per-URL tasks (cap to 5 to stay within limits)
        for index, u in enumerate(payload.links[:5]):
            safe_key = f"{index}_{u.replace('://', '_').replace('/', '_')[:40]}"
            tasks[f"pt_{safe_key}"] = check_phishtank(client, u)
            tasks[f"us_{safe_key}"] = urlscan_submit(client, u)
            tasks[f"uh_{safe_key}"] = check_urlhaus(client, u)

        # MalwareBazaar (body SHA-256)
        tasks["mb"] = check_malware_bazaar(client, hashes.sha256)

        keys   = list(tasks.keys())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        result_map = {k: (v if not isinstance(v, Exception) else None)
                      for k, v in zip(keys, results)}

    # ── 4. Assemble typed lists ────────────────────────────────────────────
    link_scans:   list[LinkScan]          = result_map.get("vt") or []
    whois_list:   list[WhoisInfo]         = []
    cert_list:    list[CertInfo]          = []
    dns_list:     list[DnsInfo]           = []
    geo_list:     list[GeoRepInfo]        = []
    urlhaus_list: list[UrlhausResult]     = []
    tf_list:      list[ThreatFoxResult]   = []
    pt_list:      list[PhishTankResult]   = []
    us_list:      list[UrlScanResult]     = []

    # WHOIS is slow/blocking — run in thread pool
    whois_results = await asyncio.gather(
        *[get_whois(d) for d in link_domains], return_exceptions=True
    )
    for r in whois_results:
        if isinstance(r, WhoisInfo):
            whois_list.append(r)

    for k, v in result_map.items():
        if v is None:
            continue
        if k.startswith("crt_"):
            cert_list.append(v)
        elif k.startswith("dns_"):
            dns_list.append(v)
        elif k.startswith("geo_"):
            geo_list.append(v)
        elif k.startswith("tf_"):
            tf_list.append(v)
        elif k.startswith("uh_"):
            urlhaus_list.append(v)
        elif k.startswith("pt_"):
            pt_list.append(v)
        elif k.startswith("us_"):
            us_list.append(v)

    mb_result: MalwareBazaarResult = result_map.get("mb") or MalwareBazaarResult()

    # ── 5. Claude synthesis ────────────────────────────────────────────────
    intel_summary = build_intel_summary(
        sender_domain, whois_list, dns_list, geo_list, urlhaus_list, tf_list, pt_list, [mb_result]
    )
    try:
        analysis = await asyncio.to_thread(
            analyze_with_claude, payload, link_scans, hashes, intel_summary
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(500, f"Claude returned malformed JSON: {exc}")
    except Exception as exc:
        raise HTTPException(500, f"Claude analysis failed: {exc}")
    analysis = calibrate_ai_analysis(
        payload, analysis, link_scans, whois_list, dns_list, urlhaus_list, tf_list, pt_list, mb_result
    )

    # ── 6. Return ──────────────────────────────────────────────────────────
    return DeepAnalysisResponse(
        ai = AiAnalysis(
            threat_level       = analysis.get("threat_level",       "SUSPICIOUS"),
            confidence         = float(analysis.get("confidence",   0.5)),
            summary            = analysis.get("summary",            ""),
            key_findings       = analysis.get("key_findings",       []),
            recommended_action = analysis.get("recommended_action", ""),
        ),
        hashes         = hashes,
        link_scans     = link_scans,
        whois_info     = whois_list,
        cert_info      = cert_list,
        dns_info       = dns_list,
        geo_rep        = geo_list,
        malware_bazaar = [mb_result],
        urlscan        = us_list,
        phishtank      = pt_list,
        urlhaus        = urlhaus_list,
        threatfox      = tf_list,
    )


# ── Legacy /analyze endpoint (backward compat) ────────────────────────────────

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(payload: EmailPayload):
    if not get_key("VIRUS_TOTAL_API_KEY"):
        raise HTTPException(500, "VIRUS_TOTAL_API_KEY not set.")
    if not get_key("ANTHROPIC_API_KEY"):
        raise HTTPException(500, "ANTHROPIC_API_KEY not set.")

    link_scans = await vt_scan_all(payload.links)
    hashes     = compute_hashes(payload.body)

    try:
        analysis = await asyncio.to_thread(
            analyze_with_claude, payload, link_scans, hashes, ""
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(500, f"Claude returned malformed JSON: {exc}")
    except Exception as exc:
        raise HTTPException(500, f"Claude analysis failed: {exc}")
    analysis = calibrate_ai_analysis(
        payload,
        analysis,
        link_scans,
        [],
        [],
        [],
        [],
        [],
        MalwareBazaarResult(),
    )

    return AnalysisResponse(
        threat_level       = analysis.get("threat_level",       "SUSPICIOUS"),
        confidence         = float(analysis.get("confidence",   0.5)),
        summary            = analysis.get("summary",            ""),
        key_findings       = analysis.get("key_findings",       []),
        recommended_action = analysis.get("recommended_action", ""),
        link_scans         = link_scans,
    )
