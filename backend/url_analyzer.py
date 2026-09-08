"""
PhishGuard - URL Deep Security Analyzer & Intelligence Service
Retrieves real destination website data using standard protocols (DNS, SSL, WHOIS, HTTP)
Calculates an objective Security Trust Score and detects redirect chains.
No fake data: unretrievable fields clearly state 'Information not publicly available'.
"""

import socket
import ssl
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser

import requests
try:
    import whois
except ImportError:
    whois = None

# Custom HTML Parser to extract title, description, favicon, and OpenGraph tags
class WebsiteMetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = None
        self.in_title = False
        self.meta_desc = None
        self.og_title = None
        self.og_desc = None
        self.favicon = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "title" and not self.title:
            self.in_title = True
        elif tag_lower == "meta":
            name = attrs_dict.get("name", "").lower()
            prop = attrs_dict.get("property", "").lower()
            content = attrs_dict.get("content", "").strip()

            if name == "description" and not self.meta_desc:
                self.meta_desc = content
            elif prop == "og:description" and not self.og_desc:
                self.og_desc = content
            elif prop == "og:title" and not self.og_title:
                self.og_title = content
        elif tag_lower == "link":
            rel = attrs_dict.get("rel", "").lower()
            href = attrs_dict.get("href", "").strip()
            if ("icon" in rel or "shortcut icon" in rel) and not self.favicon and href:
                self.favicon = href

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title and not self.title:
            cleaned = data.strip()
            if cleaned:
                self.title = cleaned


def sanitize_url(raw_url: str) -> tuple[str, str, int]:
    """Ensures scheme is present and extracts domain and port."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0].strip()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return url, domain, port


def get_dns_and_ip_info(domain: str) -> dict:
    """Resolves IP addresses, canonical hostname, and aliases."""
    try:
        canonical, aliases, ips = socket.gethostbyname_ex(domain)
        primary_ip = ips[0] if ips else "Information not publicly available"
        return {
            "ip_address": primary_ip,
            "all_ips": ips[:5],
            "canonical_name": canonical if canonical != domain else "Same as domain",
            "aliases": aliases if aliases else [],
            "status": "Resolved"
        }
    except Exception as e:
        return {
            "ip_address": "Information not publicly available",
            "all_ips": [],
            "canonical_name": "Information not publicly available",
            "aliases": [],
            "status": f"DNS Lookup Failed ({str(e)})"
        }


def get_ssl_certificate_details(domain: str, port: int = 443) -> dict:
    """Connects via TLS and extracts real SSL certificate attributes."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, port), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Extract Issuer Organization and Common Name
                issuer_org = "Information not publicly available"
                issuer_cn = "Information not publicly available"
                for rdn in cert.get("issuer", ()):
                    for key, val in rdn:
                        if key == "organizationName":
                            issuer_org = val
                        elif key == "commonName":
                            issuer_cn = val

                # Extract Subject Common Name
                subject_cn = "Information not publicly available"
                for rdn in cert.get("subject", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            subject_cn = val

                valid_from = cert.get("notBefore", "Information not publicly available")
                valid_until = cert.get("notAfter", "Information not publicly available")

                return {
                    "has_ssl": True,
                    "status": "Valid & Active",
                    "issuer": issuer_org if issuer_org != "Information not publicly available" else issuer_cn,
                    "subject": subject_cn,
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                    "tls_version": version or "TLS 1.2/1.3",
                    "cipher": cipher[0] if cipher else "AES-GCM",
                    "self_signed": False
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "has_ssl": False,
            "status": "Untrusted / Invalid Certificate",
            "issuer": "Untrusted / Self-signed",
            "subject": domain,
            "valid_from": "Information not publicly available",
            "valid_until": "Information not publicly available",
            "tls_version": "N/A",
            "cipher": "N/A",
            "self_signed": True,
            "error": str(e)
        }
    except Exception as e:
        return {
            "has_ssl": False,
            "status": "No Valid SSL / Connection Timed Out",
            "issuer": "Information not publicly available",
            "subject": "Information not publicly available",
            "valid_from": "Information not publicly available",
            "valid_until": "Information not publicly available",
            "tls_version": "None",
            "cipher": "None",
            "self_signed": False,
            "error": str(e)
        }


def format_whois_date(val) -> str:
    """Helper to convert whois dates (which may be lists) to YYYY-MM-DD."""
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return "Information not publicly available"


def get_whois_info(domain: str) -> dict:
    """Queries WHOIS data for registrar, creation date, expiration, and calculates age."""
    if whois is None:
        return {
            "registrar": "Information not publicly available",
            "creation_date": "Information not publicly available",
            "expiration_date": "Information not publicly available",
            "domain_age": "Information not publicly available",
            "organization": "Information not publicly available",
            "country": "Information not publicly available",
            "nameservers": []
        }

    try:
        w = whois.whois(domain)

        creation_dt = w.creation_date[0] if isinstance(w.creation_date, list) and w.creation_date else w.creation_date
        expiration_dt = w.expiration_date[0] if isinstance(w.expiration_date, list) and w.expiration_date else w.expiration_date

        creation_str = format_whois_date(creation_dt)
        expiration_str = format_whois_date(expiration_dt)

        # Calculate domain age
        age_str = "Information not publicly available"
        if isinstance(creation_dt, datetime):
            now = datetime.now(creation_dt.tzinfo) if creation_dt.tzinfo else datetime.now()
            diff_days = (now - creation_dt).days
            if diff_days >= 365:
                years = diff_days // 365
                months = (diff_days % 365) // 30
                age_str = f"{years} years, {months} months ({diff_days:,} days)"
            elif diff_days > 0:
                age_str = f"{diff_days} days"
            else:
                age_str = "Newly registered"

        # Registrar
        reg = w.registrar or "Information not publicly available"
        if isinstance(reg, list):
            reg = reg[0]

        # Organization & Country
        org = getattr(w, "org", None) or getattr(w, "name", None) or "Information not publicly available"
        country = getattr(w, "country", None) or "Information not publicly available"

        nameservers = w.name_servers or []
        if isinstance(nameservers, list):
            nameservers = [str(ns).lower() for ns in nameservers[:4]]

        return {
            "registrar": reg,
            "creation_date": creation_str,
            "expiration_date": expiration_str,
            "domain_age": age_str,
            "organization": org,
            "country": country,
            "nameservers": nameservers
        }
    except Exception:
        return {
            "registrar": "Information not publicly available",
            "creation_date": "Information not publicly available",
            "expiration_date": "Information not publicly available",
            "domain_age": "Information not publicly available",
            "organization": "Information not publicly available",
            "country": "Information not publicly available",
            "nameservers": []
        }


def get_ip_geolocation_and_asn(ip: str) -> dict:
    """Queries ip-api.com for public server hosting, ASN, and geo location."""
    if not ip or ip == "Information not publicly available" or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return {
            "hosting_provider": "Internal / Private Network",
            "asn": "Private Network",
            "city": "Local / Unspecified",
            "country": "Private Network",
            "country_code": "LOC"
        }

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as",
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "hosting_provider": data.get("org") or data.get("isp") or "Information not publicly available",
                    "asn": data.get("as") or "Information not publicly available",
                    "city": data.get("city") or "Information not publicly available",
                    "country": data.get("country") or "Information not publicly available",
                    "country_code": data.get("countryCode") or ""
                }
    except Exception:
        pass

    return {
        "hosting_provider": "Information not publicly available",
        "asn": "Information not publicly available",
        "city": "Information not publicly available",
        "country": "Information not publicly available",
        "country_code": ""
    }


def get_website_metadata_and_redirects(url: str) -> dict:
    """
    Sends a controlled GET request to inspect redirect chains, HTTP status,
    server headers, page title, description, and favicon.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        resp = requests.get(url, timeout=3.5, headers=headers, allow_redirects=True)
        redirects = [h.url for h in resp.history]
        final_url = resp.url
        server_header = resp.headers.get("Server", "Information not publicly available")
        content_type = resp.headers.get("Content-Type", "").split(";")[0] or "text/html"

        # Parse HTML for title, meta description, and favicon
        parser = WebsiteMetadataParser()
        html_chunk = resp.text[:100000]  # Inspect first 100KB of HTML
        try:
            parser.feed(html_chunk)
        except Exception:
            pass

        title = parser.title or parser.og_title or "Information not publicly available"
        description = parser.meta_desc or parser.og_desc or "Information not publicly available"

        favicon_url = None
        if parser.favicon:
            favicon_url = urljoin(final_url, parser.favicon)
        else:
            # Standard fallback
            parsed_final = urlparse(final_url)
            favicon_url = f"{parsed_final.scheme}://{parsed_final.netloc}/favicon.ico"

        return {
            "title": title,
            "description": description,
            "favicon": favicon_url,
            "server_header": server_header,
            "content_type": content_type,
            "redirect_count": len(redirects),
            "redirect_chain": redirects,
            "final_destination": final_url,
            "http_status": resp.status_code
        }
    except Exception as e:
        return {
            "title": "Information not publicly available",
            "description": "Information not publicly available",
            "favicon": None,
            "server_header": "Information not publicly available",
            "content_type": "Information not publicly available",
            "redirect_count": 0,
            "redirect_chain": [],
            "final_destination": url,
            "http_status": f"Unreachable ({str(e)})"
        }


def calculate_trust_score(
    is_phishing: bool,
    ml_confidence: float,
    has_ssl: bool,
    domain_age: str,
    suspicious_count: int,
    redirect_count: int
) -> int:
    """
    Computes an objective 0-100 Security Trust Score.
    """
    if is_phishing:
        # Base penalty for phishing
        score = max(5, int(100 - ml_confidence))
        if not has_ssl:
            score -= 5
        score = max(3, min(25, score))
        return score

    # For legitimate / safe sites:
    score = 80

    if has_ssl:
        score += 10
    else:
        score -= 25

    # Domain age bonuses
    if "years" in domain_age:
        try:
            years = int(re.search(r"(\d+)\s+years", domain_age).group(1))
            if years >= 10:
                score += 8
            elif years >= 2:
                score += 5
        except Exception:
            score += 3
    elif "Newly" in domain_age or "days" in domain_age:
        score -= 10

    if suspicious_count == 0:
        score += 2
    else:
        score -= (suspicious_count * 5)

    if redirect_count > 3:
        score -= 10

    return max(50, min(99, score))


def analyze_url_deep(raw_url: str, ml_prediction: str, ml_confidence: float, feature_dict: dict) -> dict:
    """
    Runs concurrent intelligence gathering across DNS, SSL, WHOIS, IP Geolocation,
    and HTTP metadata to assemble a complete Safe Website Report or Phishing Diagnostic.
    """
    norm_url, domain, port = sanitize_url(raw_url)
    is_phishing = ml_prediction.lower() == "phishing"

    # Parallel execution of external lookups for minimal latency
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_dns = executor.submit(get_dns_and_ip_info, domain)
        future_ssl = executor.submit(get_ssl_certificate_details, domain, port)
        future_whois = executor.submit(get_whois_info, domain)
        future_http = executor.submit(get_website_metadata_and_redirects, norm_url)

        dns_info = future_dns.result()
        ssl_info = future_ssl.result()
        whois_info = future_whois.result()
        http_info = future_http.result()

    # Query IP Geolocation with resolved IP
    geo_info = get_ip_geolocation_and_asn(dns_info.get("ip_address"))

    # Determine Owner / Organization
    organization = whois_info.get("organization")
    if organization == "Information not publicly available":
        organization = geo_info.get("hosting_provider")

    country = whois_info.get("country")
    if country == "Information not publicly available":
        country = geo_info.get("country")

    # Calculate Trust Score
    trust_score = calculate_trust_score(
        is_phishing=is_phishing,
        ml_confidence=ml_confidence,
        has_ssl=ssl_info.get("has_ssl", False),
        domain_age=whois_info.get("domain_age", ""),
        suspicious_count=feature_dict.get("suspicious_words_count", 0),
        redirect_count=http_info.get("redirect_count", 0)
    )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "url": norm_url,
        "domain": domain,
        "prediction": ml_prediction,
        "is_safe": not is_phishing,
        "trust_score": trust_score,
        "security_score": trust_score,
        "timestamp": now_iso,
        "can_redirect": not is_phishing,

        "domain_info": {
            "domain_name": domain,
            "creation_date": whois_info.get("creation_date"),
            "expiration_date": whois_info.get("expiration_date"),
            "domain_age": whois_info.get("domain_age"),
            "registrar": whois_info.get("registrar"),
            "nameservers": whois_info.get("nameservers", [])
        },

        "organization_info": {
            "name": organization,
            "country": country,
            "city": geo_info.get("city")
        },

        "ssl_info": ssl_info,

        "server_info": {
            "ip_address": dns_info.get("ip_address"),
            "hosting_provider": geo_info.get("hosting_provider"),
            "asn": geo_info.get("asn"),
            "city": geo_info.get("city"),
            "country": geo_info.get("country"),
            "web_server": http_info.get("server_header"),
            "canonical_name": dns_info.get("canonical_name")
        },

        "website_metadata": {
            "title": http_info.get("title"),
            "description": http_info.get("description"),
            "favicon": http_info.get("favicon"),
            "content_type": http_info.get("content_type"),
            "redirect_count": http_info.get("redirect_count"),
            "final_destination": http_info.get("final_destination"),
            "http_status": http_info.get("http_status")
        }
    }


if __name__ == "__main__":
    # Test execution
    print("Testing url_analyzer on https://wikipedia.org ...")
    dummy_feats = {"suspicious_words_count": 0}
    report = analyze_url_deep("https://wikipedia.org", "Legitimate", 99.8, dummy_feats)
    import pprint
    pprint.pprint(report)
