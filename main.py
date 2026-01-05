import os
import socket
import json
import ssl
import datetime
try:
    import dns.resolver as dns_resolver
except Exception:
    dns_resolver = None
from functools import lru_cache
from urllib.parse import urlparse
from urllib.request import urlopen, Request

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .model_inference import get_classifier

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str
    headers: dict | None = None

# --- Enterprise Security Analyzers ---

class SSLAnalyzer:
    @staticmethod
    @lru_cache(maxsize=128)
    def analyze(hostname: str) -> dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Expiry Check
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.datetime.now()).days
                    
                    # Issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    common_name = issuer.get('commonName', 'Unknown')
                    
                    return {
                        "valid": True,
                        "days_until_expiry": days_left,
                        "issuer": common_name,
                        "protocol": ssock.version()
                    }
        except Exception:
            return {"valid": False, "error": "SSL handshake failed or invalid"}

class DNSAnalyzer:
    @staticmethod
    @lru_cache(maxsize=128)
    def analyze(hostname: str) -> dict:
        results = {"has_spf": False, "has_dmarc": False}
        if dns_resolver is None:
            return results
        try:
            try:
                txt_records = dns_resolver.resolve(hostname, 'TXT', lifetime=3)
                for record in txt_records:
                    if "v=spf1" in record.to_text():
                        results["has_spf"] = True
                        break
            except:
                pass
            try:
                dmarc_records = dns_resolver.resolve(f"_dmarc.{hostname}", 'TXT', lifetime=3)
                for record in dmarc_records:
                    if "v=DMARC1" in record.to_text():
                        results["has_dmarc"] = True
                        break
            except:
                pass
        except Exception:
            pass
        return results

class HeaderAnalyzer:
    @staticmethod
    def analyze(headers: dict) -> list:
        weaknesses = []
        if not headers: return weaknesses
        
        # normalize headers to lowercase
        h = {k.lower(): v for k, v in headers.items()}
        
        if 'strict-transport-security' not in h:
            weaknesses.append("Missing HSTS header (Man-in-the-Middle risk)")
        if 'content-security-policy' not in h:
            weaknesses.append("Missing CSP header (XSS risk)")
        if 'x-frame-options' not in h:
            weaknesses.append("Missing X-Frame-Options (Clickjacking risk)")
        if 'x-content-type-options' not in h:
            weaknesses.append("Missing X-Content-Type-Options (MIME sniffing risk)")
            
        return weaknesses

# --- Main Logic ---

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan")
def scan_url(data: URLRequest):
    url = data.url
    # 1. Base ML Classification
    clf = get_classifier()
    result = clf.predict(url)
    
    base_score = int(result.get("risk_score", 0))
    classification = result.get("classification", "safe")
    reasons = list(result.get("reasons", []))
    features = dict(result.get("features", {}))
    
    # Parse Hostname
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except:
        hostname = ""

    # 2. Header Analysis (Enterprise)
    if data.headers:
        header_issues = HeaderAnalyzer.analyze(data.headers)
        if header_issues:
            # Cap penalty for headers to avoid false positives on simple sites
            base_score = max(base_score, 25) 
            reasons.extend(header_issues[:3]) # Top 3 header issues
            
        server = data.headers.get("server") or data.headers.get("x-powered-by")
        if server:
            features["server_banner"] = server

    # 3. Host Resolution & Shodan/InternetDB
    ip_addr = None
    if hostname:
        try:
            ip_addr = socket.gethostbyname(hostname)
            features["resolved_ip"] = ip_addr
            
            # Shodan/InternetDB Lookup
            shodan_vulns = []
            shodan_ports = []
            shodan_key = os.getenv("SHODAN_API_KEY")
            
            # Try Shodan API
            if shodan_key:
                try:
                    with urlopen(f"https://api.shodan.io/shodan/host/{ip_addr}?key={shodan_key}", timeout=3) as resp:
                        d = json.loads(resp.read().decode("utf-8"))
                        shodan_vulns = d.get("vulns", [])
                        shodan_ports = d.get("ports", [])
                except: pass
            
            # Fallback InternetDB
            if not shodan_vulns and not shodan_ports:
                try:
                    req = Request(
                        f"https://internetdb.shodan.io/{ip_addr}",
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                    )
                    with urlopen(req, timeout=3) as resp:
                        d = json.loads(resp.read().decode("utf-8"))
                        shodan_vulns = d.get("vulns", [])
                        shodan_ports = d.get("ports", [])
                except: pass

            if shodan_ports:
                features["open_ports"] = shodan_ports
                reasons.append(f"Open ports: {', '.join(str(p) for p in shodan_ports[:5])}...")
            
            if shodan_vulns:
                features["cve_count"] = len(shodan_vulns)
                features["cve_list"] = shodan_vulns # Send full list for UI
                reasons.append(f"Vulnerabilities found: {len(shodan_vulns)} CVEs detected")
                # Critical Enterprise Rule: Known Vulnerabilities = Block
                base_score = max(base_score, 90)
                classification = "malicious"

        except Exception:
            pass

    # 4. Advanced Active Checks (SSL & DNS)
    if hostname:
        # SSL Check
        if parsed.scheme == "https":
             ssl_res = SSLAnalyzer.analyze(hostname)
             if not ssl_res["valid"]:
                 base_score = max(base_score, 75)
                 reasons.append("SSL Certificate Invalid or Expired")
             elif ssl_res["valid"] and ssl_res["days_until_expiry"] < 30:
                  reasons.append(f"SSL Expiring soon ({ssl_res['days_until_expiry']} days)")
        
        # DNS Security Check
        dns_res = DNSAnalyzer.analyze(hostname)
        if not dns_res["has_spf"] and not dns_res["has_dmarc"]:
             reasons.append("Missing Email Security Records (SPF/DMARC)")
             # Only penalize if not already malicious to avoid noise
             if base_score < 70: 
                base_score += 10

    # Final Classification Logic
    if base_score >= 75:
        classification = "malicious"
        action = "block"
    elif base_score >= 40:
        classification = "suspicious"
        action = "warn"
    else:
        classification = "safe"
        action = "allow"

    return {
        "risk_score": min(100, base_score),
        "classification": classification,
        "action": action,
        "reasons": list(set(reasons)), # Deduplicate
        "features": features,
        "model_confidence": float(result.get("model_confidence", 0.0)),
    }
