from fastapi import FastAPI, HTTPException, Header, Query
from typing import Optional
import urllib.request
import re
import dns.resolver

app = FastAPI(
    title="Advanced Disposable Email & Domain Risk Checker API",
    description="Multi-layer disposable email detection using community blacklists and MX fingerprinting.",
    version="1.0.0"
)

RAPIDAPI_SECRET = "d8567c40-b525-11f1-8dcf-d55eb89b0915"

# Global set for 5000+ community reported disposable domains
DISPOSABLE_DOMAINS = set()

# Known disposable mail server fingerprints (MX hosts)
DISPOSABLE_MX_KEYWORDS = [
    "tempmail", "mailinator", "guerrillamail", "sharklasers", 
    "yopmail", "dispostable", "trashmail", "dropmail", "10minutemail"
]

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "proton.me", "protonmail.com", "zoho.com", "aol.com"
}

@app.on_event("startup")
def load_disposable_blacklist():
    global DISPOSABLE_DOMAINS
    print("Loading comprehensive disposable domains blacklist...")
    try:
        # Trusted community list maintained with 3000+ active burner domains
        url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            lines = response.read().decode('utf-8').splitlines()
            DISPOSABLE_DOMAINS = {line.strip().lower() for line in lines if line.strip() and not line.startswith('#')}
        print(f"Successfully loaded {len(DISPOSABLE_DOMAINS)} disposable domains into RAM!")
    except Exception as e:
        print(f"Warning: Could not fetch remote list ({e}), loading core fallback set.")
        DISPOSABLE_DOMAINS = {
            "tempmailo.com", "forexzig.com", "10minutemail.com", "guerrillamail.com",
            "mailinator.com", "sharklasers.com", "yopmail.com", "temp-mail.org"
        }

def verify_proxy_secret(secret_header: Optional[str]):
    if RAPIDAPI_SECRET != "DISABLED" and secret_header != RAPIDAPI_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Unauthorized request")

def inspect_mx(domain: str):
    """Fetches MX records and inspects host fingerprints."""
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=2.5)
        mx_records = [str(r.exchange).rstrip('.').lower() for r in answers]
        
        # Check if MX points to any known disposable mail servers
        is_mx_disposable = any(
            any(keyword in mx for keyword in DISPOSABLE_MX_KEYWORDS)
            for mx in mx_records
        )
        return True, mx_records, is_mx_disposable
    except Exception:
        return False, [], False

@app.get("/")
def health():
    return {
        "status": "online",
        "service": "Disposable Email & Risk Checker API",
        "blacklisted_domains_count": len(DISPOSABLE_DOMAINS)
    }

@app.get("/api/v1/verify/email")
def verify_email(
    email: str = Query(..., description="Email to inspect (e.g. mufude@forexzig.com)"),
    x_rapidapi_proxy_secret: Optional[str] = Header(None)
):
    verify_proxy_secret(x_rapidapi_proxy_secret)

    clean_email = email.strip().lower()
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", clean_email):
        raise HTTPException(status_code=400, detail="Invalid email syntax format.")

    username, domain = clean_email.split("@", 1)

    # 1. Direct Domain Check
    matched_domain_blacklist = domain in DISPOSABLE_DOMAINS

    # 2. MX Server Inspection & Fingerprinting
    has_mx, mx_hosts, matched_mx_blacklist = inspect_mx(domain)

    # Final Disposable Verdict
    is_disposable = matched_domain_blacklist or matched_mx_blacklist
    is_free = domain in FREE_PROVIDERS

    # Risk Calculation
    if is_disposable:
        risk_score = 98
        reason = "Domain or mail exchange host flagged as temporary/disposable."
    elif not has_mx:
        risk_score = 85
        reason = "Domain does not have valid MX records to receive emails."
    elif is_free:
        risk_score = 15
        reason = "Free consumer email provider."
    else:
        risk_score = 0
        reason = "Legitimate business/corporate domain with active mail exchangers."

    return {
        "success": True,
        "email": clean_email,
        "domain": domain,
        "is_disposable": is_disposable,
        "is_free_provider": is_free,
        "has_mx_records": has_mx,
        "mx_hosts": mx_hosts,
        "risk_score": risk_score,
        "reason": reason,
        "recommendation": "block" if is_disposable or not has_mx else "accept"
    }
