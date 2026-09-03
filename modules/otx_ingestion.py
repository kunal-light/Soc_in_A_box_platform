import ipaddress, re, requests
from config import Config
from modules.database import get_connection, record_feed_sync

URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

def classify(t):
    t=(t or "").lower()
    if t in ("ipv4","ipv6"): return "IP"
    if t in ("domain","hostname"): return "DOMAIN"
    if t in ("url","uri"): return "URL"
    if t in ("filehash-md5","filehash-sha1","filehash-sha256"): return "HASH"

def valid(v,t):
    if not v or not t: return False
    if t=="IP":
        try: ipaddress.ip_address(v); return True
        except ValueError: return False
    if t=="DOMAIN": return bool(re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}",v))
    if t=="URL": return v.lower().startswith(("http://","https://"))
    if t=="HASH": return bool(re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}",v))
    return False

def fetch_otx_indicators(limit=10):
    if not Config.OTX_API_KEY: raise RuntimeError("OTX_API_KEY is not configured.")
    r=requests.get(URL,headers={"X-OTX-API-KEY":Config.OTX_API_KEY},params={"limit":limit},timeout=30)
    r.raise_for_status()
    result=[]
    for pulse in r.json().get("results",[]):
        for x in pulse.get("indicators",[]):
            v=(x.get("indicator") or "").strip(); t=classify(x.get("type"))
            if valid(v,t): result.append((v,t,"AlienVault OTX","HIGH"))
    return result

def ingest_otx_feed(limit=10):
    try:
        rows=fetch_otx_indicators(limit)
        conn=get_connection(); cur=conn.cursor(); inserted=0
        for v,t,s,severity in rows:
            cur.execute("SELECT 1 FROM iocs WHERE indicator=%s LIMIT 1",(v,))
            if cur.fetchone(): continue
            cur.execute("INSERT INTO iocs (indicator,ioc_type,source,severity,created_at) VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP)",(v,t,s,severity))
            inserted+=1
        conn.commit(); cur.close(); conn.close()
        record_feed_sync("AlienVault OTX","SUCCESS",inserted,f"Fetched {len(rows)} valid indicators; inserted {inserted} new IOCs.")
        return {"fetched":len(rows),"inserted":inserted}
    except Exception as e:
        record_feed_sync("AlienVault OTX","FAILED",0,str(e)[:1000]); raise
