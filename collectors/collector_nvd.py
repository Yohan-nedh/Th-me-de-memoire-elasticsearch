import requests
import logging
import time
import os
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────
ES_HOST     = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER     = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# INDEX CORRIGÉ : aligné avec ce qui existe dans ton Elasticsearch
INDEX_NAME  = "vulnerabilities-nvd"

# NVD : fenêtre max autorisée par l'API = 120 jours par tranche
BATCH_SIZE      = 2000
SLEEP_SEC       = 6   # sans clé API
SLEEP_SEC_KEY   = 1   # avec clé API
MAX_DAYS_WINDOW = 120 # limite NVD API par requête

# ── Logging ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/nvd_collector.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── Connexion Elasticsearch ────────────────────────────────────
def get_es_client():
    return Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASSWORD),
        verify_certs=False,
        ssl_show_warn=False
    )

# ── Mapping de l'index ─────────────────────────────────────────
def create_index(es):
    mapping = {
        "mappings": {
            "properties": {
                "cve_id":            {"type": "keyword"},
                "description":       {"type": "text"},
                "published":         {"type": "date"},
                "last_modified":     {"type": "date"},
                "cvss_score":        {"type": "float"},
                "cvss_severity":     {"type": "keyword"},
                "cvss_vector":       {"type": "keyword"},
                "cvss_version":      {"type": "keyword"},
                "cwe":               {"type": "keyword"},
                "references":        {"type": "keyword"},
                "affected_products": {"type": "keyword"},
                "vendor":            {"type": "keyword"},
                "patch_available":   {"type": "boolean"},
                "exploitability":    {"type": "float"},
                "impact_score":      {"type": "float"},
                "collected_at":      {"type": "date"},
                "source":            {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards":   1,
            "number_of_replicas": 0
        }
    }
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME, body=mapping)
        log.info(f"Index '{INDEX_NAME}' créé.")
    else:
        log.info(f"Index '{INDEX_NAME}' déjà existant.")

# ── Normalisation d'un CVE ─────────────────────────────────────
def normalize_cve(cve):
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics        = cve.get("metrics", {})
    cvss_score     = None
    cvss_severity  = None
    cvss_vector    = None
    cvss_version   = None
    exploitability = None
    impact_score   = None

    for vk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if vk in metrics and metrics[vk]:
            m = metrics[vk][0]
            d = m.get("cvssData", {})
            cvss_score     = d.get("baseScore")
            cvss_severity  = d.get("baseSeverity") or m.get("baseSeverity")
            cvss_vector    = d.get("vectorString")
            cvss_version   = d.get("version")
            exploitability = m.get("exploitabilityScore")
            impact_score   = m.get("impactScore")
            break

    if cvss_score and not cvss_severity:
        if   cvss_score >= 9.0: cvss_severity = "CRITICAL"
        elif cvss_score >= 7.0: cvss_severity = "HIGH"
        elif cvss_score >= 4.0: cvss_severity = "MEDIUM"
        else:                   cvss_severity = "LOW"

    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    refs = [r.get("url", "") for r in cve.get("references", [])]
    patch_available = any(
        k in ref.lower() for ref in refs
        for k in ["patch", "fix", "update", "advisory", "security"]
    )

    affected = []
    vendors  = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                uri   = cpe.get("criteria", "")
                parts = uri.split(":")
                if len(parts) > 4:
                    vendors.append(parts[3])
                    affected.append(f"{parts[3]}:{parts[4]}")

    return {
        "_id":               cve_id,
        "cve_id":            cve_id,
        "description":       desc,
        "published":         cve.get("published"),
        "last_modified":     cve.get("lastModified"),
        "cvss_score":        cvss_score,
        "cvss_severity":     cvss_severity,
        "cvss_vector":       cvss_vector,
        "cvss_version":      cvss_version,
        "cwe":               list(set(cwes)),
        "references":        refs[:10],
        "affected_products": list(set(affected))[:20],
        "vendor":            list(set(vendors))[:10],
        "patch_available":   patch_available,
        "exploitability":    exploitability,
        "impact_score":      impact_score,
        "collected_at":      datetime.now(timezone.utc).isoformat(),
        "source":            "NVD"
    }

# ── Collecte d'une fenêtre temporelle ─────────────────────────
def fetch_window(start_date, end_date, headers, sleep):
    """Collecte les CVE entre start_date et end_date (max 120 jours)."""
    params = {
        "pubStartDate":   start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": BATCH_SIZE,
        "startIndex":     0
    }

    all_cves = []
    total    = None
    page     = 0

    while True:
        page += 1
        log.info(f"  Page {page} | startIndex={params['startIndex']} | "
                 f"Fenêtre: {start_date.date()} → {end_date.date()}")
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, headers=headers, timeout=60
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.error(f"Erreur requête NVD : {e}")
            time.sleep(30)  # attendre avant retry
            break

        if total is None:
            total = data.get("totalResults", 0)
            log.info(f"  Total dans cette fenêtre : {total}")

        for item in data.get("vulnerabilities", []):
            all_cves.append(normalize_cve(item.get("cve", {})))

        params["startIndex"] += BATCH_SIZE
        if params["startIndex"] >= total:
            break
        time.sleep(sleep)

    return all_cves

# ── COLLECTE HISTORIQUE COMPLÈTE (depuis 2002) ─────────────────
# CORRECTION MAJEURE : on collecte TOUTE la base NVD par tranches
# de 120 jours pour respecter les limites de l'API.
# Une CVE de 2017 (EternalBlue) sera donc bien collectée.
def fetch_nvd_full_history(es, start_year=2002):
    headers   = {}
    sleep_sec = SLEEP_SEC

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        sleep_sec         = SLEEP_SEC_KEY
        log.info("Clé API NVD détectée — collecte accélérée.")
    else:
        log.warning("Aucune clé API NVD — collecte lente (6s entre requêtes).")

    end_date    = datetime.now(timezone.utc)
    start_date  = datetime(start_year, 1, 1, tzinfo=timezone.utc)
    window_days = timedelta(days=MAX_DAYS_WINDOW)

    total_indexed = 0
    cursor     = start_date
    total_wins = 0

    log.info(f"=== Collecte historique NVD depuis {start_year} ===")

    while cursor < end_date:
        win_end  = min(cursor + window_days, end_date)
        total_wins += 1
        log.info(f"Fenêtre {total_wins}: {cursor.date()} → {win_end.date()}")

        batch = fetch_window(cursor, win_end, headers, sleep_sec)
        indexed = index_cves(es, batch)
	batch.clear()
        log.info(f"  → {len(batch)} CVE collectés | Total: {len(all_cves)}")

        cursor = win_end + timedelta(seconds=1)
        time.sleep(sleep_sec)

    log.info(f"Collecte historique terminée : {len(all_cves)} CVE au total")

# ── COLLECTE INCRÉMENTALE (mises à jour récentes) ──────────────
# Pour la collecte hebdomadaire : on utilise lastModStartDate
# au lieu de pubStartDate → capte aussi les CVEs anciennes
# qui ont été MISES À JOUR récemment (score CVSS révisé, etc.)
def fetch_nvd_incremental(days_back=7):
    headers   = {}
    sleep_sec = SLEEP_SEC

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        sleep_sec         = SLEEP_SEC_KEY

    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)

    log.info(f"=== Collecte incrémentale NVD — {days_back} derniers jours ===")

    # CORRECTION : lastModStartDate au lieu de pubStartDate
    # → on récupère aussi les vieilles CVEs modifiées récemment
    params = {
        "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate":   end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage":   BATCH_SIZE,
        "startIndex":       0
    }

    all_cves = []
    total    = None
    page     = 0

    while True:
        page += 1
        log.info(f"Page {page} — startIndex={params['startIndex']}")
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, headers=headers, timeout=60
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.error(f"Erreur requête NVD : {e}")
            break

        if total is None:
            total = data.get("totalResults", 0)
            log.info(f"CVE modifiés/ajoutés : {total}")

        for item in data.get("vulnerabilities", []):
            all_cves.append(normalize_cve(item.get("cve", {})))

        params["startIndex"] += BATCH_SIZE
        if params["startIndex"] >= total:
            break
        time.sleep(sleep_sec)

    return all_cves

# ── Indexation bulk ────────────────────────────────────────────
def index_cves(es, cves):
    if not cves:
        log.warning("Aucun CVE à indexer.")
        return 0

    actions = [
        {
            "_op_type": "index",
            "_index":   INDEX_NAME,
            "_id":      doc["_id"],
            "_source":  {k: v for k, v in doc.items() if k != "_id"}
        }
        for doc in cves if doc.get("_id")
    ]

    success, errors = helpers.bulk(es, actions, raise_on_error=False)
    log.info(f"Indexés avec succès : {success}")
    if errors:
        log.error(f"Erreurs d'indexation : {len(errors)}")
    return success

# ── Point d'entrée ─────────────────────────────────────────────
def run(mode="incremental", days_back=7, start_year=2002):
    """
    mode="full"        → collecte tout depuis start_year (première fois)
    mode="incremental" → collecte les 7 derniers jours (cron hebdo)
    """
    log.info(f"=== Démarrage collecteur NVD [mode={mode}] ===")
    start = time.time()

    es = get_es_client()
    if not es.ping():
        log.error("Elasticsearch inaccessible. Abandon.")
        return

    create_index(es)

    if mode == "full":
        cves = fetch_nvd_full_history(start_year=start_year)
    else:
        cves = fetch_nvd_incremental(days_back=days_back)
	indexed = index_cves(es, cves)

    duration = round(time.time() - start, 2)
    log.info(f"=== NVD terminé en {duration}s ===")

if __name__ == "__main__":
    import sys
    # Usage:
    #   python collector_nvd.py full       → collecte historique complète
    #   python collector_nvd.py full 2015  → depuis 2015 seulement
    #   python collector_nvd.py            → incrémental 7 jours (défaut)
    #   python collector_nvd.py incremental 30 → 30 derniers jours
    if len(sys.argv) > 1 and sys.argv[1] == "full":
        year = int(sys.argv[2]) if len(sys.argv) > 2 else 2002
        run(mode="full", start_year=year)
    else:
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
        run(mode="incremental", days_back=days)
