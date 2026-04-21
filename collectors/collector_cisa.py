import requests
import logging
import time
import os
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────
ES_HOST     = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER     = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "elastic123")
INDEX_NAME  = "exploits-cisa-kev"

# URLs de secours si l'URL principale échoue
CISA_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"  # backup
]

# ── Logging ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/cisa_collector.log"),
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
                "cve_id":             {"type": "keyword"},
                "vendor_project":     {"type": "keyword"},
                "product":            {"type": "keyword"},
                "vulnerability_name": {"type": "text"},
                "date_added":         {"type": "date"},
                "short_description":  {"type": "text"},
                "required_action":    {"type": "text"},
                "due_date":           {"type": "date"},
                "known_ransomware":   {"type": "keyword"},
                "notes":              {"type": "text"},
                "actively_exploited": {"type": "boolean"},
                "collected_at":       {"type": "date"},
                "source":             {"type": "keyword"}
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

# ── Téléchargement CISA KEV avec retry ────────────────────────
def fetch_cisa_kev():
    # Headers pour éviter le blocage par le serveur CISA
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
        "Accept":     "application/json"
    }

    url = CISA_URLS[0]
    max_retries = 3

    for attempt in range(1, max_retries + 1):
        log.info(f"Téléchargement CISA KEV — tentative {attempt}/{max_retries}...")
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=60,
                verify=True  # SSL activé
            )
            resp.raise_for_status()
            data = resp.json()
            break  # succès
        except requests.exceptions.SSLError as e:
            log.warning(f"Erreur SSL : {e} — retry sans vérification SSL...")
            try:
                resp = requests.get(url, headers=headers, timeout=60, verify=False)
                resp.raise_for_status()
                data = resp.json()
                break
            except Exception as e2:
                log.error(f"Échec SSL désactivé aussi : {e2}")
                if attempt == max_retries:
                    return []
                time.sleep(10 * attempt)
        except requests.exceptions.ConnectionError as e:
            log.error(f"Erreur connexion : {e}")
            if attempt == max_retries:
                log.error("Toutes les tentatives ont échoué.")
                return []
            time.sleep(10 * attempt)
        except Exception as e:
            log.error(f"Erreur inattendue : {e}")
            if attempt == max_retries:
                return []
            time.sleep(10 * attempt)

    vulnerabilities = data.get("vulnerabilities", [])
    log.info(f"CISA KEV téléchargé : {len(vulnerabilities)} entrées")
    log.info(f"Catalogue complet — couvre TOUTES les années (pas seulement les récentes)")

    docs = []
    for v in vulnerabilities:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue

        docs.append({
            "_id":                cve_id,
            "cve_id":             cve_id,
            "vendor_project":     v.get("vendorProject", ""),
            "product":            v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added":         v.get("dateAdded", None),
            "short_description":  v.get("shortDescription", ""),
            "required_action":    v.get("requiredAction", ""),
            "due_date":           v.get("dueDate", None),
            "known_ransomware":   v.get("knownRansomwareCampaignUse", "Unknown"),
            "notes":              v.get("notes", ""),
            "actively_exploited": True,  # Tout ce qui est dans KEV = activement exploité
            "collected_at":       datetime.now(timezone.utc).isoformat(),
            "source":             "CISA-KEV"
        })

    # Log statistiques par année pour montrer la couverture historique
    years = {}
    for d in docs:
        date_added = d.get("date_added", "")
        if date_added:
            year = date_added[:4]
            years[year] = years.get(year, 0) + 1
    for year in sorted(years.keys()):
        log.info(f"  {year} : {years[year]} exploits")

    return docs

# ── Indexation bulk ────────────────────────────────────────────
def index_exploits(es, docs):
    if not docs:
        log.warning("Aucun exploit à indexer.")
        return 0

    actions = [
        {
            "_op_type": "index",
            "_index":   INDEX_NAME,
            "_id":      doc["_id"],
            "_source":  {k: v for k, v in doc.items() if k != "_id"}
        }
        for doc in docs
    ]

    success, errors = helpers.bulk(es, actions, raise_on_error=False)
    log.info(f"Indexés avec succès : {success}")
    if errors:
        log.error(f"Erreurs : {len(errors)}")
    return success

# ── Point d'entrée ─────────────────────────────────────────────
def run():
    log.info("=== Démarrage collecteur CISA KEV ===")
    log.info("Note: CISA KEV contient TOUS les exploits actifs toutes années confondues")
    start = time.time()

    es = get_es_client()
    if not es.ping():
        log.error("Elasticsearch inaccessible. Abandon.")
        return

    create_index(es)
    docs    = fetch_cisa_kev()
    indexed = index_exploits(es, docs)

    duration = round(time.time() - start, 2)
    log.info(f"=== CISA KEV terminé en {duration}s — {indexed} exploits indexés ===")

if __name__ == "__main__":
    run()
