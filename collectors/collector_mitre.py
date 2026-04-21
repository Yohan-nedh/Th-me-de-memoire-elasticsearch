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
INDEX_NAME  = "mitre-attack"

# URLs de téléchargement — plusieurs sources pour la robustesse
MITRE_URLS = [
    # Source officielle GitHub MITRE
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    # Mirror STIX 2.1 (fallback)
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json"
]

# ── Logging ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/mitre_collector.log"),
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
                "technique_id":     {"type": "keyword"},
                "name":             {"type": "text"},
                "description":      {"type": "text"},
                "tactic":           {"type": "keyword"},
                "platforms":        {"type": "keyword"},
                "data_sources":     {"type": "keyword"},
                "detection":        {"type": "text"},
                "is_subtechnique":  {"type": "boolean"},
                "parent_technique": {"type": "keyword"},
                "url":              {"type": "keyword"},
                "collected_at":     {"type": "date"},
                "source":           {"type": "keyword"}
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

# ── Téléchargement MITRE ATT&CK avec retry ────────────────────
def fetch_mitre():
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
        "Accept":     "application/json"
    }

    data = None
    for url in MITRE_URLS:
        log.info(f"Téléchargement MITRE ATT&CK depuis : {url}")
        for attempt in range(1, 4):
            try:
                resp = requests.get(url, headers=headers, timeout=120)
                resp.raise_for_status()
                data = resp.json()
                log.info("Téléchargement réussi.")
                break
            except requests.exceptions.ConnectionError as e:
                log.warning(f"Tentative {attempt}/3 — Connexion échouée : {e}")
                if attempt < 3:
                    time.sleep(15 * attempt)
            except requests.exceptions.Timeout:
                log.warning(f"Tentative {attempt}/3 — Timeout (>120s)")
                if attempt < 3:
                    time.sleep(15 * attempt)
            except Exception as e:
                log.error(f"Erreur inattendue : {e}")
                break
        if data:
            break

    if not data:
        log.error("Impossible de télécharger MITRE ATT&CK depuis toutes les sources.")
        return []

    objects = data.get("objects", [])
    log.info(f"Total objets MITRE bruts : {len(objects)}")

    docs = []
    stats = {"techniques": 0, "subtechniques": 0, "revoked": 0, "deprecated": 0}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Comptage des révoqués/dépréciés pour les stats
        if obj.get("revoked", False):
            stats["revoked"] += 1
            continue
        if obj.get("x_mitre_deprecated", False):
            stats["deprecated"] += 1
            continue

        technique_id = ""
        url_ref      = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url_ref      = ref.get("url", "")
                break

        if not technique_id:
            continue

        tactics = [
            phase.get("phase_name", "").replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        is_subtechnique  = obj.get("x_mitre_is_subtechnique", False)
        parent_technique = technique_id.split(".")[0] if is_subtechnique else ""

        if is_subtechnique:
            stats["subtechniques"] += 1
        else:
            stats["techniques"] += 1

        docs.append({
            "_id":              technique_id,
            "technique_id":     technique_id,
            "name":             obj.get("name", ""),
            "description":      obj.get("description", ""),
            "tactic":           tactics,
            "platforms":        obj.get("x_mitre_platforms", []),
            "data_sources":     obj.get("x_mitre_data_sources", []),
            "detection":        obj.get("x_mitre_detection", ""),
            "is_subtechnique":  is_subtechnique,
            "parent_technique": parent_technique,
            "url":              url_ref,
            "collected_at":     datetime.now(timezone.utc).isoformat(),
            "source":           "MITRE-ATTACK"
        })

    log.info(f"Techniques principales  : {stats['techniques']}")
    log.info(f"Sous-techniques         : {stats['subtechniques']}")
    log.info(f"Révoquées (ignorées)    : {stats['revoked']}")
    log.info(f"Dépréciées (ignorées)   : {stats['deprecated']}")
    log.info(f"Total valides           : {len(docs)}")

    return docs

# ── Indexation bulk ────────────────────────────────────────────
def index_techniques(es, docs):
    if not docs:
        log.warning("Aucune technique à indexer.")
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
    log.info(f"Indexées avec succès : {success}")
    if errors:
        log.error(f"Erreurs : {len(errors)}")
    return success

# ── Point d'entrée ─────────────────────────────────────────────
def run():
    log.info("=== Démarrage collecteur MITRE ATT&CK ===")
    log.info("Note: MITRE ATT&CK contient toutes les techniques (anciennes et nouvelles)")
    start = time.time()

    es = get_es_client()
    if not es.ping():
        log.error("Elasticsearch inaccessible. Abandon.")
        return

    create_index(es)
    docs    = fetch_mitre()
    indexed = index_techniques(es, docs)

    duration = round(time.time() - start, 2)
    log.info(f"=== MITRE ATT&CK terminé en {duration}s — {indexed} techniques indexées ===")

if __name__ == "__main__":
    run()
