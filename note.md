
note sur mon évolution

Logstash est un pipeline de traitement de données côté serveur, open source, qui collecte, transforme et envoie des données (logs, métriques) en temps réel. Membre clé de la suite Elastic (ELK), il structure les données non structurées, les enrichit et les dirige vers des destinations comme Elasticsearch pour analyse. 


Fonctions principales de Logstash :
Ingestion (Input) : Collecte des données provenant de multiples sources simultanément (fichiers de logs, applications web, bases de données, services AWS).
Transformation (Filter/Parsing) : Analyse et structure les données brutes (non structurées) en données exploitables grâce à des plugins comme Grok (découpage), déchiffre des données géographiques, et anonymise des informations.
Envoi (Output) : Transfère les données transformées vers diverses destinations, principalement Elasticsearch pour le stockage et l'indexation.
Fiabilité : Garantit la livraison des événements (files d'attente persistantes) et gère les pics de charge sans perte de données. 


Il fonctionne en trois étapes : Input (entrée), Filter (filtre/transformation), et Output (sortie).

./logstash/pipeline/ → contient le fichier logstash.conf qui définit comment Logstash reçoit, filtre et envoie les logs vers Elasticsearch
./logstash/config/logstash.yml → fichier de configuration principale de Logstash (ports, monitoring, etc.)

## Commençons par le pipeline NVD (National Vulnerability Database)

**Créer la structure du projet**
mkdir -p /home/ubuntu-server/elasticsearch/collectors
mkdir -p /home/ubuntu-server/elasticsearch/collectors/logs

cd /home/ubuntu-server/elasticsearch/collectors

**Créer le fichier de requirements Python**
cat > requirements.txt <<EOF
requests==2.31.0
elasticsearch==8.13.0
python-dotenv==1.0.0
schedule==1.2.1
EOF

**Installer Python et pip si nécessaire**
sudo apt-get install -y python3 python3-pip
pip3 install -r requirements.txt --break-system-packages

**collectors/ — contient tous les scripts Python**
par exemple : collector_nvd.py → collecte les CVE depuis l'API NVD

 **collectors/logs/ — contient les fichiers de logs des script**
 par exemple : nvd_collector.log → trace de chaque exécution (combien de CVE récupérés, erreurs, durée)

script pour nvd nom collectors_nvd.py
cat > /home/ubuntu-server/elasticsearch/collectors/collector_nvd.py << 'EOF'
import requests
import logging
import time
import os
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

### ── Configuration ──────────────────────────────────────────────
ES_HOST    = os.getenv("ES_HOST", "http://localhost:9200")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
INDEX_NAME  = "vulnerabilities-nvd"
BATCH_SIZE  = 2000
SLEEP_SEC   = 6        # respect rate limit NVD (sans clé API)

### ── Logging ────────────────────────────────────────────────────
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

### ── Connexion Elasticsearch ────────────────────────────────────
def get_es_client():
    return Elasticsearch(ES_HOST)

### ── Mapping de l'index ─────────────────────────────────────────
def create_index(es: Elasticsearch):
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
            "number_of_replicas": 0,
            "index": {
                "lifecycle": {"name": "12-months-policy"}
            }
        }
    }
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME, body=mapping)
        log.info(f"Index '{INDEX_NAME}' créé.")
    else:
        log.info(f"Index '{INDEX_NAME}' déjà existant.")

### ── Normalisation d'un CVE ─────────────────────────────────────
def normalize_cve(cve: dict) -> dict:
    cve_id = cve.get("id", "")

    # Description en anglais
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # CVSS — on prend v3.1 en priorité, sinon v3.0, sinon v2
    metrics    = cve.get("metrics", {})
    cvss_score    = None
    cvss_severity = None
    cvss_vector   = None
    cvss_version  = None
    exploitability = None
    impact_score   = None

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and metrics[version_key]:
            m = metrics[version_key][0]
            cvss_data      = m.get("cvssData", {})
            cvss_score     = cvss_data.get("baseScore")
            cvss_severity  = cvss_data.get("baseSeverity") or m.get("baseSeverity")
            cvss_vector    = cvss_data.get("vectorString")
            cvss_version   = cvss_data.get("version")
            exploitability = m.get("exploitabilityScore")
            impact_score   = m.get("impactScore")
            break

    # Criticité textuelle si absente
    if cvss_score and not cvss_severity:
        if   cvss_score >= 9.0: cvss_severity = "CRITICAL"
        elif cvss_score >= 7.0: cvss_severity = "HIGH"
        elif cvss_score >= 4.0: cvss_severity = "MEDIUM"
        else:                   cvss_severity = "LOW"

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    # Références
    refs = [r.get("url", "") for r in cve.get("references", [])]

    # Produits affectés
    affected  = []
    vendors   = []
    patch_available = False
    configs = cve.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                uri = cpe.get("criteria", "")
                parts = uri.split(":")
                if len(parts) > 4:
                    vendors.append(parts[3])
                    affected.append(f"{parts[3]}:{parts[4]}")

    # Présence d'un patch (heuristique sur les références)
    patch_keywords = ["patch", "fix", "update", "advisory", "security"]
    for ref in refs:
        if any(k in ref.lower() for k in patch_keywords):
            patch_available = True
            break

    return {
        "_id":              cve_id,
        "cve_id":           cve_id,
        "description":      desc,
        "published":        cve.get("published"),
        "last_modified":    cve.get("lastModified"),
        "cvss_score":       cvss_score,
        "cvss_severity":    cvss_severity,
        "cvss_vector":      cvss_vector,
        "cvss_version":     cvss_version,
        "cwe":              list(set(cwes)),
        "references":       refs[:10],
        "affected_products": list(set(affected))[:20],
        "vendor":           list(set(vendors))[:10],
        "patch_available":  patch_available,
        "exploitability":   exploitability,
        "impact_score":     impact_score,
        "collected_at":     datetime.now(timezone.utc).isoformat(),
        "source":           "NVD"
    }

### ── Collecte paginée depuis l'API NVD ─────────────────────────
def fetch_nvd(days_back: int = 7):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        log.info("Clé API NVD détectée — rate limit étendu.")
    else:
        log.warning("Aucune clé API NVD — limite : 5 req/30s.")

    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": BATCH_SIZE,
        "startIndex": 0
    }

    all_cves  = []
    total     = None
    page      = 0

    while True:
        page += 1
        log.info(f"Requête page {page} — startIndex={params['startIndex']}")
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.error(f"Erreur requête NVD : {e}")
            break

        if total is None:
            total = data.get("totalResults", 0)
            log.info(f"Total CVE à récupérer : {total}")

        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            all_cves.append(normalize_cve(item.get("cve", {})))

        log.info(f"Récupérés : {len(all_cves)}/{total}")

        params["startIndex"] += BATCH_SIZE
        if params["startIndex"] >= total:
            break

        time.sleep(SLEEP_SEC)

    return all_cves

### ── Indexation bulk dans Elasticsearch ────────────────────────
def index_cves(es: Elasticsearch, cves: list):
    if not cves:
        log.warning("Aucun CVE à indexer.")
        return

    actions = [
        {
            "_op_type": "index",
            "_index":   INDEX_NAME,
            "_id":      doc["_id"],
            "_source":  {k: v for k, v in doc.items() if k != "_id"}
        }
        for doc in cves
    ]

    success, errors = helpers.bulk(es, actions, raise_on_error=False)
    log.info(f"Indexés avec succès : {success}")
    if errors:
        log.error(f"Erreurs d'indexation : {len(errors)}")
        for e in errors[:5]:
            log.error(e)

### ── Point d'entrée ─────────────────────────────────────────────
def run(days_back: int = 7):
    log.info("=== Démarrage collecteur NVD ===")
    start = time.time()

    es = get_es_client()
    if not es.ping():
        log.error("Elasticsearch inaccessible. Abandon.")
        return

    create_index(es)
    cves = fetch_nvd(days_back=days_back)
    index_cves(es, cves)

    duration = round(time.time() - start, 2)
    log.info(f"=== Collecteur NVD terminé en {duration}s — {len(cves)} CVE indexés ===")

if __name__ == "__main__":
    import sys
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    run(days_back=days)
EOF




