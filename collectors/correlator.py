import logging
import os
import time
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────
# ES_HOST : adresse d'Elasticsearch
# INDEX_OUT : index de sortie qui contiendra les menaces corrélées
ES_HOST   = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER   = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
INDEX_OUT = "threats-correlated"

# ── Logging ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/correlator.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

def get_es_client():
    return Elasticsearch(
	ES_HOST,
	basic_auth=(ES_USER, ES_PASSWORD),
	verify_certs=False,
	ssl_show_warn=False

)

# ── Mapping de l'index de sortie ───────────────────────────────
# Cet index contiendra les CVE enrichis avec :
# - les infos CISA KEV (exploitation active, ransomware)
# - les tactiques MITRE ATT&CK associées
# - le score de priorité calculé
# - les recommandations correctives
def create_index(es):
    mapping = {
        "mappings": {
            "properties": {
                "cve_id":              {"type": "keyword"},
                "description":         {"type": "text"},
                "published":           {"type": "date"},
                "cvss_score":          {"type": "float"},
                "cvss_severity":       {"type": "keyword"},
                "cvss_vector":         {"type": "keyword"},
                "cwe":                 {"type": "keyword"},
                "affected_products":   {"type": "keyword"},
                "vendor":              {"type": "keyword"},
                "patch_available":     {"type": "boolean"},
                "actively_exploited":  {"type": "boolean"},
                "ransomware_related":  {"type": "boolean"},
                "required_action":     {"type": "text"},
                "due_date":            {"type": "date"},
                "mitre_techniques":    {"type": "keyword"},
                "mitre_tactics":       {"type": "keyword"},
                "mitre_names":         {"type": "text"},
                "priority_score":      {"type": "float"},
                "priority_level":      {"type": "keyword"},
                "recommendation":      {"type": "text"},
                "recommendation_short": {"type": "keyword"},
                "correlated_at":       {"type": "date"},
                "source":              {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards":   1,
            "number_of_replicas": 0
        }
    }
    if not es.indices.exists(index=INDEX_OUT):
        es.indices.create(index=INDEX_OUT, body=mapping)
        log.info(f"Index '{INDEX_OUT}' créé.")
    else:
        log.info(f"Index '{INDEX_OUT}' déjà existant.")

# ── Chargement CISA KEV en mémoire ────────────────────────────
# On charge tout le catalogue CISA KEV en mémoire RAM
# pour éviter de faire une requête ES pour chaque CVE
# C'est beaucoup plus rapide (1 requête au lieu de 1381)
def load_cisa_kev(es):
    log.info("Chargement CISA KEV en mémoire...")
    kev_map = {}
    resp = es.search(
        index="exploits-cisa-kev",
        body={"query": {"match_all": {}}, "size": 10000},
        scroll="2m"
    )
    scroll_id = resp["_scroll_id"]
    hits      = resp["hits"]["hits"]

    while hits:
        for hit in hits:
            src = hit["_source"]
            kev_map[src["cve_id"]] = {
                "actively_exploited": True,
                "ransomware_related": src.get("known_ransomware") == "Known",
                "required_action":    src.get("required_action", ""),
                "due_date":           src.get("due_date", None)
            }
        resp      = es.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits      = resp["hits"]["hits"]

    es.clear_scroll(scroll_id=scroll_id)
    log.info(f"CISA KEV chargé : {len(kev_map)} entrées")
    return kev_map

# ── Chargement MITRE ATT&CK en mémoire ────────────────────────
# On charge les techniques MITRE organisées par tactique
# ex: {"Initial Access": [{"technique_id": "T1190", ...}]}
def load_mitre(es):
    log.info("Chargement MITRE ATT&CK en mémoire...")
    mitre_map = {}
    resp = es.search(
        index="mitre-attack",
        body={"query": {"match_all": {}}, "size": 10000},
        scroll="2m"
    )
    scroll_id = resp["_scroll_id"]
    hits      = resp["hits"]["hits"]

    while hits:
        for hit in hits:
            src = hit["_source"]
            for tactic in src.get("tactic", []):
                if tactic not in mitre_map:
                    mitre_map[tactic] = []
                mitre_map[tactic].append({
                    "technique_id": src.get("technique_id"),
                    "name":         src.get("name"),
                    "platforms":    src.get("platforms", [])
                })
        resp      = es.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits      = resp["hits"]["hits"]

    es.clear_scroll(scroll_id=scroll_id)
    log.info(f"MITRE ATT&CK chargé : {len(mitre_map)} tactiques")
    return mitre_map

# ── Calcul du score de priorité ───────────────────────────────
# Formule de priorisation :
# Base          = score CVSS (0 à 10)
# +2.0          = si activement exploité (CISA KEV)
# +1.5          = si lié à un ransomware
# +0.5          = si aucun patch disponible
# Score final plafonné à 10.0
def compute_priority(cvss_score, actively_exploited, ransomware, patch_available):
    score = cvss_score or 0.0

    if actively_exploited: score += 2.0
    if ransomware:         score += 1.5
    if not patch_available: score += 0.5

    score = min(score, 10.0)

    if   score >= 9.0: level = "CRITICAL"
    elif score >= 7.0: level = "HIGH"
    elif score >= 4.0: level = "MEDIUM"
    else:              level = "LOW"

    return round(score, 2), level

# ── Génération de recommandation ──────────────────────────────
# Génère automatiquement une recommandation corrective
# basée sur les informations disponibles sur le CVE
def generate_recommendation(doc):
    parts = []

    if doc["actively_exploited"] and doc["ransomware_related"]:
        parts.append("URGENT : Vulnérabilité exploitée dans des campagnes ransomware.")
    elif doc["actively_exploited"]:
        parts.append("URGENT : Vulnérabilité activement exploitée dans la nature.")

    if doc["patch_available"]:
        parts.append("Un patch est disponible — appliquer immédiatement.")
    else:
        parts.append("Aucun patch disponible — envisager des mesures de contournement.")

    if doc["due_date"]:
        parts.append(f"Date limite d'action CISA : {doc['due_date']}.")

    if doc["required_action"]:
        parts.append(f"Action requise : {doc['required_action']}")

    severity = doc.get("cvss_severity", "")
    if   severity == "CRITICAL": parts.append("Remédiation sous 24h.")
    elif severity == "HIGH":     parts.append("Remédiation sous 72h.")
    elif severity == "MEDIUM":   parts.append("Remédiation sous 30 jours.")

    return " ".join(parts) if parts else "Surveiller et appliquer les correctifs disponibles."

# ── Table de correspondance CWE → Tactiques MITRE ─────────────
# Cette table fait le lien entre le type de faiblesse (CWE)
# et les tactiques d'attaque MITRE correspondantes
# ex: CWE-89 (SQL Injection) → Initial Access + Execution
CWE_TO_TACTIC = {
    "CWE-89":  ["Initial Access", "Execution"],
    "CWE-79":  ["Initial Access", "Execution"],
    "CWE-78":  ["Execution", "Privilege Escalation"],
    "CWE-22":  ["Initial Access", "Collection"],
    "CWE-287": ["Initial Access", "Defense Evasion"],
    "CWE-416": ["Privilege Escalation", "Execution"],
    "CWE-125": ["Execution", "Credential Access"],
    "CWE-190": ["Execution", "Privilege Escalation"],
    "CWE-269": ["Privilege Escalation"],
    "CWE-434": ["Initial Access", "Execution"],
    "CWE-502": ["Initial Access", "Execution"],
    "CWE-77":  ["Execution"],
    "CWE-306": ["Initial Access", "Defense Evasion"],
}

def get_mitre_for_cve(cwe_list, mitre_map):
    techniques = []
    tactics    = []
    names      = []

    for cwe in cwe_list:
        mapped_tactics = CWE_TO_TACTIC.get(cwe, [])
        for tactic in mapped_tactics:
            if tactic in mitre_map and tactic not in tactics:
                tactics.append(tactic)
                for tech in mitre_map[tactic][:3]:
                    if tech["technique_id"] not in techniques:
                        techniques.append(tech["technique_id"])
                        names.append(tech["name"])

    return techniques[:5], tactics[:3], names[:5]

# ── Corrélation principale ────────────────────────────────────
# C'est le cœur du moteur :
# Pour chaque CVE de NVD :
# 1. On vérifie s'il est dans CISA KEV
# 2. On trouve les tactiques MITRE via le CWE
# 3. On calcule le score de priorité
# 4. On génère une recommandation
# 5. On indexe le document enrichi dans threats-correlated
def correlate(es):
    kev_map   = load_cisa_kev(es)
    mitre_map = load_mitre(es)

    log.info("Démarrage de la corrélation NVD + CISA KEV + MITRE...")

    resp = es.search(
        index="vulnerabilities-nvd",
        body={"query": {"match_all": {}}, "size": 10000},
        scroll="2m"
    )
    scroll_id = resp["_scroll_id"]
    hits      = resp["hits"]["hits"]
    total     = resp["hits"]["total"]["value"]
    log.info(f"CVE à corréler : {total}")

    docs_to_index = []

    while hits:
        for hit in hits:
            src    = hit["_source"]
            cve_id = src.get("cve_id", "")

            # Étape 1 : Vérifier si le CVE est dans CISA KEV
            kev_data           = kev_map.get(cve_id, {})
            actively_exploited = kev_data.get("actively_exploited", False)
            ransomware_related = kev_data.get("ransomware_related", False)
            required_action    = kev_data.get("required_action", "")
            due_date           = kev_data.get("due_date", None)

            # Étape 2 : Trouver les tactiques MITRE via le CWE
            cwe_list = src.get("cwe", [])
            mitre_techniques, mitre_tactics, mitre_names = get_mitre_for_cve(
                cwe_list, mitre_map
            )

            # Étape 3 : Calculer le score de priorité
            priority_score, priority_level = compute_priority(
                src.get("cvss_score"),
                actively_exploited,
                ransomware_related,
                src.get("patch_available", False)
            )

            # Étape 4 : Générer la recommandation
            doc = {
                "cve_id":             cve_id,
                "description":        src.get("description", ""),
                "published":          src.get("published"),
                "cvss_score":         src.get("cvss_score"),
                "cvss_severity":      src.get("cvss_severity"),
                "cvss_vector":        src.get("cvss_vector"),
                "cwe":                cwe_list,
                "affected_products":  src.get("affected_products", []),
                "vendor":             src.get("vendor", []),
                "patch_available":    src.get("patch_available", False),
                "actively_exploited": actively_exploited,
                "ransomware_related": ransomware_related,
                "required_action":    required_action,
                "due_date":           due_date,
                "mitre_techniques":   mitre_techniques,
                "mitre_tactics":      mitre_tactics,
                "mitre_names":        mitre_names,
                "priority_score":     priority_score,
                "priority_level":     priority_level,
                "recommendation_short": generate_recommendation({
                    "actively_exploited": actively_exploited,
                    "ransomware_related": ransomware_related,
                    "patch_available":    src.get("patch_available", False),
                    "due_date":           due_date,
                    "required_action":    required_action,
                    "cvss_severity":      src.get("cvss_severity")
                })[:150],
                "recommendation":     generate_recommendation({
                    "actively_exploited": actively_exploited,
                    "ransomware_related": ransomware_related,
                    "patch_available":    src.get("patch_available", False),
                    "due_date":           due_date,
                    "required_action":    required_action,
                    "cvss_severity":      src.get("cvss_severity")
                }),
                "correlated_at": datetime.now(timezone.utc).isoformat(),
                "source":        "CORRELATED"
            }
            docs_to_index.append({"_id": cve_id, **doc})

        resp      = es.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits      = resp["hits"]["hits"]

    es.clear_scroll(scroll_id=scroll_id)

    # Étape 5 : Indexation bulk dans threats-correlated
    actions = [
        {
            "_op_type": "index",
            "_index":   INDEX_OUT,
            "_id":      doc["_id"],
            "_source":  {k: v for k, v in doc.items() if k != "_id"}
        }
        for doc in docs_to_index
    ]
    success, errors = helpers.bulk(es, actions, raise_on_error=False)
    log.info(f"Corrélations indexées : {success}")
    if errors:
        log.error(f"Erreurs : {len(errors)}")

    return len(docs_to_index)

# ── Point d'entrée ─────────────────────────────────────────────
def run():
    log.info("=== Démarrage moteur de corrélation ===")
    start = time.time()

    es = get_es_client()
    if not es.ping():
        log.error("Elasticsearch inaccessible. Abandon.")
        return

    create_index(es)
    total = correlate(es)

    duration = round(time.time() - start, 2)
    log.info(f"=== Corrélation terminée en {duration}s — {total} menaces corrélées ===")

if __name__ == "__main__":
    run()
