import logging
import os
import re
import time
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────
ES_HOST       = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER       = os.getenv("ES_USER", "elastic")
ES_PASSWORD   = os.getenv("ES_PASSWORD", "elastic123")
INDEX_IN      = "syslog-metasploitable-*"
INDEX_OUT     = "security-alerts"
POLL_INTERVAL = 30  # secondes entre chaque scan
CHECKPOINT_FILE = "logs/enricher_checkpoint.txt"

# ── Logging ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/enricher.log"),
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

# ── Détection automatique du service depuis le message ─────────
SERVICE_PATTERNS = [
    (r'\bsshd?\b|\bopenssh\b|\bssh2?\b',              "openssh"),
    (r'\bvsftpd\b|\bproftpd\b|\bpure-ftpd\b|\bftp\b', "ftp"),
    (r'\bhttpd\b|\bapache\b|\bnginx\b|\bhttp\b',       "apache http server"),
    (r'\bmysql\b|\bmariadb\b|\bmysqld\b',              "mysql"),
    (r'\bsmbd?\b|\bsamba\b|\bnmbd\b|\bsmb\b',          "samba"),
    (r'\bpostfix\b|\bsmtp\b|\bsendmail\b|\bdovecot\b', "postfix"),
    (r'\bphp\b|\bphp-fpm\b|\bphp-cgi\b',              "php"),
    (r'\btomcat\b|\bcatalina\b',                        "apache tomcat"),
    (r'\bpostgres\b|\bpostgresql\b',                   "postgresql"),
    (r'\btelnetd?\b',                                   "telnet"),
    (r'\bsnmpd?\b',                                     "snmp"),
    (r'\brdp\b|\bxrdp\b|\bms-wbt-server\b',            "rdp"),
]

def detect_service(message: str) -> str:
    msg_lower = message.lower()
    for pattern, service in SERVICE_PATTERNS:
        if re.search(pattern, msg_lower):
            return service
    prog_match = re.search(r'\w+\[\d+\]:', message)
    if prog_match:
        return prog_match.group(0).split('[')[0].lower()
    return "unknown"

# ── Extraction de l'IP source ──────────────────────────────────
def extract_source_ip(message: str) -> str | None:
    m = re.search(r'from (\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        return m.group(1)
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        return m.group(1)
    return None

# ── AMÉLIORATION 2 : Mapping MITRE direct par type d'attaque ──
ATTACK_TO_MITRE = {
    "SSH Brute Force":              ("T1110.001", "Credential Access"),
    "SSH Invalid User Enumeration": ("T1087",     "Discovery"),
    "SSH Successful Login":         ("T1078",     "Defense Evasion"),
    "Brute Force Login":            ("T1110",     "Credential Access"),
    "User Enumeration":             ("T1087",     "Discovery"),
    "Port Scan / Reconnaissance":   ("T1046",     "Discovery"),
    "SQL Injection Attempt":        ("T1190",     "Initial Access"),
    "Directory Traversal":          ("T1083",     "Discovery"),
    "Reverse Shell Attempt":        ("T1059",     "Execution"),
    "Privilege Escalation Attempt": ("T1068",     "Privilege Escalation"),
    "Metasploit Exploit":           ("T1190",     "Initial Access"),
    "Successful Authentication":    ("T1078",     "Defense Evasion"),
    "Connection Scan":              ("T1046",     "Discovery"),
    "Exploitation Attempt":         ("T1203",     "Execution"),
    "Security Event":               ("T1082",     "Discovery"),
}

# ── AMÉLIORATION 1 : Détection complète des attaques ──────────
def detect_attack_type(message: str, tags: list) -> str:
    msg_lower = message.lower()

    # Tags Logstash en priorité
    if "ssh_failed_login" in tags:
        return "SSH Brute Force"
    if "ssh_invalid_user" in tags:
        return "SSH Invalid User Enumeration"
    if "ssh_success_login" in tags:
        return "SSH Successful Login"

    # Attaques réseau / reconnaissance
    if "port scan" in msg_lower or "nmap" in msg_lower or "syn scan" in msg_lower:
        return "Port Scan / Reconnaissance"

    # Injection SQL
    if "union select" in msg_lower or "sql" in msg_lower and "inject" in msg_lower:
        return "SQL Injection Attempt"

    # Directory Traversal
    if "../" in msg_lower or "directory traversal" in msg_lower or "path traversal" in msg_lower:
        return "Directory Traversal"

    # Reverse Shell
    if "reverse shell" in msg_lower or "/bin/sh" in msg_lower or "/bin/bash" in msg_lower:
        return "Reverse Shell Attempt"

    # Metasploit / Meterpreter
    if "meterpreter" in msg_lower or "metasploit" in msg_lower or "msf" in msg_lower:
        return "Metasploit Exploit"

    # Privilege Escalation
    if "sudo" in msg_lower and ("incorrect" in msg_lower or "failed" in msg_lower or "3 incorrect" in msg_lower):
        return "Privilege Escalation Attempt"

    # Patterns généraux
    if "failed password" in msg_lower or "authentication failure" in msg_lower:
        return "Brute Force Login"
    if "invalid user" in msg_lower or "illegal user" in msg_lower:
        return "User Enumeration"
    if "accepted password" in msg_lower or "session opened" in msg_lower:
        return "Successful Authentication"
    if "refused connect" in msg_lower or "connection refused" in msg_lower:
        return "Connection Scan"
    if "segfault" in msg_lower or "buffer overflow" in msg_lower:
        return "Exploitation Attempt"
    if "sudo" in msg_lower:
        return "Privilege Escalation Attempt"

    return "Security Event"

# ── AMÉLIORATION 3 : Checkpoint (sauvegarde du dernier timestamp) ─
def save_checkpoint(ts: str):
    try:
        with open(CHECKPOINT_FILE, "w") as f:
            f.write(ts)
        log.debug(f"Checkpoint sauvegardé : {ts}")
    except Exception as e:
        log.warning(f"Impossible de sauvegarder le checkpoint : {e}")

def load_checkpoint() -> str:
    try:
        with open(CHECKPOINT_FILE) as f:
            ts = f.read().strip()
            if ts:
                log.info(f"Reprise depuis le checkpoint : {ts}")
                return ts
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning(f"Erreur lecture checkpoint : {e}")
    # Pas de checkpoint → démarrer depuis maintenant
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    log.info(f"Aucun checkpoint trouvé — démarrage depuis : {ts}")
    return ts

# ── Recherche des CVE dans threats-correlated ─────────────────
def find_related_cves(es, service: str, message: str) -> list:
    stopwords = {"the","a","an","is","in","on","at","to","for",
                 "of","and","or","from","with","by","mar","apr",
                 "jan","feb","jun","jul","aug","sep","oct","nov","dec"}
    words    = re.findall(r'[a-zA-Z]{4,}', message.lower())
    keywords = [w for w in words if w not in stopwords][:5]

    should = [
        {"match_phrase": {"description":      service}},
        {"match":        {"vendor":           {"query": service, "boost": 3}}},
        {"match":        {"affected_products": {"query": service, "boost": 2}}},
    ]
    for kw in keywords:
        should.append({"match": {"description": {"query": kw, "boost": 1}}})

    try:
        resp = es.search(
            index="threats-correlated",
            body={
                "query": {
                    "bool": {
                        "should": should,
                        "minimum_should_match": 1
                    }
                },
                "sort": [
                    {"priority_score":     {"order": "desc"}},
                    {"actively_exploited": {"order": "desc"}},
                    {"cvss_score":         {"order": "desc"}}
                ],
                "size": 5,
                "_source": [
                    "cve_id", "cvss_score", "cvss_severity",
                    "priority_score", "priority_level",
                    "actively_exploited", "ransomware_related",
                    "patch_available", "recommendation",
                    "mitre_techniques", "mitre_tactics",
                    "vendor", "affected_products", "description"
                ]
            }
        )
        return resp["hits"]["hits"]
    except Exception as e:
        log.error(f"Erreur recherche CVE pour service '{service}': {e}")
        return []

# ── Création de l'index security-alerts ───────────────────────
def create_index(es):
    mapping = {
        "mappings": {
            "properties": {
                "attack_type":         {"type": "keyword"},
                "service_attacked":    {"type": "keyword"},
                "source_ip":           {"type": "ip"},
                "target_host":         {"type": "keyword"},
                "attack_message":      {"type": "text"},
                "attack_timestamp":    {"type": "date"},
                "tags":                {"type": "keyword"},
                "related_cves":        {"type": "keyword"},
                "cve_count":           {"type": "integer"},
                "max_cvss_score":      {"type": "float"},
                "max_priority_score":  {"type": "float"},
                "priority_level":      {"type": "keyword"},
                "mitre_techniques":    {"type": "keyword"},
                "mitre_tactics":       {"type": "keyword"},
                "recommendation":      {"type": "text"},
                "patch_available":     {"type": "boolean"},
                "actively_exploited":  {"type": "boolean"},
                "ransomware_related":  {"type": "boolean"},
                "enriched_at":         {"type": "date"},
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

# ── Scan et enrichissement des logs ───────────────────────────
def enrich_logs(es, last_timestamp: str) -> tuple[int, str]:
    resp = es.search(
        index=INDEX_IN,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gt": last_timestamp}}}
                    ],
                    "should": [
                        {"term":  {"tags": "security_alert"}},
                        {"term":  {"tags": "ssh_failed_login"}},
                        {"term":  {"tags": "ssh_invalid_user"}},
                        {"term":  {"tags": "ssh_success_login"}},
                        {"match": {"message": "failed"}},
                        {"match": {"message": "error"}},
                        {"match": {"message": "refused"}},
                        {"match": {"message": "invalid"}},
                        {"match": {"message": "authentication failure"}},
                        {"match": {"message": "segfault"}},
                        {"match": {"message": "exploit"}},
                        {"match": {"message": "nmap"}},
                        {"match": {"message": "meterpreter"}},
                        {"match": {"message": "select"}},
                        {"match": {"message": "traversal"}},
                        {"match": {"message": "sudo"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 500
        }
    )

    hits = resp["hits"]["hits"]
    if not hits:
        return 0, last_timestamp

    log.info(f"Nouveaux événements à enrichir : {len(hits)}")
    enriched_docs = []
    new_timestamp = last_timestamp

    for hit in hits:
        src     = hit["_source"]
        message = src.get("message", "")
        tags    = src.get("tags", [])
        ts      = src.get("@timestamp", "")

        if ts > new_timestamp:
            new_timestamp = ts

        service     = detect_service(message)
        attack_type = detect_attack_type(message, tags)
        source_ip   = extract_source_ip(message)
        hostname    = (src.get("host") or {}).get("name", "metasploitable3")

        # ── AMÉLIORATION 2 : Mapping MITRE direct par type d'attaque ──
        mitre_direct = ATTACK_TO_MITRE.get(attack_type)
        mitre_techniques = [mitre_direct[0]] if mitre_direct else []
        mitre_tactics    = [mitre_direct[1]] if mitre_direct else []

        # Enrichissement CVE depuis threats-correlated
        cve_hits = find_related_cves(es, service, message)

        related_cves       = []
        max_cvss           = 0.0
        max_priority       = 0.0
        priority_level     = "LOW"
        recommendation     = ""
        patch_available    = False
        actively_exploited = False
        ransomware_related = False

        for cve_hit in cve_hits:
            c      = cve_hit["_source"]
            cve_id = c.get("cve_id", "")
            if cve_id:
                related_cves.append(cve_id)

            cvss = c.get("cvss_score") or 0
            if cvss > max_cvss:
                max_cvss = cvss

            prio = c.get("priority_score") or 0
            if prio > max_priority:
                max_priority   = prio
                priority_level = c.get("priority_level", "LOW")
                recommendation = c.get("recommendation", "")

            if c.get("patch_available"):    patch_available    = True
            if c.get("actively_exploited"): actively_exploited = True
            if c.get("ransomware_related"): ransomware_related = True

            # Fusionner les techniques MITRE des CVEs (sans doublons)
            for t in c.get("mitre_techniques", []):
                if t not in mitre_techniques:
                    mitre_techniques.append(t)
            for t in c.get("mitre_tactics", []):
                if t not in mitre_tactics:
                    mitre_tactics.append(t)

        if not recommendation:
            recommendation = (
                f"Service {service.upper()} : événement de sécurité détecté. "
                f"Type : {attack_type}. "
                f"Surveiller les connexions depuis {source_ip or 'IP inconnue'}."
            )

        enriched_docs.append({
            "attack_type":        attack_type,
            "service_attacked":   service,
            "source_ip":          source_ip,
            "target_host":        hostname,
            "attack_message":     message[:500],
            "attack_timestamp":   ts,
            "tags":               tags,
            "related_cves":       related_cves[:5],
            "cve_count":          len(related_cves),
            "max_cvss_score":     round(max_cvss, 2),
            "max_priority_score": round(max_priority, 2),
            "priority_level":     priority_level,
            "mitre_techniques":   mitre_techniques[:5],
            "mitre_tactics":      mitre_tactics[:3],
            "recommendation":     recommendation,
            "patch_available":    patch_available,
            "actively_exploited": actively_exploited,
            "ransomware_related": ransomware_related,
            "enriched_at":        datetime.now(timezone.utc).isoformat(),
            "source":             "ENRICHED"
        })

    if enriched_docs:
        actions = [
            {"_op_type": "index", "_index": INDEX_OUT, "_source": doc}
            for doc in enriched_docs
        ]
        success, errors = helpers.bulk(es, actions, raise_on_error=False)
        log.info(f"Alertes enrichies indexées : {success}")
        if errors:
            log.warning(f"Erreurs d'indexation : {len(errors)}")

    return len(enriched_docs), new_timestamp

# ── Daemon principal ───────────────────────────────────────────
def run():
    log.info("=== Démarrage du daemon d'enrichissement universel ===")
    es = get_es_client()

    if not es.ping():
        log.error("Elasticsearch inaccessible. Abandon.")
        return

    create_index(es)

    # AMÉLIORATION 3 : Charger le checkpoint (reprend là où on s'est arrêté)
    last_timestamp = load_checkpoint()
    log.info(f"Surveillance depuis : {last_timestamp}")
    log.info(f"Intervalle de scan  : {POLL_INTERVAL} secondes")

    while True:
        try:
            count, last_timestamp = enrich_logs(es, last_timestamp)
            # Sauvegarder le checkpoint après chaque cycle
            save_checkpoint(last_timestamp)
            if count > 0:
                log.info(f"{count} alertes enrichies — prochain scan dans {POLL_INTERVAL}s")
            else:
                log.debug(f"Aucun nouvel événement — prochain scan dans {POLL_INTERVAL}s")
        except Exception as e:
            log.error(f"Erreur dans le cycle d'enrichissement : {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
