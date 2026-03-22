# Note mémoire

## Thème : Implémentation d'un système intelligent de gestion des menaces et vulnérabilités basé sur la suite ELK

Ici se trouve les note de mon avancé par rapport à mon mémoire. Pour l'instant j'ai commencer en local avec ma vm ubuntu server.

### architecture du project
Pour commencé j'ai crée un dossier appelé **memoire_ELK** donc l'architecture visuel est celle-ci:

```zsh
memoire_ELK/
├── docker-compose.yml       ← démarre ES + Kibana + Logstash
├── logstash/
│   ├── config/
│   │   └── logstash.yml     ← paramètres Logstash
│   └── pipeline/
│       └── logstash.conf    ← pipeline de traitement
├── collectors/
│   ├── collector_nvd.py     ← collecte NVD
│   ├── collector_cisa.py    ← collecte CISA KEV
│   ├── collector_mitre.py   ← collecte MITRE ATT&CK
│   ├── correlator.py        ← corrélation
│   ├── api.py               ← API REST
│   ├── .env                 ← clés et mots de passe
│   └── logs/                ← journaux
└── certs/                   ← certificats TLS
```

**memoire_ELK/ ** Dossier racine du projet
C'est le dossier principal qui contient tout le projet. On y trouvera aussi le fichier docker-compose.yml qui définit comment démarrer les conteneurs ELK.

**memoire_ELK/logstash/config/** Configuration de Logstash
Contient le fichier logstash.yml qui définit les paramètres généraux de Logstash comme l'adresse d'écoute et le monitoring.

**memoire_ELK/logstash/pipeline/** Pipeline de traitement
Contient le fichier logstash.conf qui définit comment Logstash reçoit les données, les transforme et les envoie vers Elasticsearch. C'est le cerveau de Logstash.

**memoire_ELK/collectors/** Scripts Python de collecte
Contient tous nos scripts Python :

collector_nvd.py → collecte les CVE depuis NVD

collector_cisa.py → collecte les exploits depuis CISA KEV

collector_mitre.py → collecte les techniques depuis MITRE ATT&CK

correlator.py → croise et enrichit les données

api.py → expose les données via une API REST

**memoire_ELK/collectors/logs/** Journaux d'exécution
Contient les fichiers .log générés automatiquement à chaque exécution des scripts. Permet de diagnostiquer les problèmes et de prouver que les collectes ont bien eu lieu.

**memoire_ELK/certs/** Certificats TLS
Contiendra les certificats SSL/TLS pour chiffrer les communications entre les composants de la stack ELK.

### Docker-compose

Parfait ! Le fichier est créé. Laissez-moi vous expliquer chaque section :

---

**`image`** — L'image Docker à télécharger
```yaml
image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
```
C'est comme dire "télécharge la version 8.13.0 d'Elasticsearch depuis le serveur officiel d'Elastic". On fixe la version pour éviter les surprises.

---

**`container_name`** — Le nom du conteneur
```yaml
container_name: elasticsearch
```
Permet de référencer le conteneur par son nom au lieu de son ID. C'est pourquoi Kibana peut écrire `http://elasticsearch:9200` — Docker résout automatiquement ce nom.

---

**`environment`** — Variables d'environnement
```yaml
- discovery.type=single-node   # Un seul nœud (pas de cluster)
- xpack.security.enabled=false # Sécurité désactivée pour l'instant
- ES_JAVA_OPTS=-Xms1g -Xmx1g  # RAM allouée à Java : min 1GB, max 1GB
```

---

**`ports`** — Exposition des ports
```yaml
- "9200:9200"  # port_hôte:port_conteneur
```
Le port 9200 du conteneur devient accessible sur le port 9200 de votre serveur.

---

**`volumes`** — Persistance des données
```yaml
- es_data:/usr/share/elasticsearch/data
```
Sans volume, toutes les données sont perdues au redémarrage. `es_data` est un volume Docker nommé qui persiste même si le conteneur s'arrête.

---

**`healthcheck`** — Vérification de santé
```yaml
test: curl -s http://localhost:9200/_cluster/health | grep -q 'green\|yellow'
interval: 15s   # vérifie toutes les 15 secondes
retries: 10     # essaie 10 fois avant de déclarer le service mort
```
Kibana et Logstash attendent qu'Elasticsearch soit vraiment prêt avant de démarrer — c'est le `depends_on: condition: service_healthy`.

---

**`networks`** — Réseau interne
```yaml
networks:
  elk-net:
    driver: bridge
```
Crée un réseau privé entre les 3 conteneurs. Ils peuvent se parler entre eux mais sont isolés du reste.

---

**`:ro` dans les volumes Logstash**
```yaml
- ./logstash/pipeline:/usr/share/logstash/pipeline:ro
```
`ro` = read-only. Le conteneur peut lire les fichiers mais pas les modifier — bonne pratique de sécurité.

---

### Logstash (explication brève)


Logstash est un pipeline de traitement de données open source qui permet d'ingérer des données provenant de différentes sources, de les transformer et de les envoyer vers d'autres destinations. Il permet également de convertir des données non structurées en données structurées, de les enrichir, de les transformer et de les envoyer vers de multiples destinations(ex: elasticsearch). Logstash peut être utilisé pour :

**analyser des données et des événements structurés et non structurés ;
se connecter à différents types de sources d'entrée et de sortie, comme des fichiers, Beats, Kafka, des bases de données, Elasticsearch, etc. ; transformer des données et les stocker pour analyse ; récupérer des données depuis différentes sources, telles que des bases de données, des fichiers CSV et des fichiers.**

Les trois composants du pipeline Logstash sont **Input**, **Filter** et **Output**. Voici chacun en détail :

---

**1. INPUT — Recevoir les données**

C'est la porte d'entrée de Logstash. Il écoute et collecte les données depuis les sources. Dans le cas de ton projet sécurité, les inputs typiques sont :

- `file` — lit les fichiers de logs (firewall, système)
- `beats` — reçoit les données des agents Filebeat/Winlogbeat déployés sur les machines
- `syslog` — écoute les journaux réseau sur le port 514
- `tcp/udp` — capte les flux réseau bruts
- `http` — reçoit des données via des APIs

Un exemple concret de configuration :
```
input {
  beats { port => 5044 }
  syslog { port => 514 }
}
```

---

**2. FILTER — Transformer les données**

C'est le cerveau du pipeline, l'étape la plus importante. Les données brutes arrivent illisibles et désordonnées, les filtres les structurent et les enrichissent. Les principaux filtres :

- `grok` — découpe une ligne de log brute en champs structurés (source_ip, action, timestamp...) via des expressions régulières
- `geoip` — ajoute la localisation géographique d'une adresse IP (pays, coordonnées)
- `mutate` — renomme, supprime ou modifie des champs
- `translate` — enrichit avec des données externes (CVE, IOC, réputation IP)
- `date` — normalise les formats de date
- `drop` — supprime les événements inutiles pour réduire le bruit

Exemple :
```
filter {
  grok {
    match => { "message" => "%{SYSLOGLINE}" }
  }
  geoip {
    source => "src_ip"
  }
}
```

---

**3. OUTPUT — Envoyer les données**

C'est la sortie du pipeline. Une fois transformées, les données sont acheminées vers une ou plusieurs destinations simultanément :

- `elasticsearch` — destination principale, indexation pour Kibana
- `kafka` — mise en file d'attente pour traitement asynchrone
- `file` — sauvegarde locale
- `stdout` — affichage console (utile en phase de débogage)

Exemple :
```
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }
}
```

---

**En résumé visuel :**

```
[Sources]  →  INPUT  →  FILTER  →  OUTPUT  →  [Elasticsearch]
              (collecter)  (transformer)  (envoyer)
```

Le pipeline est séquentiel : chaque événement passe obligatoirement par ces 3 étapes dans l'ordre. C'est ce qui fait la puissance de Logstash — on peut chaîner autant de filtres que nécessaire entre l'entrée et la sortie.


## Configuration de logstash
### logstash.yml
Commençons par le fichier `logstash.yml` — la configuration principale de Logstash.

**C'est quoi ce fichier ?**
C'est le fichier de paramètres globaux de Logstash. Il définit comment Logstash se comporte en général — pas ce qu'il fait avec les données (ça c'est le pipeline), mais comment il tourne.

```bash
cat > /home/ubuntu-server/memoire_ELK/logstash/config/logstash.yml << 'EOF'
http.host: "0.0.0.0"
xpack.monitoring.enabled: false
EOF

cat /home/ubuntu-server/memoire_ELK/logstash/config/logstash.yml
```

**Explication des deux lignes :**

`http.host: "0.0.0.0"` → Logstash écoute sur toutes les interfaces réseau. Sans ça, l'API de monitoring sur le port 9600 ne serait pas accessible depuis l'extérieur du conteneur.

`xpack.monitoring.enabled: false` → Désactive l'envoi de métriques de monitoring vers Elasticsearch. On n'en a pas besoin pour notre projet et ça allège le système.

### logstash.conf

Créons le fichier `logstash.conf` — le pipeline de traitement.

**C'est quoi ce fichier ?**
C'est le cerveau de Logstash. Il définit 3 choses dans cet ordre :

```
INPUT   → d'où viennent les données ?
FILTER  → comment les transformer/enrichir ?
OUTPUT  → où les envoyer ?
```

```bash
cat > /home/ubuntu-server/memoire_ELK/logstash/pipeline/logstash.conf << 'EOF'
input {
  beats {
    port => 5044
  }
  udp {
    port => 5514
    codec => plain
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => {
        "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}"
      }
    }
    date {
      match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
      target => "@timestamp"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
}
EOF

cat /home/ubuntu-server/memoire_ELK/logstash/pipeline/logstash.conf
```

### explication

Parfait ! Le fichier est créé. Voici l'explication détaillée de chaque bloc :

---

**BLOC INPUT — D'où viennent les données ?**

```
beats {
  port => 5044
}
```
Écoute sur le port 5044 les données envoyées par **Filebeat** — un agent léger installé sur des machines pour collecter leurs logs. Par exemple si vous installez Filebeat sur un serveur Windows, il enverrait ses logs vers ce port.

```
udp {
  port => 5514
  codec => plain
  type => "syslog"
}
```
Écoute sur le port 5514 en **UDP** les messages Syslog. Le protocole Syslog est utilisé par les équipements réseau (routeurs, pare-feux, switches) pour envoyer leurs logs. `type => "syslog"` étiquette ces messages pour le filtre.

---

**BLOC FILTER — Comment transformer les données ?**

```
if [type] == "syslog" {
```
On applique le filtre uniquement aux messages de type syslog — pas aux logs Beats.

```
grok {
  match => {
    "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} ..."
  }
}
```
**Grok** est un parser qui décompose une ligne de texte brut en champs structurés. Par exemple :

```
Avant grok (texte brut) :
"Mar 20 19:00:01 ubuntu-server sshd[1234]: Failed password for root"

Après grok (structuré) :
syslog_timestamp : "Mar 20 19:00:01"
syslog_hostname  : "ubuntu-server"
syslog_program   : "sshd"
syslog_pid       : "1234"
syslog_message   : "Failed password for root"
```

C'est très utile pour détecter des tentatives d'intrusion SSH par exemple.

```
date {
  match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
  target => "@timestamp"
}
```
Convertit la date du log en vrai champ de date Elasticsearch. Sans ça, Kibana ne saurait pas quand l'événement s'est produit.

---

**BLOC OUTPUT — Où envoyer les données ?**

```
elasticsearch {
  hosts => ["http://elasticsearch:9200"]
  index => "logstash-%{+YYYY.MM.dd}"
}
```
Envoie tout vers Elasticsearch. L'index est nommé automatiquement avec la date — par exemple `logstash-2026.03.20`. Ça crée un index par jour ce qui facilite la gestion et la suppression des vieilles données.

---

**Résumé du flux complet :**

```
Filebeat (port 5044)          Syslog UDP (port 5514)
        ↓                              ↓
        └──────────── INPUT ───────────┘
                          ↓
                       FILTER
                 (grok parse le syslog)
                          ↓
                       OUTPUT
              → elasticsearch:9200
              → index logstash-2026.03.20
```

## Démarrage du stack ELK
véririfier bien si vous êtes dans le dossier oui il y'a votre fichier **docker-compose.yml** et ce qui va se passer :

saisissez cette commande :
```
docker compose up -d 
```

1. Docker télécharge les 3 images (ES, Kibana, Logstash)
2. Elasticsearch démarre en premier
3. Le healthcheck vérifie qu'ES est prêt
4. Kibana et Logstash démarrent ensuite

 <img width="1918" height="95" alt="image" src="https://github.com/user-attachments/assets/63a1658a-08c6-4b9e-8f00-421f87a2a823" />

```
# Vérifier l'état des conteneurs
docker ps | grep -E "elasticsearch|kibana|logstash"

# Tester Elasticsearch
curl http://localhost:9200

# Tester Kibana
curl -s http://localhost:5601/api/status | python3 -m json.tool | grep -E "level|summary" | head -3
 ``` 
La stack ELK de base est complète et fonctionnelle. Passons maintenant aux collecteurs Python.

### Construction des API 
pour des raisons de lisibilité les code python des différentes seront ajouter dans une section bien précise de ce dépôt mais les explications seront données ici.

**Installer les dépendances Python**

```bash
# Installer les bibliothèques nécessaires
pip3 install requests elasticsearch python-dotenv fastapi uvicorn --break-system-packages

# Vérifier l'installation
pip3 show elasticsearch | grep Version
pip3 show fastapi | grep Version
```

**Pourquoi ces bibliothèques ?**
- `requests` → pour appeler les APIs NVD, CISA, MITRE
- `elasticsearch` → pour communiquer avec Elasticsearch depuis Python
- `python-dotenv` → pour lire le fichier `.env` (clés API, mots de passe)
- `fastapi` → pour créer l'API de recherche
- `uvicorn` → pour faire tourner FastAPI

Maintenant créons le fichier `.env` qui contient les variables de configuration :

```bash
cat > /home/ubuntu-server/memoire_ELK/collectors/.env << EOF
ES_HOST=http://localhost:9200
NVD_API_KEY=153e15f0-888a-416f-92a2-878281e1643a
EOF

cat /home/ubuntu-server/memoire_ELK/collectors/.env
```

**Pourquoi un fichier `.env` ?**

C'est une bonne pratique de sécurité — on ne met jamais les clés API directement dans le code. Si vous partagez votre code sur GitHub par exemple, la clé NVD ne sera pas exposée car `.env` est toujours ajouté au `.gitignore`.

```bash
# Créer le .gitignore
echo ".env" > /home/ubuntu-server/memoire_ELK/.gitignore
```

Dans un environnement de production, les credentials seraient gérés via un outil de gestion de secrets tel que HashiCorp Vault, remplaçant le fichier .env utilisé dans cette phase de développement.

### collector_nvd.py
Le script interroge l'API NVD toutes les X minutes, récupère les nouvelles vulnérabilités publiées, les nettoie et les stocke dans Elasticsearch pour qu'elles soient disponibles dans le dashboard Kibana.
Lançons le test :

```bash
cd /home/ubuntu-server/memoire_ELK/collectors
python3 collector_nvd.py 7
```

**Ce qui va se passer :**
1. Le script se connecte à Elasticsearch
2. Crée l'index `vulnerabilities-nvd`
3. Interroge l'API NVD pour les 7 derniers jours
4. Normalise chaque CVE
5. Indexe tout dans Elasticsearch
   
<img width="908" height="251" alt="image" src="https://github.com/user-attachments/assets/7a0014cb-2e6c-47e6-89c9-5ba14c217e09" />

### collector_cisa.py

Le catalogue **CISA KEV (Known Exploited Vulnerabilities)** est une base de données publique de la Cybersecurity and Infrastructure Security Agency (CISA) répertoriant les failles de sécurité logicielles activement exploitées par des cyberattaquants. Il sert d'outil de référence essentiel pour les entreprises, leur permettant de prioriser la correction des vulnérabilités les plus dangereuses.

Points clés du catalogue CISA KEV :
Objectif : Identifier les vulnérabilités qui ont déjà été utilisées dans des attaques réelles, aidant ainsi à prioriser les correctifs les plus critiques.

Contenu : Répertorie les failles par fournisseur, produit, date et description, avec des mesures correctives.

Utilisation : Les équipes de sécurité (SOC) utilisent ces données pour scanner leurs systèmes, et des formats JSON/CSV permettent une automatisation.

Importance : Essentiel pour la gestion proactive des risques, il aide à renforcer la posture de sécurité contre les menaces actives

bon nous avons eu à lancer notre script de collecte donc le resultat est( le script est dans le dépot):

<img width="908" height="251" alt="image" src="https://github.com/user-attachments/assets/db0b95cc-1142-4961-8a91-743efca2d242" />

### collector_mitre.py

pour voir les tactique et technique d'attaque 

vérifions si nos index ont bien été enregistrés 
```curl -s http://localhost:9200/_cat/indices?v```

**note**
La Common Weakness Enumeration (CWE) est un système de classification communautaire standardisé, maintenu par The MITRE Corporation, répertoriant les faiblesses sous-jacentes de sécurité dans les logiciels et le matériel. Elle aide les développeurs à identifier, corriger et prévenir les défauts de conception ou de code avant qu'ils ne deviennent des vulnérabilités exploitables (CVE)

### script qui permet le lancement des collecteur
Passons maintenant au **script maître** qui orchestre tout automatiquement :

```bash
cat > /home/ubuntu-server/memoire_ELK/collectors/run_all.sh << 'EOF'
#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Script maître — lance tous les collecteurs + corrélation
# Exécuté automatiquement par cron toutes les 30 minutes
# ─────────────────────────────────────────────────────────────

cd /home/ubuntu-server/memoire_ELK/collectors

echo "=== $(date) - Démarrage collecte ===" >> logs/cron.log

# 1. Collecter les nouveaux CVE (7 derniers jours)
echo "--- NVD ---" >> logs/cron.log
python3 collector_nvd.py 7 >> logs/cron.log 2>&1

# 2. Mettre à jour les exploits actifs CISA KEV
echo "--- CISA KEV ---" >> logs/cron.log
python3 collector_cisa.py >> logs/cron.log 2>&1

# 3. Relancer la corrélation
echo "--- CORRÉLATION ---" >> logs/cron.log
python3 correlator.py >> logs/cron.log 2>&1

echo "=== $(date) - Collecte terminée ===" >> logs/cron.log
EOF

chmod +x /home/ubuntu-server/memoire_ELK/collectors/run_all.sh

# Tester le script
/home/ubuntu-server/memoire_ELK/collectors/run_all.sh

# Voir les logs
tail -20 /home/ubuntu-server/memoire_ELK/collectors/logs/cron.log
```

**Le script maître fonctionne parfaitement !**

Remarquez que la base a grandi  **1431 CVE** au lieu de 1381 — le cron a déjà collecté de nouveaux CVE pendant qu'on travaillait !

Maintenant configurons l'**automatisation cron** :

```bash
crontab -e
```

Choisissez **nano (option 1)** et ajoutez ces lignes à la fin du fichier :

```bash
# NVD + CISA + corrélation toutes les 30 minutes
*/30 * * * * /home/ubuntu-server/memoire_ELK/collectors/run_all.sh

# MITRE ATT&CK toutes les semaines (dimanche à 2h)
0 2 * * 0 cd /home/ubuntu-server/memoire_ELK/collectors && python3 collector_mitre.py >> logs/cron.log 2>&1
```

Sauvegardez avec `Ctrl+O` puis `Ctrl+X`.

<img width="1920" height="497" alt="image" src="https://github.com/user-attachments/assets/9ba2666d-5c86-49fa-af37-e327f213cdbf" />


**Pourquoi ces fréquences ?**

| Tâche | Fréquence | Raison |
|-------|-----------|--------|
| NVD + CISA + corrélation | 30 min | CVE publiés en continu |
| MITRE ATT&CK | Hebdomadaire | Framework stable, peu de changements |

Vérifiez que le cron est bien enregistré :

```bash
crontab -l
```

### API pour la recherche 
 L'API est une **couche d'abstraction** entre l'utilisateur et Elasticsearch.

Créons le fichier :

```bash
cat > /home/ubuntu-server/memoire_ELK/collectors/api.py << 'EOF'
from fastapi import FastAPI, Query
from elasticsearch import Elasticsearch
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────
# On lit l'adresse ES depuis le fichier .env
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
es      = Elasticsearch(ES_HOST)
app     = FastAPI(
    title="Threat Intelligence API",
    description="API de recherche intelligente des menaces et vulnérabilités",
    version="1.0.0"
)

# ── 1. Recherche full-text multicritères ──────────────────────
# Permet de chercher avec plusieurs filtres combinés
# ex: /search?q=cisco&severity=CRITICAL&exploited=true
@app.get("/search", summary="Recherche multicritères")
def search(
    q:         Optional[str]   = Query(None, description="Recherche full-text"),
    severity:  Optional[str]   = Query(None, description="CRITICAL/HIGH/MEDIUM/LOW"),
    vendor:    Optional[str]   = Query(None, description="Nom du vendeur"),
    exploited: Optional[bool]  = Query(None, description="Activement exploité"),
    cvss_min:  Optional[float] = Query(None, description="Score CVSS minimum"),
    size:      int             = Query(20,   description="Nombre de résultats"),
    page:      int             = Query(1,    description="Page")
):
    must   = []
    filter = []

    if q:
        must.append({"multi_match": {
            "query":  q,
            "fields": ["description", "cve_id", "vendor"]
        }})
    if severity:
        filter.append({"term": {"cvss_severity": severity.upper()}})
    if vendor:
        filter.append({"term": {"vendor": vendor.lower()}})
    if exploited is not None:
        filter.append({"term": {"actively_exploited": exploited}})
    if cvss_min is not None:
        filter.append({"range": {"cvss_score": {"gte": cvss_min}}})

    query = {"match_all": {}} if not must and not filter else {"bool": {"must": must, "filter": filter}}

    resp = es.search(
        index="threats-correlated",
        body={
            "query": query,
            "sort":  [{"priority_score": "desc"}, {"cvss_score": "desc"}],
            "from":  (page - 1) * size,
            "size":  size,
            "_source": [
                "cve_id", "cvss_score", "cvss_severity", "priority_score",
                "priority_level", "actively_exploited", "ransomware_related",
                "vendor", "description", "recommendation", "published"
            ]
        }
    )
    return {
        "total":   resp["hits"]["total"]["value"],
        "page":    page,
        "results": [h["_source"] for h in resp["hits"]["hits"]]
    }

# ── 2. Détail d'un CVE ────────────────────────────────────────
# Retourne toutes les informations sur un CVE spécifique
# ex: /cve/CVE-2026-1234
@app.get("/cve/{cve_id}", summary="Détail d'un CVE")
def get_cve(cve_id: str):
    try:
        resp = es.get(index="threats-correlated", id=cve_id.upper())
        return resp["_source"]
    except Exception:
        try:
            resp = es.get(index="vulnerabilities-nvd", id=cve_id.upper())
            return resp["_source"]
        except Exception:
            return {"error": f"{cve_id} non trouvé"}

# ── 3. CVE critiques ──────────────────────────────────────────
# Retourne les CVE avec priority_level = CRITICAL
# triés par score décroissant (les plus dangereux en premier)
@app.get("/critical", summary="CVE critiques")
def get_critical(size: int = Query(20)):
    resp = es.search(
        index="threats-correlated",
        body={
            "query": {"term": {"priority_level": "CRITICAL"}},
            "sort":  [{"priority_score": "desc"}],
            "size":  size,
            "_source": [
                "cve_id", "cvss_score", "priority_score",
                "actively_exploited", "ransomware_related",
                "recommendation", "published"
            ]
        }
    )
    return {
        "total":   resp["hits"]["total"]["value"],
        "results": [h["_source"] for h in resp["hits"]["hits"]]
    }

# ── 4. CVE activement exploités ───────────────────────────────
# Retourne les CVE confirmés dans CISA KEV
# Option : filtrer uniquement ceux liés à des ransomwares
@app.get("/exploited", summary="CVE activement exploités")
def get_exploited(ransomware: Optional[bool] = Query(None), size: int = Query(20)):
    f = [{"term": {"actively_exploited": True}}]
    if ransomware is not None:
        f.append({"term": {"ransomware_related": ransomware}})

    resp = es.search(
        index="threats-correlated",
        body={
            "query": {"bool": {"filter": f}},
            "sort":  [{"priority_score": "desc"}],
            "size":  size,
            "_source": [
                "cve_id", "cvss_score", "priority_score",
                "ransomware_related", "due_date",
                "recommendation", "published"
            ]
        }
    )
    return {
        "total":   resp["hits"]["total"]["value"],
        "results": [h["_source"] for h in resp["hits"]["hits"]]
    }

# ── 5. Statistiques globales ──────────────────────────────────
# Retourne un résumé chiffré de toute la base
# Utilisé par le dashboard Kibana pour les métriques
@app.get("/stats", summary="Statistiques globales")
def get_stats():
    resp = es.search(
        index="threats-correlated",
        body={
            "size": 0,
            "aggs": {
                "by_severity":     {"terms":  {"field": "cvss_severity"}},
                "by_priority":     {"terms":  {"field": "priority_level"}},
                "exploited_count": {"filter": {"term": {"actively_exploited": True}}},
                "ransomware_count":{"filter": {"term": {"ransomware_related": True}}},
                "avg_cvss":        {"avg":    {"field": "cvss_score"}},
                "patch_available": {"filter": {"term": {"patch_available": True}}}
            }
        }
    )
    aggs = resp["aggregations"]
    return {
        "total_cve":          resp["hits"]["total"]["value"],
        "actively_exploited": aggs["exploited_count"]["doc_count"],
        "ransomware_related": aggs["ransomware_count"]["doc_count"],
        "patch_available":    aggs["patch_available"]["doc_count"],
        "avg_cvss_score":     round(aggs["avg_cvss"]["value"] or 0, 2),
        "by_severity":        {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
        "by_priority":        {b["key"]: b["doc_count"] for b in aggs["by_priority"]["buckets"]}
    }

# ── 6. Health check ───────────────────────────────────────────
# Vérifie que l'API et Elasticsearch fonctionnent
# Utilisé pour le monitoring du service
@app.get("/health", summary="Vérification de santé")
def health():
    return {
        "status":          "ok",
        "elasticsearch":   es.ping(),
        "version":         "1.0.0"
    }
EOF

# Lancer l'API
cd /home/ubuntu-server/memoire_ELK/collectors
uvicorn api:app --host 0.0.0.0 --port 8001 --reload
```

🎉 **L'API fonctionne parfaitement !**

**Ce qu'on voit :**
- **1431 CVE** dans la base
- **141 CVE critiques** dont `CVE-2026-22557` avec CVSS **10.0** — le maximum !
- **732 CVE avec patch disponible**
- Score CVSS moyen : **6.62**
- Recommandations générées automatiquement ✅

Maintenant rendons l'API permanente avec un service systemd :

```bash
sudo bash -c 'cat > /etc/systemd/system/threat-api.service << EOF
[Unit]
Description=Threat Intelligence API
After=network.target

[Service]
User=ubuntu-server
WorkingDirectory=/home/ubuntu-server/memoire_ELK/collectors
EnvironmentFile=/home/ubuntu-server/memoire_ELK/collectors/.env
ExecStart=/usr/bin/python3 -m uvicorn api:app --host 0.0.0.0 --port 8001
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable threat-api
sudo systemctl start threat-api
sudo systemctl status threat-api
```

Partagez le résultat !
