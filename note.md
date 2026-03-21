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

