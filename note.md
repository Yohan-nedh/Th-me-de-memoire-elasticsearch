# Note mémoire

## Thème : Implémentation d'un système intelligent de gestion des menaces et vulnérabilités basé sur la suite ELK

Ici se trouve les note de mon avancé par rapport à mon mémoire. Pour l'instant j'ai commencer en local avec ma vm ubuntu server.

Pour comment j'ai crée un dossier appelé **memoire_ELK** donc l'architecture visuel est celle-ci:

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
