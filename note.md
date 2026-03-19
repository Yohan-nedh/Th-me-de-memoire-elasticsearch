
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
