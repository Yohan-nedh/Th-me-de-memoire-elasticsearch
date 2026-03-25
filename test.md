## TEST

Excellente idée ! C'est le test ultime pour valider votre projet. Voici l'architecture de votre lab :

```
Machine physique (Kali Linux)
        ↓ attaque
VM Metasploitable3 (cible)
        ↓ logs
VM ELK (surveillance)
```

**Mais avant de commencer**, quelques questions importantes :

**1. Réseau**
Les 3 machines sont-elles sur le même réseau ? Quelle est l'IP de chaque machine ?

```bash
# Sur chaque machine
ip addr show
```

**2. Ce qu'on va faire concrètement**

```
Étape 1 → Installer Filebeat sur Metasploitable3
           pour envoyer ses logs vers Logstash

Étape 2 → Lancer une attaque depuis Kali
           (scan Nmap, exploit Metasploit...)

Étape 3 → Voir les logs d'attaque dans Kibana
           en temps réel

Étape 4 → Croiser avec nos CVE
           "Cette attaque exploite CVE-XXXX"
```

**3. Important**
Ce test doit se faire dans un **réseau isolé** — jamais sur un réseau de production.

### Installation de filebeats
Ici nous allons installer filebeat sur la machine victime 

Installons Filebeat sur Metasploitable3. Filebeat est l'agent qui va collecter les logs et les envoyer vers Logstash.

**Sur Metasploitable3 (192.168.1.67) :**

```bash
# Télécharger Filebeat
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.0-amd64.deb

# Installer
sudo dpkg -i filebeat-8.13.0-amd64.deb

# Vérifier
filebeat version
```
Filebeat est installé ! Configurons-le pour envoyer les logs vers Logstash :

**Sur Metasploitable3 (192.168.1.67) :**

```bash
sudo nano /etc/filebeat/filebeat.yml
```

Remplacez tout le contenu par :

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
    tags: ["metasploitable3"]

  - type: log
    enabled: true
    paths:
      - /var/log/apache2/*.log
    tags: ["apache", "metasploitable3"]

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

output.logstash:
  hosts: ["192.168.1.65:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
```

Sauvegardez avec `Ctrl+O` puis `Ctrl+X`.

```bash
# Démarrer Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

Partagez le résultat !
