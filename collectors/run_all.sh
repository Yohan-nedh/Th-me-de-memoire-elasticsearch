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
