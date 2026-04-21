from fastapi import FastAPI, Query
from es_client import get_es_client
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

es  = get_es_client()
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
