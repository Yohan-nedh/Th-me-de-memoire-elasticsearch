import os
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

def get_es_client():
    host     = os.getenv("ES_HOST", "http://localhost:9200")
    user     = os.getenv("ES_USER", "elastic")
    password = os.getenv("ES_PASSWORD", "elastic123")

    return Elasticsearch(
        host,
        basic_auth=(user, password),
        verify_certs=False,
        ssl_show_warn=False
    )
