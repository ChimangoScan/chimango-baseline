#!/usr/bin/env python3
"""Amostra uniforme aleatória de repositórios do Docker Hub (grupo de controle).

Sorteia N repos de dockerhub_data.repositories_data (Mongo do crawl) com $sample
(amostragem uniforme server-side) e emite um JSONL repo:tag (uma imagem :latest
por repo) no formato que a pipeline de scan consome. A lista emitida É o registro
canônico da amostra (reprodutibilidade pela lista, já que $sample não tem semente).

Env:
  MONGO_URI    (default mongodb://127.0.0.1:27017)
  SAMPLE_N     nº de repos a sortear (default 4800 -> ~2401 escaneados após skips)
  OUT_PATH     (default data/random_sample.jsonl)
"""
import json
import os
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
N = int(os.environ.get("SAMPLE_N", "4800"))
OUT = os.environ.get("OUT_PATH", "data/random_sample.jsonl")


def pull_int(pc):
    """pull_count vem como {high, low, unsigned} (Long do Mongo) ou int."""
    if isinstance(pc, dict):
        return (int(pc.get("high", 0)) << 32) + int(pc.get("low", 0))
    try:
        return int(pc or 0)
    except (TypeError, ValueError):
        return 0


def main():
    cli = MongoClient(MONGO_URI)
    db = cli["dockerhub_data"]
    pipeline = [
        {"$sample": {"size": N}},
        {"$project": {"namespace": 1, "name": 1, "pull_count": 1, "_id": 0}},
    ]
    rows = db.repositories_data.aggregate(pipeline, allowDiskUse=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    n = 0
    with open(OUT, "w") as f:
        for d in rows:
            ns = d.get("namespace") or ""
            nm = d.get("name") or ""
            if not nm:
                continue
            # repo:tag no mesmo formato do ranker (library -> só o nome)
            rt = nm if ns == "library" else (ns + "/" + nm if ns else nm)
            obj = {
                "repository_namespace": ns,
                "repository_name": nm,
                "tag_name": "latest",
                "image": rt + ":latest",
                "pull_count": pull_int(d.get("pull_count")),
            }
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
            n += 1
    cli.close()
    print("amostra escrita: %d repos -> %s" % (n, OUT))


if __name__ == "__main__":
    main()
