# chimango-baseline

Baseline aleatório do Docker Hub — **grupo de controle** do estudo ChimangoScan
(que mede as imagens de maior *exposure*).

Mede a postura de segurança de uma **amostra aleatória uniforme** de repositórios
do Docker Hub, escaneada com os **mesmos 6 scanners** do estudo principal
(Syft, Trivy, Grype, OSV-Scanner, Dockle, TruffleHog), para quantificar o quão
representativa — ou não — é a cabeça de alta-exposure.

Planejamento completo em [`PLAN.md`](PLAN.md). Alvo: trilha de short paper (SBSeg 2026).

## Uso rápido
```bash
# 1. sorteio uniforme da amostra (Mongo do crawl no gpu1)
MONGO_URI=mongodb://127.0.0.1:27017 SAMPLE_N=4800 python3 scripts/sample_repos.py
# -> data/random_sample.jsonl  (uma imagem :latest por repo sorteado)

# 2. (a fazer) seed da fila + scan distribuído nos 6 scanners
# 3. (a fazer) análise + comparação cabeça-vs-aleatória
```
