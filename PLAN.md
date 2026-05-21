# Planejamento — Baseline Aleatório do Docker Hub (short paper / grupo de controle)

## 1. Motivação
O estudo principal (ChimangoScan) mede as **52.895** imagens de maior *exposure* e
afirma explicitamente que esse corpus **não é uma média do ecossistema** — é a
cabeça mais consequente. Falta o controle: uma **amostra aleatória uniforme** do
Docker Hub que caracterize a imagem *típica* e quantifique o quão (não)
representativa é a cabeça popular. Este short paper preenche essa lacuna.

## 2. Perguntas de pesquisa
- **RQ1** — Qual a postura de segurança (prevalência de vuln/crítico/secret/
  misconfig; mediana de findings) de uma imagem *aleatória* do Docker Hub?
- **RQ2** — Quão diferente é a cabeça de alta-exposure (52.895) da média do
  ecossistema?
- **RQ3** — Que fração do namespace é **inacessível/abandonada** (taxa de skip) —
  algo que a cabeça popular esconde?
- **RQ4 (opcional)** — A divergência inter-scanner (na cabeça, os 3 scanners de
  SCA concordam em só 2,7% dos findings distintos) se mantém na cauda?

## 3. Hipóteses
- **H1** — A cabeça é mais "carregada" em absoluto (mais pacotes/vulns), pois a
  cauda concentra imagens pequenas/abandonadas.
- **H2** — A *prevalência* pode ser parecida (consistente com "exposure não
  prediz vulnerabilidade", já achado no principal) — a testar.
- **H3** — A taxa de skip da aleatória ≫ da cabeça (a cauda tem mais repos
  deletados/vazios/single-arch).

## 4. Desenho amostral
- **População:** N = 12.716.568 repositórios (`repositories_data`, Mongo no gpu1).
- **Amostragem:** uniforme por repositório — representativa por construção
  (reproduz, em esperança, a distribuição de pull-count da população). Sorteio via
  `$sample` do MongoDB; a lista sorteada é gravada como **registro canônico**
  (reprodutibilidade pela lista, já que `$sample` não aceita semente).
- **Tamanho (95% de confiança, p=0,5 pior caso):** n₀ = 1,96²·p(1−p)/e²; a
  correção de população finita é desprezível (n/N ≈ 2·10⁻⁴).

  | margem de erro | n escaneadas |
  |---|---|
  | ±3% | 1.068 |
  | **±2% (alvo)** | **2.401** |
  | ±1% | 9.604 |

- **Sobre-amostragem:** sortear ~4.800 repos (≈2× o alvo) para absorver skips,
  **em ondas** — sortear 4.000, medir o *yield* real, completar até 2.401
  escaneadas com sucesso. A taxa de skip vira resultado (RQ3).
- **Unidade:** `:latest` de cada repo (idêntico ao principal).
- **Opcional:** 2ª amostra **ponderada por pull** ("imagem típica *puxada*", não
  "repo típico") como baseline complementar.
- **Nota:** imagens oficiais (`library/`) somem na aleatória (~centenas em 12,7M)
  → sem split oficial/comunidade; a amostra caracteriza a imagem **comunitária
  típica** (que é o ponto).

## 5. Bateria de scanners — TRAVADA nos 6 do principal
**Syft, Trivy, Grype, OSV-Scanner, Dockle, TruffleHog** — exatamente os do estudo
principal. Justificativa:
- **Comparabilidade:** o objetivo é comparar cabeça-vs-aleatória com **o mesmo
  método**; trocar a bateria invalidaria a comparação.
- **Evidência (estudo interno dos 31 scanners sobre 130 containers):** esses 6 já
  são o conjunto "vale a pena" dos eixos estáticos — SCA precisa dos 3
  (grype+trivy+osv, 97% de cobertura; nenhum sozinho passa de ~60%), image-config
  (dockle), SBOM (syft), secrets (trufflehog). A curva de saturação mostra retorno
  decrescente além disso.
- **Sem scanner dinâmico:** a cauda aleatória é quase toda biblioteca/CLI/base
  **sem serviço de rede** → web/rede achariam ~nada, e o openvas (~15 min/host)
  custaria dias à toa. O dinâmico fica reservado a um estudo próprio sobre um
  corpus *curado de serviços* (a ideia "gap estático↔dinâmico").

## 6. Metodologia de scan
- Reusa a pipeline distribuída de 6 scanners (mesmos adapters, merge, schema
  `Finding`), imagem **pinada por digest**, `linux/amd64`, cap de 15 GB,
  `remove_image_after`.
- 13 máquinas, fila distribuída: faz `seed` da fila com a amostra e roda.
- Registra **skips e motivos** (deletada, sem `:latest`, single-arch não-amd64,
  >15 GB, inacessível) — insumo da RQ3.

## 7. Métricas e comparações (cabeça vs aleatória)
- Prevalência: vuln / crítico / high / secret / misconfig.
- Distribuição: mediana, p90, p99, máx de vulns por imagem.
- Divergência inter-scanner (% single-scanner) na aleatória.
- Top-10 pacotes vulneráveis; mix de ecossistemas (SBOM); contagem de pacotes.
- **Taxa de skip** (RQ3).
- **Testes:** IC de Wilson (95%) para proporções; diferença de proporções
  cabeça-vs-aleatória com IC; KS / Mann–Whitney para as distribuições de contagem.

## 8. Estimativa de tempo (13 máquinas, gargalo de banda ~500–800 img/h)
- Sorteio + montar fila: **minutos**.
- Scan de ~4.800 imagens (cauda → imagens pequenas, mais rápidas): **~meio dia a
  1 dia**.
- Análise + figuras: **~1 dia**.
- (Sem openvas/dinâmico — ver §5; com eles seriam ~2,5 dias só de openvas, à toa.)

## 9. Ameaças à validade
- Crawl defasado (repos deletados entre crawl e scan) → captado como skip (RQ3).
- `:latest` pode não representar o repo (mesma limitação do principal).
- Uniforme-por-repo ≠ uniforme-por-pull (reportar ambos se fizer a 2ª amostra).
- `linux/amd64` apenas.

## 10. Estrutura do repositório
```
chimango-baseline/
├── PLAN.md              este planejamento
├── README.md            visão geral
├── scripts/
│   ├── sample_repos.py  sorteio uniforme do repositories_data -> JSONL
│   ├── build_queue.py   monta a fila de scan a partir da amostra (a fazer)
│   └── analyze.py       stats + comparação cabeça-vs-aleatória (a fazer)
├── data/                amostra + resultados (grandes ficam no .gitignore)
└── figures/             figuras do paper
```

## 11. Alvo
Trilha de **short paper** (SBSeg 2026). Contribuição: o grupo de controle
aleatório que contextualiza o estudo de alta-exposure e testa, em escala de
ecossistema, se popularidade prediz (ou não) postura de segurança.
