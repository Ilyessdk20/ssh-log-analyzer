# ssh-log-analyzer

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Pandas](https://img.shields.io/badge/pandas-Data%20Analysis-150458?logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![Matplotlib](https://img.shields.io/badge/matplotlib-Visualization-11557C)](https://matplotlib.org/)
[![CLI](https://img.shields.io/badge/Interface-CLI-2ea44f)](https://docs.python.org/3/library/argparse.html)
[![Last Commit](https://img.shields.io/github/last-commit/Ilyessdk20/ssh-log-analyzer)](https://github.com/Ilyessdk20/ssh-log-analyzer)

Analyseur Python de logs SSH Linux (auth.log / secure) orienté cybersecurite et data analysis.

Ce projet transforme des logs systeme bruts en indicateurs de securite exploitables:
- tentatives de connexion echouees,
- connexions reussies,
- IP les plus actives,
- IP suspectes selon un seuil configurable,
- heures avec le plus d'echecs SSH.

## Pourquoi ce projet est CV-ready

- Cas d'usage realiste de cybersurveillance (detection de brute-force SSH).
- Pipeline complet: parsing, structuration, analyse, export, visualisation.
- Outil CLI propre, testable localement, sans complexite inutile.
- Resultats chiffrables et faciles a presenter en entretien technique.

## Competences Demontrees

- Cybersecurite operationnelle: analyse d'evenements d'authentification SSH Linux.
- Detection de comportements suspects: seuil d'alerte par IP (`--threshold`).
- Data engineering Python: parsing regex, nettoyage et structuration en DataFrame.
- Data analysis: agregations par IP et par heure pour identifier des patterns.
- Reporting technique: export CSV/TXT/PNG pour partage avec une equipe SOC/Blue Team.
- Bonnes pratiques software: code modulaire (`parser`, `analyzer`, `report`, `main`) et gestion d'erreurs simple.

## Resultats Cles (sur le fichier d'exemple)

Execution:

```bash
python src/main.py --input data/sample_auth.log --outdir results --threshold 3
```

Indicateurs obtenus:

| Metrique | Valeur |
|---|---:|
| Evenements SSH parses | 18 |
| Tentatives echouees | 13 |
| Connexions reussies | 5 |
| IP uniques observees | 6 |
| IP suspectes (threshold = 3) | 2 |
| Heure la plus active en echec | 08:00 (4 echecs) |

Top IP suspectes detectees:
- 203.0.113.10 -> 7 echecs
- 198.51.100.77 -> 4 echecs

## Stack Technique

- Python 3
- pandas
- matplotlib
- argparse
- regex (module `re` standard Python)
- pathlib

## Structure Du Projet

```text
ssh-log-analyzer/
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   └── sample_auth.log
├── results/
│   └── .gitkeep
└── src/
    ├── parser.py
    ├── analyzer.py
    ├── report.py
    └── main.py
```

## Installation

```bash
# 1) Se placer dans le dossier du projet
cd ssh-log-analyzer

# 2) Creer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# 3) Installer les dependances
pip install -r requirements.txt
```

## Utilisation

```bash
python src/main.py --input data/sample_auth.log --outdir results --threshold 3
```

Arguments:
- `--input`: chemin du fichier de logs SSH.
- `--outdir`: dossier de sortie des resultats.
- `--threshold`: seuil minimal d'echecs pour marquer une IP comme suspecte.
- `--year`: annee a appliquer aux timestamps (par defaut: annee courante).

## Fichiers Generes

Le dossier `results/` contient:
- `parsed_events.csv`: evenements SSH parses (date, heure, user, IP, port, type).
- `ip_summary.csv`: resume par IP (echecs, succes, total).
- `hourly_failures.csv`: volume d'echecs par heure.
- `suspicious_ips.csv`: IP suspectes selon le seuil.
- `report.txt`: rapport texte de synthese.
- `failed_by_hour.png`: graphique des echecs par heure.

## Exemple De Sortie Console

```text
[INFO] Analysis completed.
[INFO] Total parsed events: 18
[INFO] Failed attempts: 13
[INFO] Successful logins: 5
[INFO] Suspicious IPs (threshold=3): 2
[INFO] Generated files:
  - parsed_events_csv: results/parsed_events.csv
  - ip_summary_csv: results/ip_summary.csv
  - hourly_failures_csv: results/hourly_failures.csv
  - suspicious_ips_csv: results/suspicious_ips.csv
  - report_txt: results/report.txt
  - failed_by_hour_png: results/failed_by_hour.png
```

## Valeur Cybersecurite

- Identification rapide des sources d'attaques SSH les plus actives.
- Priorisation des IP a bloquer/monitorer selon un seuil objectif.
- Vue temporelle des pics d'echecs pour orienter la reponse incident.
- Base solide pour evoluer vers un mini-SIEM ou une detection temps reel.