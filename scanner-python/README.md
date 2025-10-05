# mini-scanner

Petit scanner pédagogique (TCP connect + banner grabbing) pour les labs.

## Installation / prérequis
- Python 3.8+
- Pas de dépendances externes (utilise socket/threading)

## Usage
Exemples :
```bash
# scan basique
python3 mini_scanner.py --target 127.0.0.1 --ports 80,8080 --threads 20 --timeout 0.8 --output /tmp/results.json --csv

# scan range
python3 mini_scanner.py --target 127.0.0.1 --ports 1-1024 --threads 100 --timeout 0.6 --output dvwa_scan.json

