# Guide d'installation et d'exécution des tests

## Installation

### Option 1 : Environnement virtuel (recommandé)

```bash
# Créer un environnement virtuel
python3 -m venv venv

# Activer l'environnement
source venv/bin/activate  # Linux/macOS
# ou
venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements-dev.txt
```

### Option 2 : Installation utilisateur

```bash
python3 -m pip install -r requirements-dev.txt --user
```

### Option 3 : Installation système (macOS avec Homebrew)

```bash
python3 -m pip install -r requirements-dev.txt --break-system-packages
```

## Exécution des tests

### Avec Make (recommandé)

```bash
make test          # Tous les tests
make test-unit     # Tests unitaires uniquement
make test-cov      # Tests avec couverture
make lint          # Vérification syntaxe
make clean         # Nettoyage
```

### Avec le script shell

```bash
./run_tests.sh
```

### Avec pytest directement

```bash
# Tous les tests
pytest test/ -v

# Tests spécifiques
pytest test/test_trivy_scan.py -v
pytest test/test_merge_sbom.py -v
pytest test/test_integration.py -v

# Avec couverture
pytest test/ --cov=. --cov-report=html
```

## Vérification rapide

Avant de commit :

```bash
# Vérifier la syntaxe
make lint

# Exécuter les tests
make test

# Vérifier la couverture
make test-cov
```

## CI/CD

Les tests sont automatiquement exécutés sur GitHub Actions :
- À chaque push sur main/develop
- À chaque pull request
- Sur Python 3.11 et 3.12

Voir le statut : [![Tests](https://github.com/RomainValmo/FullTrivyScanCycloneDX/actions/workflows/test.yml/badge.svg)](https://github.com/RomainValmo/FullTrivyScanCycloneDX/actions/workflows/test.yml)

## Dépannage

### pytest: command not found

```bash
# Vérifier l'installation
python3 -m pytest --version

# Si pas installé
pip install pytest pytest-cov pytest-mock
```

### Import errors

```bash
# Ajouter le répertoire au PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Ou utiliser pytest avec le flag
pytest test/ --import-mode=importlib
```

### Permission denied sur run_tests.sh

```bash
chmod +x run_tests.sh
```

## Support

- Documentation complète : [test/README.md](test/README.md)
- Issues : [GitHub Issues](https://github.com/RomainValmo/FullTrivyScanCycloneDX/issues)
