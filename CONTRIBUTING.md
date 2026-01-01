# Contributing to FullTrivyScanCycloneDX

Merci de votre intérêt pour contribuer ! Ce guide vous aidera à démarrer.

## Configuration de développement

### Prérequis

- Docker installé et fonctionnel
- Python 3.11+
- Trivy installé localement (pour les tests)
- Git

### Installation de Trivy (pour tests locaux)

#### macOS
```bash
brew install aquasecurity/trivy/trivy
```

#### Ubuntu/Debian
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

### Tests locaux

1. Cloner le dépôt :
```bash
git clone https://github.com/RomainValmo/FullTrivyScanCycloneDX.git
cd FullTrivyScanCycloneDX
```

2. Installer les dépendances de développement :
```bash
pip install -r requirements-dev.txt
```

3. Exécuter les tests :
```bash
# Avec le script
./scripts/run_tests.sh

# Ou avec Make
make test

# Ou directement avec pytest
pytest test/ -v
```

4. Tester avec le projet de test :
```bash
cd test
python3 ../trivy_scan.py
python3 ../merge_sbom.py
python3 ../metadata.py
```

5. Vérifier les résultats :
```bash
ls -la sbom/
cat sbom/metadata.json | jq '.stats'
```

## Tests

Le projet dispose d'une batterie complète de tests :

### Structure des tests
- `test/test_trivy_scan.py` : Tests unitaires pour la détection et le scan
- `test/test_merge_sbom.py` : Tests unitaires pour la fusion des SBOM
- `test/test_language_mappings.py` : Tests unitaires pour la catégorisation
- `test/test_integration.py` : Tests d'intégration du workflow complet

### Exécuter les tests

```bash
# Tous les tests
make test

# Tests unitaires uniquement
make test-unit

# Tests d'intégration uniquement
make test-integration

# Avec couverture de code
make test-cov
```

### Couverture de code

Après avoir exécuté `make test-cov`, ouvrez `htmlcov/index.html` dans votre navigateur pour voir le rapport détaillé.

Cible de couverture : **> 80%**

### Structure du projet

```
.
├── action.yml              # Définition de la GitHub Action
├── trivy_scan.py          # Script principal : détection et scan
├── merge_sbom.py          # Fusion des SBOM sans doublons
├── metadata.py            # Enrichissement et génération métadonnées
├── language_mappings.py   # Catégorisation des composants
├── README.md              # Documentation principale
├── CONTRIBUTING.md        # Ce fichier
├── QUICKSTART.md         # Guide de démarrage rapide
├── LICENSE               # Licence MIT
└── test/
    └── Dockerfile        # Dockerfile de test
```

## Faire des modifications

### 1. Créer une branche

```bash
git checkout -b feature/nom-de-votre-feature
```

### 2. Faire vos modifications

- Gardez les changements focalisés et atomiques
- Suivez le style de code existant (PEP 8 pour Python)
- Mettez à jour la documentation si nécessaire
- Testez minutieusement

### 3. Valider vos changements

#### Vérifier la syntaxe Python
```bash
python3 -m py_compile trivy_scan.py
python3 -m py_compile merge_sbom.py
python3 -m py_compile metadata.py
python3 -m py_compile language_mappings.py
```

#### Valider le YAML
```bash
python3 -c "import yaml; yaml.safe_load(open('action.yml'))"
```

#### Tester le workflow complet
```bash
cd test
python3 ../trivy_scan.py && \
python3 ../merge_sbom.py && \
python3 ../metadata.py && \
echo "✅ Tests réussis"
```

#### Vérifier les sorties
```bash
# Vérifier que les fichiers sont générés
test -f sbom/merged-sbom.cdx.json && echo "✅ SBOM fusionné OK"
test -f sbom/metadata.json && echo "✅ Métadonnées OK"

# Valider le format JSON
jq empty sbom/merged-sbom.cdx.json && echo "✅ SBOM valide"
jq empty sbom/metadata.json && echo "✅ Metadata valide"

# Afficher les stats
jq '.stats' sbom/metadata.json
```

### 4. Soumettre une Pull Request

- Écrivez une description claire de vos changements
- Référencez les issues liées si applicable
- Assurez-vous que tous les tests passent
- Attendez la revue de code

## Directives de code

### Style Python

- Suivez PEP 8
- Utilisez des noms de variables descriptifs
- Ajoutez des docstrings pour les fonctions
- Loggez les informations importantes

Exemple :
```python
def process_component(component: dict, runtime_versions: dict) -> dict:
    """
    Traite un composant et enrichit ses métadonnées.
    
    Args:
        component: Dictionnaire représentant un composant CycloneDX
        runtime_versions: Versions détectées des runtimes
    
    Returns:
        dict: Composant enrichi avec métadonnées
    """
    # Implementation
    pass
```

### Style YAML

- Utilisez 2 espaces pour l'indentation
- Ajoutez des commentaires pour les étapes complexes
- Gardez les lignes sous 120 caractères

### Gestion des erreurs

- Utilisez `try/except` pour les opérations risquées
- Loggez les erreurs avec contexte
- Retournez des valeurs par défaut appropriées

Exemple :
```python
try:
    with open(file_path, 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    logger.warning(f"Fichier {file_path} introuvable")
    return {}
except json.JSONDecodeError:
    logger.error(f"Format JSON invalide dans {file_path}")
    return {}
```

## Types de contributions

### Bugs et corrections

Si vous trouvez un bug :
1. Vérifiez qu'il n'existe pas déjà dans les issues
2. Créez une issue avec :
   - Description claire du problème
   - Étapes pour reproduire
   - Comportement attendu vs. observé
   - Logs pertinents
3. Proposez une PR avec la correction

### Nouvelles fonctionnalités

Avant d'ajouter une nouvelle fonctionnalité :
1. Ouvrez une issue pour discussion
2. Attendez le feedback des mainteneurs
3. Implémentez avec tests
4. Mettez à jour la documentation

### Documentation

La documentation est toujours bienvenue :
- Corrections de typos
- Clarifications
- Exemples supplémentaires
- Traductions

## Tests

### Cas de test à valider

1. **Détection de Dockerfiles**
   - Dockerfile à la racine
   - Dockerfiles dans sous-dossiers
   - Différents noms (Dockerfile.dev, app.dockerfile)

2. **Détection de fichiers de dépendances**
   - Python : requirements.txt, poetry.lock
   - Node.js : package-lock.json, yarn.lock
   - Go : go.sum
   - Autres langages

3. **Fusion des SBOM**
   - Pas de doublons
   - Préservation des métadonnées
   - Format CycloneDX valide

4. **Enrichissement**
   - Versions corrigées ajoutées
   - Catégorisation correcte
   - Runtime versions détectées

### Créer un projet de test

```bash
mkdir test-project
cd test-project

# Créer un Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
EOF

# Créer requirements.txt
cat > requirements.txt << 'EOF'
requests==2.28.0
flask==2.3.0
EOF

# Tester l'action
python3 ../trivy_scan.py
python3 ../merge_sbom.py
python3 ../metadata.py
```

## Release

Les releases sont gérées par les mainteneurs :
1. Mise à jour du numéro de version
2. Création d'un tag Git
3. Publication sur GitHub
4. Mise à jour de la marketplace

## Questions ?

- Ouvrez une issue pour les questions générales
- Rejoignez les discussions dans les PR existantes
- Consultez les issues fermées pour solutions passées

## Code de conduite

Soyez respectueux, inclusif et professionnel dans toutes les interactions.

## Licence

En contribuant, vous acceptez que vos contributions soient sous licence MIT.

Tous les fichiers source Python doivent inclure le header de licence :

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Full Trivy Scan with CycloneDX SBOM
Copyright (c) 2025-2026 RomainValmo
Licensed under the MIT License - see LICENSE file for details

[Description du module]
"""
```

## Reconnaissance

Les contributeurs sont reconnus dans :
- [AUTHORS.md](AUTHORS.md) - Liste des auteurs
- [CHANGELOG.md](CHANGELOG.md) - Notes de version
- GitHub Contributors - Page des contributeurs

## Ressources

- [Documentation Trivy](https://aquasecurity.github.io/trivy/)
- [Spécification CycloneDX](https://cyclonedx.org/specification/overview/)
- [Code of Conduct](CODE_OF_CONDUCT.md) - Notre code de conduite
- [Security Policy](SECURITY.md) - Politique de sécurité

Merci de contribuer ! 🙏
- **Comments**: Explain "why" not "what"
- **Naming**: Use descriptive variable names

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Keep first line under 50 characters
- Add detailed description if needed

### Documentation

- Update README.md for user-facing changes
- Update QUICKSTART.md for common use cases
- Add comments for complex logic
- Include examples when helpful

## Adding New Features

### New Input Parameters

1. Add to `action.yml` inputs section
2. Update `trivy_scan.py` to handle the parameter
3. Update README.md with usage examples
4. Update QUICKSTART.md if it's a common use case

### New Output Formats

1. Update Trivy command in `trivy_scan.py`
2. Update output parsing logic
3. Add examples to documentation
4. Test with real scans

### New Scan Types

1. Add support in `trivy_scan.py`
2. Update documentation
3. Add example workflow
4. Test thoroughly

## Testing Checklist

Before submitting:

- [ ] Python syntax is valid
- [ ] YAML files are valid
- [ ] Docker image builds successfully
- [ ] Action works with default parameters
- [ ] Action works with custom parameters
- [ ] Documentation is updated
- [ ] Examples are provided
- [ ] No sensitive data is included

## Getting Help

- Check existing issues and PRs
- Read the full documentation
- Ask questions in discussions
- Be patient and respectful

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the project
- Welcome newcomers

Thank you for contributing! 🎉
