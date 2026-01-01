# Tests

## Structure des tests

```
test/
├── test_trivy_scan.py      # Tests unitaires pour trivy_scan.py
├── test_merge_sbom.py      # Tests unitaires pour merge_sbom.py
├── test_language_mappings.py  # Tests unitaires pour language_mappings.py
├── test_integration.py     # Tests d'intégration fonctionnels
└── Dockerfile             # Dockerfile de test
```

## Installation des dépendances

```bash
pip install -r requirements-dev.txt
```

## Exécuter les tests

### Tous les tests
```bash
pytest
```

### Tests unitaires uniquement
```bash
pytest test/test_trivy_scan.py test/test_merge_sbom.py test/test_language_mappings.py
```

### Tests d'intégration uniquement
```bash
pytest test/test_integration.py
```

### Avec couverture de code
```bash
pytest --cov=. --cov-report=html
```

Le rapport de couverture sera généré dans `htmlcov/index.html`.

### Tests verbeux
```bash
pytest -v
```

### Tests spécifiques
```bash
# Une classe de tests
pytest test/test_trivy_scan.py::TestExtractBuildArgs

# Un test spécifique
pytest test/test_trivy_scan.py::TestExtractBuildArgs::test_extract_build_args_with_defaults
```

## Résultats attendus

### Tests unitaires

- **test_trivy_scan.py** : 24 tests
  - Extraction des build args
  - Détection des Dockerfiles
  - Détection des fichiers de dépendances

- **test_merge_sbom.py** : 18 tests
  - Chargement des SBOM
  - Fusion sans doublons
  - Conformité CycloneDX

- **test_language_mappings.py** : 14 tests
  - Détection des versions runtime
  - Catégorisation des composants

### Tests d'intégration

- **test_integration.py** : 9 tests
  - Workflow complet
  - Gestion d'erreurs
  - Tests de performance

**Total : 65+ tests**

## CI/CD

Les tests sont exécutés automatiquement sur GitHub Actions :

- ✅ À chaque push sur `main` et `develop`
- ✅ À chaque pull request
- ✅ Sur Python 3.11 et 3.12
- ✅ Avec couverture de code
- ✅ Tests d'intégration avec Trivy
- ✅ Validation SBOM
- ✅ Lint et vérification syntaxe
- ✅ Self-scan du projet

Voir [.github/workflows/test.yml](../.github/workflows/test.yml) pour les détails.

## Couverture de code

Les rapports de couverture sont automatiquement téléversés sur Codecov après chaque run CI.

Cible : > 80% de couverture

## Écrire de nouveaux tests

### Tests unitaires

```python
def test_my_function(self, tmp_path):
    """Description du test"""
    # Arrange
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    
    # Act
    result = my_function(test_file)
    
    # Assert
    assert result == expected_value
```

### Tests d'intégration

```python
def test_full_workflow(self, tmp_path):
    """Test du workflow complet"""
    # Setup
    setup_test_project(tmp_path)
    
    # Execute
    run_trivy_scan()
    run_merge_sbom()
    
    # Verify
    assert (tmp_path / "sbom" / "merged-sbom.cdx.json").exists()
```

## Fixtures pytest utiles

- `tmp_path` : Dossier temporaire nettoyé après chaque test
- `test_project` : Projet de test complet (dans test_integration.py)

## Dépannage

### Tests échouent localement

1. Vérifier que les dépendances sont installées :
   ```bash
   pip install -r requirements-dev.txt
   ```

2. Vérifier la version de Python :
   ```bash
   python --version  # Doit être 3.11+
   ```

3. Nettoyer les fichiers cache :
   ```bash
   find . -type d -name __pycache__ -exec rm -rf {} +
   find . -type f -name "*.pyc" -delete
   ```

### Tests d'intégration échouent

Les tests d'intégration nécessitent Trivy installé. Pour les désactiver :
```bash
pytest -m "not integration"
```

### Tests lents

Exécuter uniquement les tests rapides :
```bash
pytest -m "not slow"
```

## Contributeurs

Lors de l'ajout de nouvelles fonctionnalités, **ajoutez toujours des tests** :
- Au moins 1 test unitaire par fonction
- Tests de cas normaux et cas limites
- Tests de gestion d'erreurs
