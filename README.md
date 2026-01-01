# Full Trivy Scan with CycloneDX SBOM

[![Tests](https://github.com/RomainValmo/FullTrivyScanCycloneDX/actions/workflows/test.yml/badge.svg)](https://github.com/RomainValmo/FullTrivyScanCycloneDX/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/RomainValmo/FullTrivyScanCycloneDX/branch/main/graph/badge.svg)](https://codecov.io/gh/RomainValmo/FullTrivyScanCycloneDX)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests Count](https://img.shields.io/badge/tests-61%20passed-brightgreen.svg)](test/)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Une GitHub Action complète pour analyser la sécurité de vos projets, générer des SBOM CycloneDX et produire des métadonnées enrichies.

## Fonctionnalités

- 🔍 **Scan automatique des Dockerfiles** : Détecte et build toutes les images Docker du projet
- 📦 **Scan des fichiers de dépendances** : Analyse requirements.txt, package.json, go.sum, etc.
- 🔗 **Fusion intelligente des SBOM** : Combine tous les SBOM en un seul sans doublons
- 📊 **Enrichissement Trivy** : Ajoute les versions corrigées et statuts de vulnérabilités
- 🏷️ **Catégorisation des composants** : Identifie les runtimes, toolchains et dépendances
- 📋 **Génération de métadonnées** : Fichier JSON détaillé pour reporting avancé
- ✅ **Conforme CycloneDX 1.6** : Format SBOM standardisé et reconnu

## Flux de travail

```mermaid
graph LR
    A[Checkout] --> B[Scan Dockerfiles & Dépendances]
    B --> C[Génération SBOM individuels]
    C --> D[Fusion des SBOM]
    D --> E[Enrichissement Trivy]
    E --> F[Génération métadonnées]
    F --> G[Upload artifacts]
```

## Usage

### Utilisation basique

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Full SBOM Generation
        uses: RomainValmo/FullTrivyScanCycloneDX@main
      
      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          name: merged-sbom
          path: ./sbom-results
```

### Exemple complet avec Docker

Si votre projet contient des Dockerfiles et des fichiers de dépendances :

```yaml
name: Complete Security Analysis
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run Full Trivy Scan
        uses: RomainValmo/FullTrivyScanCycloneDX@main
      
      - name: Download SBOM results
        uses: actions/download-artifact@v4
        with:
          name: merged-sbom
          path: ./security-reports
      
      - name: Display statistics
        run: |
          if [ -f ./security-reports/metadata.json ]; then
            echo "📊 Scan Results:"
            jq -r '.stats' ./security-reports/metadata.json
          fi
```

## Sorties générées

| Fichier | Description |
|---------|-------------|
| `merged-sbom.cdx.json` | SBOM CycloneDX fusionné et enrichi |
| `metadata.json` | Métadonnées détaillées avec sources et vulnérabilités |

### Structure du metadata.json

```json
{
  "generated_at": "2026-01-01T12:00:00Z",
  "repository": "owner/repo",
  "branch": "main",
  "commit": "abc123...",
  "component_sources": {
    "pkg:pypi/requests@2.31.0": {
      "package_name": "requests",
      "version": "2.31.0",
      "source_file": "requirements.txt",
      "source_type": "dependency-file"
    }
  },
  "vulnerabilities": [
    {
      "vulnerability_id": "CVE-2023-xxxxx",
      "affected_packages": [
        {
          "package_name": "requests",
          "installed_version": "2.28.0",
          "fixed_version": "2.31.0",
          "fix_status": "fixed",
          "source_file": "requirements.txt"
        }
      ]
    }
  ],
  "stats": {
    "total_components": 45,
    "total_vulnerabilities": 3
  }
}
```

## Fichiers détectés automatiquement

### Dockerfiles
- `Dockerfile`
- `Dockerfile.*` (ex: `Dockerfile.dev`)
- `*.dockerfile`

### Fichiers de dépendances
- **Python** : `requirements.txt`, `Pipfile.lock`, `poetry.lock`
- **Node.js** : `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- **Go** : `go.sum`
- **Rust** : `Cargo.lock`
- **Java** : `pom.xml`, `build.gradle`
- **PHP** : `composer.lock`
- **Ruby** : `Gemfile.lock`

## Outputs

| Output | Description |
|--------|-------------|
| `sbom-file` | Chemin vers le SBOM fusionné : `sbom/merged-sbom.cdx.json` |

## Architecture du projet

```
votre-repo/
├── Dockerfile              # Détecté et scanné
├── requirements.txt        # Détecté et scanné
├── package.json           # Détecté et scanné
└── app/
    └── Dockerfile.prod    # Détecté et scanné
```

Résultat généré :
```
sbom/
├── merged-sbom.cdx.json          # SBOM fusionné
├── metadata.json                 # Métadonnées enrichies
├── Dockerfile-image.cdx.json     # SBOM de l'image Docker racine
├── app-image.cdx.json            # SBOM de l'image Docker app
├── requirements.txt.cdx.json     # SBOM des dépendances Python
└── package.json.cdx.json         # SBOM des dépendances Node.js
```
```

## Comment ça marche ?

### Étapes d'exécution

1. **Installation de Trivy** : Installe Trivy sur le runner GitHub Actions
2. **Détection automatique** : Recherche tous les Dockerfiles et fichiers de dépendances
3. **Build des images Docker** : Construit chaque image Docker détectée avec les build-args appropriés
4. **Scan Trivy** : Génère un SBOM CycloneDX pour chaque cible (images + fichiers de dépendances)
5. **Fusion** : Combine tous les SBOM en un seul fichier sans doublons
6. **Enrichissement** : Lance Trivy sur le SBOM fusionné pour ajouter les vulnérabilités et versions corrigées
7. **Métadonnées** : Génère un fichier JSON avec toutes les informations enrichies
8. **Upload** : Téléverse les résultats comme artifacts GitHub Actions

### Détection des versions runtime

L'action détecte automatiquement les versions des runtimes (Go, Python, Node.js, etc.) depuis les SBOM et les utilise pour enrichir les composants toolchain qui n'ont pas de version.

### Catégorisation des composants

Chaque composant est catégorisé selon son type :
- **dependency-file** : Dépendances externes (npm, pip, etc.)
- **docker-image** : Composants issus d'images Docker
- **go-toolchain** : Outils de compilation Go
- **application-binary** : Binaires applicatifs

## Prérequis

- GitHub Actions runner avec Ubuntu
- Docker installé (si vous scannez des Dockerfiles)
- Permissions d'écriture pour upload des artifacts

## Avancé

### Variables d'environnement utilisées

L'action utilise automatiquement ces variables GitHub Actions :
- `GITHUB_REPOSITORY` : Nom du dépôt
- `GITHUB_REF_NAME` : Nom de la branche
- `GITHUB_SHA` : Hash du commit
- `GITHUB_RUN_ID` : ID du workflow run

### Versions par défaut des runtimes

Si un Dockerfile utilise des `ARG` sans valeur par défaut, ces versions sont utilisées :
- `GO_VERSION`: 1.24
- `NODE_VERSION`: 22
- `PYTHON_VERSION`: 3.13
- `RUST_VERSION`: 1.83
- `JAVA_VERSION`: 21

## Limitations

- Profondeur de scan : 3 niveaux pour les Dockerfiles, 4 pour les fichiers de dépendances
- Les images Docker sont construites localement (nécessite de l'espace disque)
- Le SBOM fusionné peut être volumineux pour les projets complexes

## Dépannage

### Problème : Le build Docker échoue

Assurez-vous que vos Dockerfiles peuvent être buildés sans arguments externes. Utilisez des `ARG` avec des valeurs par défaut.

### Problème : Aucun SBOM généré

Vérifiez que votre projet contient au moins un Dockerfile ou un fichier de dépendances supporté.

### Problème : Metadata vide

Le fichier `metadata.json` nécessite que le SBOM fusionné contienne des composants et des vulnérabilités. Vérifiez les logs Trivy.

## Contribution

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les instructions de développement et contribution.

## Licence

MIT License - voir [LICENSE](LICENSE) pour plus de détails.

## Auteur

Développé par [RomainValmo](https://github.com/RomainValmo)

## Ressources

- [Documentation Trivy](https://aquasecurity.github.io/trivy/)
- [Spécification CycloneDX](https://cyclonedx.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 0 * * 0'  # Every Sunday at midnight

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Audit
        uses: RomainValmo/FullTrivyScanCycloneDX@main
        with:
          format: 'cyclonedx'
          severity: 'HIGH,CRITICAL'
      
      - name: Archive Results
        uses: actions/upload-artifact@v4
        with:
          name: weekly-audit-${{ github.run_number }}
          path: trivy-sbom.json
```

## Development

### Project Structure

```
.
├── action.yml           # GitHub Action metadata
├── Dockerfile          # Container definition
├── trivy_scan.py       # Main Python script
├── requirements.txt    # Python dependencies
├── .gitignore         # Git ignore patterns
└── README.md          # This file
```

### Local Testing

You can test the action locally using Docker:

```bash
# Build the Docker image
docker build -t trivy-action .

# Run a scan
docker run -v $(pwd):/scan trivy-action fs /scan cyclonedx output.json UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL os,library 0 latest
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- How to set up the development environment
- How to run tests locally ([docs/TESTING.md](docs/TESTING.md))
- Code style guidelines
- How to submit pull requests

Please also read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Quick Start

See our [Quick Start Guide](docs/QUICKSTART.md) for getting started quickly.

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) for responsible disclosure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses:
- [Trivy](https://github.com/aquasecurity/trivy) - Apache 2.0 License
- [CycloneDX](https://cyclonedx.org/) - Apache 2.0 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About Trivy

[Trivy](https://github.com/aquasecurity/trivy) is a comprehensive and versatile security scanner developed by Aqua Security. It can detect vulnerabilities in:
- Operating system packages
- Application dependencies
- Container images
- Infrastructure as Code (IaC) files
- Kubernetes clusters

## About CycloneDX

[CycloneDX](https://cyclonedx.org/) is a full-stack Bill of Materials (BOM) standard that provides advanced supply chain capabilities for cyber risk reduction.
