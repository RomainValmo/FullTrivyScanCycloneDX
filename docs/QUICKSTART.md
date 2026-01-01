# Guide de démarrage rapide

## Qu'est-ce que cette action fait ?

Une GitHub Action qui scanne automatiquement votre projet avec Trivy pour :
- ✅ Détecter tous vos Dockerfiles et les builder
- ✅ Analyser vos fichiers de dépendances (requirements.txt, package.json, etc.)
- ✅ Générer des SBOM CycloneDX pour chaque composant
- ✅ Fusionner tous les SBOM en un seul fichier
- ✅ Enrichir avec les vulnérabilités et versions corrigées
- ✅ Produire un fichier de métadonnées détaillé

## Usage ultra-simple

Ajoutez ceci à votre workflow :

```yaml
- name: Scan complet
  uses: RomainValmo/FullTrivyScanCycloneDX@main
```

C'est tout ! L'action va :
1. Détecter tous vos Dockerfiles et fichiers de dépendances
2. Générer les SBOM pour chaque composant
3. Fusionner le tout en un SBOM complet
4. Enrichir avec les vulnérabilités
5. Upload les résultats comme artifacts

## Récupérer les résultats

```yaml
- name: Scan complet
  uses: RomainValmo/FullTrivyScanCycloneDX@main

- name: Télécharger les résultats
  uses: actions/download-artifact@v4
  with:
    name: merged-sbom
    path: ./security-reports
```

Les fichiers générés :
- `merged-sbom.cdx.json` : SBOM CycloneDX complet et fusionné
- `metadata.json` : Métadonnées détaillées avec sources et vulnérabilités

## Exemples pratiques

### Exemple 1 : Projet Python simple

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RomainValmo/FullTrivyScanCycloneDX@main
```

Si votre projet a :
- `requirements.txt` → Scanné automatiquement
- `Dockerfile` → Buildé et scanné automatiquement

### Exemple 2 : Projet multi-services avec Docker

```yaml
name: Multi-Service Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan complet du projet
        uses: RomainValmo/FullTrivyScanCycloneDX@main
      
      - name: Récupérer les résultats
        uses: actions/download-artifact@v4
        with:
          name: merged-sbom
          path: ./security-results
      
      - name: Afficher les statistiques
        run: |
          echo "📊 Résultats du scan :"
          jq -r '.stats' ./security-results/metadata.json
```

Votre projet :
```
mon-projet/
├── Dockerfile              # Scanné
├── requirements.txt        # Scanné
├── api/
│   └── Dockerfile.prod    # Scanné
└── worker/
    ├── Dockerfile         # Scanné
    └── package.json       # Scanné
```

Résultat : Un SBOM fusionné avec tous les composants de tous les services !

### Exemple 3 : Afficher les vulnérabilités critiques

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main

- name: Afficher les CVE critiques
  run: |
    jq -r '.vulnerabilities[] | select(.affected_packages[].fix_status == "fixed") | 
      "🔴 " + .vulnerability_id + " - " + .affected_packages[0].package_name' \
      ./security-reports/metadata.json
```

### Exemple 4 : Scan quotidien programmé

```yaml
name: Daily Security Audit
on:
  schedule:
    - cron: '0 2 * * *'  # Tous les jours à 2h du matin
  workflow_dispatch:      # Déclenchement manuel

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RomainValmo/FullTrivyScanCycloneDX@main
      
      - name: Envoyer notification si vulnérabilités
        if: always()
        run: |
          VULN_COUNT=$(jq '.stats.total_vulnerabilities' ./security-reports/metadata.json)
          if [ "$VULN_COUNT" -gt 0 ]; then
            echo "⚠️ $VULN_COUNT vulnérabilités détectées"
          fi
```

## Ce qui est détecté automatiquement

### Dockerfiles
✅ `Dockerfile`  
✅ `Dockerfile.dev`, `Dockerfile.prod`  
✅ `app.dockerfile`, `worker.dockerfile`  

### Fichiers de dépendances
✅ **Python** : `requirements.txt`, `Pipfile.lock`, `poetry.lock`  
✅ **Node.js** : `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`  
✅ **Go** : `go.sum`  
✅ **Rust** : `Cargo.lock`  
✅ **Java** : `pom.xml`, `build.gradle`  
✅ **PHP** : `composer.lock`  
✅ **Ruby** : `Gemfile.lock`  

## Structure des résultats

### merged-sbom.cdx.json
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-xxxxx",
      "affects": [...]
    }
  ]
}
```

### metadata.json
```json
{
  "generated_at": "2026-01-01T12:00:00Z",
  "repository": "owner/repo",
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

## Pas d'inputs requis !

Contrairement à d'autres actions, celle-ci ne nécessite **aucun paramètre** :
- ✅ Détection automatique des cibles
- ✅ Build automatique des Dockerfiles
- ✅ Scan automatique de tous les fichiers de dépendances
- ✅ Fusion et enrichissement automatiques
- ✅ Upload automatique des résultats

## Outputs disponibles

| Output | Description |
|--------|-------------|
| `sbom-file` | Chemin vers le SBOM fusionné : `sbom/merged-sbom.cdx.json` |

Exemple d'utilisation :
```yaml
- name: Scan
  id: scan-step
  uses: RomainValmo/FullTrivyScanCycloneDX@main

- name: Utiliser le chemin SBOM
  run: echo "SBOM généré : ${{ steps.scan-step.outputs.sbom-file }}"
```

## Cas d'usage avancés

### Comparer les SBOM entre commits

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main

- name: Comparer avec le commit précédent
  run: |
    git fetch origin main
    git checkout origin/main -- sbom/merged-sbom.cdx.json
    mv sbom/merged-sbom.cdx.json sbom-previous.json
    
    # Comparer le nombre de composants
    CURRENT=$(jq '.components | length' sbom/merged-sbom.cdx.json)
    PREVIOUS=$(jq '.components | length' sbom-previous.json)
    echo "Composants : $PREVIOUS → $CURRENT"
```

### Générer un rapport HTML

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main

- name: Générer rapport HTML
  run: |
    cat > report.html << 'EOF'
    <!DOCTYPE html>
    <html>
    <head><title>Security Report</title></head>
    <body>
      <h1>SBOM Report</h1>
      <pre id="data"></pre>
      <script>
        fetch('./metadata.json')
          .then(r => r.json())
          .then(data => {
            document.getElementById('data').textContent = 
              JSON.stringify(data, null, 2);
          });
      </script>
    </body>
    </html>
    EOF
```

## Besoin d'aide ?

Consultez la documentation complète : [README.md](README.md)

## Prêt à contribuer ?

Voir le guide : [CONTRIBUTING.md](CONTRIBUTING.md)
