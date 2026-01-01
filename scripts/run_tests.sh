#!/bin/bash
# Script pour exécuter tous les tests

set -e

echo "🧪 Exécution de la batterie de tests complète..."
echo ""

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Vérifier que pytest est installé
if ! command -v pytest &> /dev/null; then
    echo "${YELLOW}⚠️  pytest n'est pas installé${NC}"
    echo "Installation des dépendances..."
    pip install -r requirements-dev.txt
fi

# Vérifier la syntaxe Python
echo "${BLUE}📝 Vérification de la syntaxe Python...${NC}"
python -m py_compile trivy_scan.py
python -m py_compile merge_sbom.py
python -m py_compile metadata.py
python -m py_compile language_mappings.py
echo "${GREEN}✅ Syntaxe Python OK${NC}"
echo ""

# Vérifier les fichiers YAML
echo "${BLUE}📄 Vérification des fichiers YAML...${NC}"
python -c "import yaml; yaml.safe_load(open('action.yml'))"
python -c "import yaml; yaml.safe_load(open('.github/workflows/test.yml'))"
echo "${GREEN}✅ YAML OK${NC}"
echo ""

# Exécuter les tests unitaires
echo "${BLUE}🧪 Tests unitaires...${NC}"
pytest test/test_trivy_scan.py test/test_merge_sbom.py test/test_language_mappings.py -v
echo "${GREEN}✅ Tests unitaires OK${NC}"
echo ""

# Exécuter les tests d'intégration
echo "${BLUE}🔗 Tests d'intégration...${NC}"
pytest test/test_integration.py -v
echo "${GREEN}✅ Tests d'intégration OK${NC}"
echo ""

# Rapport de couverture
echo "${BLUE}📊 Génération du rapport de couverture...${NC}"
pytest test/ --cov=. --cov-report=term-missing --cov-report=html
echo "${GREEN}✅ Rapport généré dans htmlcov/index.html${NC}"
echo ""

# Résumé
echo "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "${GREEN}✨ Tous les tests sont passés avec succès !${NC}"
echo "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
