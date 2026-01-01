.PHONY: help install test test-unit test-integration test-cov lint clean

help:
	@echo "Commandes disponibles :"
	@echo "  make install          - Installer les dépendances de développement"
	@echo "  make test            - Exécuter tous les tests"
	@echo "  make test-unit       - Exécuter uniquement les tests unitaires"
	@echo "  make test-integration - Exécuter uniquement les tests d'intégration"
	@echo "  make test-cov        - Exécuter les tests avec couverture de code"
	@echo "  make lint            - Vérifier la syntaxe et le formatage"
	@echo "  make clean           - Nettoyer les fichiers temporaires"

install:
	pip install -r requirements-dev.txt

test:
	pytest test/ -v

test-unit:
	pytest test/test_trivy_scan.py test/test_merge_sbom.py test/test_language_mappings.py -v

test-integration:
	pytest test/test_integration.py -v

test-cov:
	pytest test/ --cov=src --cov-report=html --cov-report=term-missing
	@echo "📊 Rapport de couverture généré dans htmlcov/index.html"

lint:
	@echo "🔍 Vérification de la syntaxe Python..."
	python -m py_compile src/trivy_scan.py src/merge_sbom.py src/metadata.py src/language_mappings.py
	@echo "📄 Vérification des fichiers YAML..."
	python -c "import yaml; yaml.safe_load(open('action.yml'))"
	python -c "import yaml; yaml.safe_load(open('.github/workflows/test.yml'))"
	@echo "✅ Toutes les vérifications sont passées"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf test/sbom
	@echo "🧹 Nettoyage terminé"
