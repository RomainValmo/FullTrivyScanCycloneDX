"""Tests d'intégration fonctionnels"""
import pytest
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import shutil

from trivy_scan import find_dockerfiles, find_dependency_files
from merge_sbom import load_sbom_files, merge_sboms


class TestFullWorkflow:
    """Tests du workflow complet"""
    
    @pytest.fixture
    def test_project(self, tmp_path):
        """Crée un projet de test complet"""
        # Créer un Dockerfile
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
""")
        
        # Créer requirements.txt
        requirements = tmp_path / "requirements.txt"
        requirements.write_text("""
requests==2.31.0
flask==2.3.0
pytest==7.4.0
""")
        
        # Créer package.json pour multi-langage
        package_json = tmp_path / "package.json"
        package_json.write_text(json.dumps({
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0"
            }
        }))
        
        # Créer un sous-dossier avec son propre Dockerfile
        api_dir = tmp_path / "api"
        api_dir.mkdir()
        api_dockerfile = api_dir / "Dockerfile.prod"
        api_dockerfile.write_text("""
FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
CMD ["node", "server.js"]
""")
        
        return tmp_path
    
    def test_detect_all_files(self, test_project):
        """Test détection de tous les fichiers"""
        dockerfiles = find_dockerfiles(test_project)
        dep_files = find_dependency_files(test_project)
        
        # Vérifier Dockerfiles
        assert len(dockerfiles) >= 1
        dockerfile_names = [f.name for f in dockerfiles]
        assert "Dockerfile" in dockerfile_names
        
        # Vérifier fichiers de dépendances
        assert len(dep_files) >= 1
        dep_names = [f.name for f in dep_files]
        assert "requirements.txt" in dep_names
    
    def test_sbom_merge_workflow(self, tmp_path):
        """Test du workflow de fusion de SBOM"""
        # Créer des SBOM factices
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        # SBOM 1
        sbom1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "bom-ref": "pkg:pypi/requests@2.31.0",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0"
                }
            ],
            "metadata": {
                "tools": {
                    "components": [
                        {"name": "trivy", "version": "0.50.0"}
                    ]
                }
            }
        }
        
        # SBOM 2
        sbom2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "bom-ref": "pkg:pypi/flask@2.3.0",
                    "name": "flask",
                    "version": "2.3.0",
                    "purl": "pkg:pypi/flask@2.3.0"
                }
            ],
            "metadata": {
                "tools": {
                    "components": [
                        {"name": "trivy", "version": "0.50.0"}
                    ]
                }
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2023-0001",
                    "affects": [
                        {"ref": "pkg:pypi/flask@2.3.0"}
                    ]
                }
            ]
        }
        
        # Sauvegarder les SBOM
        (sbom_dir / "requirements.txt.cdx.json").write_text(json.dumps(sbom1))
        (sbom_dir / "Dockerfile-image.cdx.json").write_text(json.dumps(sbom2))
        
        # Charger et fusionner
        sboms = load_sbom_files(sbom_dir)
        merged = merge_sboms(sboms)
        
        # Vérifications
        assert merged["bomFormat"] == "CycloneDX"
        assert merged["specVersion"] == "1.6"
        assert len(merged["components"]) == 2
        assert len(merged["metadata"]["tools"]["components"]) == 1
        assert len(merged["vulnerabilities"]) == 1
    
    def test_cyclonedx_format_compliance(self, tmp_path):
        """Test conformité au format CycloneDX"""
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"name": "test", "version": "1.0.0"}
            ]
        }
        
        (sbom_dir / "test.cdx.json").write_text(json.dumps(sbom))
        
        sboms = load_sbom_files(sbom_dir)
        merged = merge_sboms(sboms)
        
        # Vérifier les champs requis
        required_fields = [
            "bomFormat",
            "specVersion",
            "serialNumber",
            "version",
            "metadata",
            "components"
        ]
        
        for field in required_fields:
            assert field in merged, f"Champ requis manquant: {field}"
        
        # Vérifier les valeurs
        assert merged["bomFormat"] == "CycloneDX"
        assert merged["specVersion"] == "1.6"
        assert merged["serialNumber"].startswith("urn:uuid:")
        assert merged["version"] == 1
    
    def test_deduplication_across_sources(self, tmp_path):
        """Test déduplication entre différentes sources"""
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        # Même composant dans deux sources différentes
        sbom1 = {
            "components": [
                {
                    "bom-ref": "pkg:pypi/requests@2.31.0",
                    "name": "requests",
                    "version": "2.31.0"
                }
            ]
        }
        
        sbom2 = {
            "components": [
                {
                    "bom-ref": "pkg:pypi/requests@2.31.0",
                    "name": "requests",
                    "version": "2.31.0"
                }
            ]
        }
        
        (sbom_dir / "source1.cdx.json").write_text(json.dumps(sbom1))
        (sbom_dir / "source2.cdx.json").write_text(json.dumps(sbom2))
        
        sboms = load_sbom_files(sbom_dir)
        merged = merge_sboms(sboms)
        
        # Doit avoir seulement 1 composant, pas 2
        assert len(merged["components"]) == 1
    
    def test_metadata_timestamp_format(self, tmp_path):
        """Test format du timestamp dans metadata"""
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        sbom = {"components": [{"name": "test", "version": "1.0.0"}]}
        (sbom_dir / "test.cdx.json").write_text(json.dumps(sbom))
        
        sboms = load_sbom_files(sbom_dir)
        merged = merge_sboms(sboms)
        
        timestamp = merged["metadata"]["timestamp"]
        
        # Vérifier format ISO 8601 avec timezone
        assert timestamp.endswith("Z")
        assert "T" in timestamp
        
        # Vérifier que c'est parsable
        from datetime import datetime
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


class TestErrorHandling:
    """Tests de gestion d'erreurs"""
    
    def test_missing_directory(self):
        """Test avec dossier inexistant"""
        result = find_dockerfiles(Path("/nonexistent/path"))
        assert result == []
    
    def test_invalid_json_sbom(self, tmp_path):
        """Test avec SBOM JSON invalide"""
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        # Créer un fichier JSON invalide
        (sbom_dir / "invalid.cdx.json").write_text("{ invalid json")
        
        # Ne doit pas crasher
        with pytest.raises(json.JSONDecodeError):
            load_sbom_files(sbom_dir)
    
    def test_permission_denied(self, tmp_path):
        """Test avec permissions insuffisantes"""
        if sys.platform == "win32":
            pytest.skip("Test non applicable sur Windows")
        
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        protected_dir.chmod(0o000)
        
        try:
            # Ne doit pas crasher
            result = find_dockerfiles(protected_dir)
            # Sur certains systèmes, peut retourner une liste vide
            assert isinstance(result, list)
        finally:
            protected_dir.chmod(0o755)


class TestPerformance:
    """Tests de performance"""
    
    def test_large_sbom_merge(self, tmp_path):
        """Test fusion de gros SBOM"""
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        # Créer un gros SBOM avec beaucoup de composants
        large_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "bom-ref": f"pkg{i}",
                    "name": f"package{i}",
                    "version": "1.0.0"
                }
                for i in range(1000)
            ]
        }
        
        (sbom_dir / "large.cdx.json").write_text(json.dumps(large_sbom))
        
        import time
        start = time.time()
        
        sboms = load_sbom_files(sbom_dir)
        merged = merge_sboms(sboms)
        
        duration = time.time() - start
        
        # Doit se terminer en moins de 5 secondes
        assert duration < 5.0
        assert len(merged["components"]) == 1000
    
    def test_many_sbom_files(self, tmp_path):
        """Test avec beaucoup de fichiers SBOM"""
        sbom_dir = tmp_path / "sbom"
        sbom_dir.mkdir()
        
        # Créer beaucoup de petits SBOM
        for i in range(50):
            sbom = {
                "components": [
                    {"bom-ref": f"pkg{i}", "name": f"package{i}", "version": "1.0.0"}
                ]
            }
            (sbom_dir / f"sbom{i}.cdx.json").write_text(json.dumps(sbom))
        
        import time
        start = time.time()
        
        sboms = load_sbom_files(sbom_dir)
        merged = merge_sboms(sboms)
        
        duration = time.time() - start
        
        # Doit se terminer rapidement
        assert duration < 3.0
        assert len(sboms) == 50
        assert len(merged["components"]) == 50
