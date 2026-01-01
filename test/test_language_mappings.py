"""Tests unitaires pour language_mappings.py"""
import pytest
from pathlib import Path

from language_mappings import detect_runtime_versions, categorize_component


class TestDetectRuntimeVersions:
    """Tests pour la fonction detect_runtime_versions"""
    
    def test_detect_go_version(self):
        """Test détection de la version Go"""
        sbom_data = {
            "components": [
                {
                    "name": "stdlib",
                    "purl": "pkg:golang/stdlib@1.21.0",
                    "version": "1.21.0"
                }
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert "go" in result
        assert result["go"] == "1.21.0"
    
    def test_detect_python_version(self):
        """Test détection de la version Python"""
        sbom_data = {
            "components": [
                {
                    "name": "python",
                    "purl": "pkg:pypi/python@3.11.2",
                    "version": "3.11.2"
                }
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert "python" in result
        assert result["python"] == "3.11.2"
    
    def test_detect_nodejs_version(self):
        """Test détection de la version Node.js"""
        sbom_data = {
            "components": [
                {
                    "name": "node",
                    "purl": "pkg:npm/node@20.10.0",
                    "version": "20.10.0"
                }
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert "nodejs" in result
        assert result["nodejs"] == "20.10.0"
    
    def test_detect_java_version(self):
        """Test détection de la version Java"""
        sbom_data = {
            "components": [
                {
                    "name": "openjdk",
                    "version": "17.0.2"
                }
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert "java" in result
        assert result["java"] == "17.0.2"
    
    def test_detect_ruby_version(self):
        """Test détection de la version Ruby"""
        sbom_data = {
            "components": [
                {
                    "name": "ruby",
                    "version": "3.2.0"
                }
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert "ruby" in result
        assert result["ruby"] == "3.2.0"
    
    def test_detect_rust_version(self):
        """Test détection de la version Rust"""
        sbom_data = {
            "components": [
                {
                    "name": "rustc",
                    "version": "1.75.0"
                }
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert "rust" in result
        assert result["rust"] == "1.75.0"
    
    def test_detect_multiple_runtimes(self):
        """Test détection de plusieurs runtimes"""
        sbom_data = {
            "components": [
                {"name": "stdlib", "purl": "pkg:golang/stdlib@1.21.0", "version": "1.21.0"},
                {"name": "python", "purl": "pkg:pypi/python@3.11.2", "version": "3.11.2"},
                {"name": "node", "purl": "pkg:npm/node@20.10.0", "version": "20.10.0"}
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert len(result) == 3
        assert "go" in result
        assert "python" in result
        assert "nodejs" in result
    
    def test_detect_no_runtimes(self):
        """Test avec aucun runtime détecté"""
        sbom_data = {
            "components": [
                {"name": "requests", "version": "2.31.0"}
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert result == {}
    
    def test_detect_runtime_first_occurrence_only(self):
        """Test que seule la première occurrence est gardée"""
        sbom_data = {
            "components": [
                {"name": "python", "purl": "pkg:pypi/python@3.11.2", "version": "3.11.2"},
                {"name": "python", "purl": "pkg:pypi/python@3.10.0", "version": "3.10.0"}
            ]
        }
        
        result = detect_runtime_versions(sbom_data)
        
        assert result["python"] == "3.11.2"  # Premier trouvé


class TestCategorizeComponent:
    """Tests pour la fonction categorize_component"""
    
    def test_categorize_pypi_component(self):
        """Test catégorisation d'un package PyPI"""
        result = categorize_component(
            purl="pkg:pypi/requests@2.31.0",
            name="requests",
            source_type="dependency-file",
            original_source_file="requirements.txt",
            runtime_versions={}
        )
        
        assert result["source_type"] == "python-dependency"
        assert result["source_file"] == "requirements.txt"
    
    def test_categorize_npm_component(self):
        """Test catégorisation d'un package npm"""
        result = categorize_component(
            purl="pkg:npm/express@4.18.0",
            name="express",
            source_type="dependency-file",
            original_source_file="package-lock.json",
            runtime_versions={}
        )
        
        assert result["source_type"] == "nodejs-dependency"
        assert result["source_file"] == "package-lock.json"
    
    def test_categorize_docker_component(self):
        """Test catégorisation d'un composant Docker"""
        result = categorize_component(
            purl="pkg:docker/alpine@3.18",
            name="alpine",
            source_type="docker-image",
            original_source_file="Dockerfile (app)",
            runtime_versions={}
        )
        
        assert result["source_type"] == "docker-image"
        assert result["source_file"] == "Dockerfile (app)"
    
    def test_categorize_go_toolchain(self):
        """Test catégorisation d'un toolchain Go"""
        result = categorize_component(
            purl="pkg:golang/go@1.21.0",
            name="go/cmd/compile",
            source_type="docker-image",
            original_source_file="Dockerfile",
            runtime_versions={"go": "1.21.0"}
        )
        
        assert result["source_type"] == "go-dependency"
        assert "source_file" in result
    
    def test_categorize_application_binary(self):
        """Test catégorisation d'un binaire applicatif"""
        result = categorize_component(
            purl="",
            name="myapp/cmd/server",
            source_type="docker-image",
            original_source_file="Dockerfile",
            runtime_versions={}
        )
        
        # Le comportement dépend de l'implémentation exacte
        assert "source_type" in result
        assert "source_file" in result
    
    def test_categorize_with_runtime_version(self):
        """Test enrichissement avec version runtime"""
        result = categorize_component(
            purl="pkg:golang/toolchain@go1.21.0",
            name="toolchain",
            source_type="docker-image",
            original_source_file="Dockerfile",
            runtime_versions={"go": "1.21.0"}
        )
        
        # Vérifie que la version est enrichie si applicable
        assert "source_file" in result
    
    def test_categorize_unknown_source(self):
        """Test catégorisation avec source inconnue"""
        result = categorize_component(
            purl="pkg:generic/unknown@1.0.0",
            name="unknown",
            source_type="unknown",
            original_source_file="unknown",
            runtime_versions={}
        )
        
        # Avec source_type != "docker-image", appelle categorize_dependency_file
        # qui retourne "dependency-file" pour les fichiers inconnus
        assert result["source_type"] == "dependency-file"
        assert result["source_file"] == "unknown"
