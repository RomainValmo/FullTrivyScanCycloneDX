"""Tests unitaires pour merge_sbom.py"""
import pytest
from pathlib import Path
import json

from merge_sbom import load_sbom_files, merge_sboms


class TestLoadSbomFiles:
    """Tests pour la fonction load_sbom_files"""
    
    def test_load_sbom_files_single(self, tmp_path):
        """Test chargement d'un seul fichier SBOM"""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "test", "version": "1.0.0"}]
        }
        
        sbom_file = tmp_path / "test.cdx.json"
        sbom_file.write_text(json.dumps(sbom_data))
        
        result = load_sbom_files(tmp_path)
        
        assert len(result) == 1
        assert result[0]["bomFormat"] == "CycloneDX"
    
    def test_load_sbom_files_multiple(self, tmp_path):
        """Test chargement de plusieurs fichiers SBOM"""
        for i in range(3):
            sbom_data = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"name": f"test{i}", "version": "1.0.0"}]
            }
            (tmp_path / f"test{i}.cdx.json").write_text(json.dumps(sbom_data))
        
        result = load_sbom_files(tmp_path)
        
        assert len(result) == 3
    
    def test_load_sbom_files_empty_directory(self, tmp_path):
        """Test avec dossier vide"""
        result = load_sbom_files(tmp_path)
        
        assert len(result) == 0
    
    def test_load_sbom_files_ignore_non_cdx(self, tmp_path):
        """Test ignore les fichiers non .cdx.json"""
        sbom_data = {"bomFormat": "CycloneDX"}
        (tmp_path / "test.cdx.json").write_text(json.dumps(sbom_data))
        (tmp_path / "test.json").write_text("{}")
        (tmp_path / "test.txt").write_text("")
        
        result = load_sbom_files(tmp_path)
        
        assert len(result) == 1


class TestMergeSboms:
    """Tests pour la fonction merge_sboms"""
    
    def test_merge_sboms_empty_list(self):
        """Test avec liste vide"""
        result = merge_sboms([])
        
        assert result == {}
    
    def test_merge_sboms_single(self):
        """Test fusion d'un seul SBOM"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"bom-ref": "pkg1", "name": "package1", "version": "1.0.0"}
            ],
            "metadata": {
                "tools": {
                    "components": [{"name": "trivy", "version": "0.50.0"}]
                }
            }
        }
        
        result = merge_sboms([sbom])
        
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.6"
        assert len(result["components"]) == 1
        assert result["components"][0]["name"] == "package1"
    
    def test_merge_sboms_no_duplicates_by_bomref(self):
        """Test pas de doublons par bom-ref"""
        sbom1 = {
            "components": [
                {"bom-ref": "pkg1", "name": "package1", "version": "1.0.0"}
            ]
        }
        sbom2 = {
            "components": [
                {"bom-ref": "pkg1", "name": "package1", "version": "1.0.0"}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["components"]) == 1
    
    def test_merge_sboms_no_duplicates_by_purl(self):
        """Test pas de doublons par purl"""
        sbom1 = {
            "components": [
                {"purl": "pkg:pypi/requests@2.31.0", "name": "requests", "version": "2.31.0"}
            ]
        }
        sbom2 = {
            "components": [
                {"purl": "pkg:pypi/requests@2.31.0", "name": "requests", "version": "2.31.0"}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["components"]) == 1
    
    def test_merge_sboms_no_duplicates_by_name_version(self):
        """Test pas de doublons par name@version"""
        sbom1 = {
            "components": [
                {"name": "flask", "version": "2.3.0"}
            ]
        }
        sbom2 = {
            "components": [
                {"name": "flask", "version": "2.3.0"}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["components"]) == 1
    
    def test_merge_sboms_multiple_components(self):
        """Test fusion de multiples composants différents"""
        sbom1 = {
            "components": [
                {"bom-ref": "pkg1", "name": "package1", "version": "1.0.0"}
            ]
        }
        sbom2 = {
            "components": [
                {"bom-ref": "pkg2", "name": "package2", "version": "2.0.0"}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["components"]) == 2
    
    def test_merge_sboms_tools(self):
        """Test fusion des outils"""
        sbom1 = {
            "metadata": {
                "tools": {
                    "components": [{"name": "trivy", "version": "0.50.0"}]
                }
            }
        }
        sbom2 = {
            "metadata": {
                "tools": {
                    "components": [{"name": "trivy", "version": "0.50.0"}]
                }
            }
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        # Pas de doublon pour les outils
        assert len(result["metadata"]["tools"]["components"]) == 1
    
    def test_merge_sboms_dependencies(self):
        """Test fusion des dépendances"""
        sbom1 = {
            "dependencies": [
                {"ref": "pkg1", "dependsOn": ["pkg2"]}
            ]
        }
        sbom2 = {
            "dependencies": [
                {"ref": "pkg2", "dependsOn": []}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["dependencies"]) == 2
    
    def test_merge_sboms_vulnerabilities(self):
        """Test fusion des vulnérabilités"""
        sbom1 = {
            "vulnerabilities": [
                {"id": "CVE-2023-0001", "affects": []}
            ]
        }
        sbom2 = {
            "vulnerabilities": [
                {"id": "CVE-2023-0002", "affects": []}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["vulnerabilities"]) == 2
    
    def test_merge_sboms_no_duplicate_vulnerabilities(self):
        """Test pas de doublons dans les vulnérabilités"""
        sbom1 = {
            "vulnerabilities": [
                {"id": "CVE-2023-0001", "affects": []}
            ]
        }
        sbom2 = {
            "vulnerabilities": [
                {"id": "CVE-2023-0001", "affects": []}
            ]
        }
        
        result = merge_sboms([sbom1, sbom2])
        
        assert len(result["vulnerabilities"]) == 1
    
    def test_merge_sboms_cleanup_empty_vulnerabilities(self):
        """Test suppression de la clé vulnerabilities si vide"""
        sbom = {
            "components": [{"name": "test", "version": "1.0.0"}]
        }
        
        result = merge_sboms([sbom])
        
        assert "vulnerabilities" not in result
    
    def test_merge_sboms_metadata_structure(self):
        """Test structure des métadonnées"""
        sbom = {
            "components": [{"name": "test", "version": "1.0.0"}]
        }
        
        result = merge_sboms([sbom])
        
        assert "metadata" in result
        assert "timestamp" in result["metadata"]
        assert "component" in result["metadata"]
        assert result["metadata"]["component"]["type"] == "application"
    
    def test_merge_sboms_serial_number_format(self):
        """Test format du numéro de série"""
        sbom = {
            "components": [{"name": "test", "version": "1.0.0"}]
        }
        
        result = merge_sboms([sbom])
        
        assert "serialNumber" in result
        assert result["serialNumber"].startswith("urn:uuid:")
    
    def test_merge_sboms_spec_version(self):
        """Test version de la spec CycloneDX"""
        sbom = {
            "components": [{"name": "test", "version": "1.0.0"}]
        }
        
        result = merge_sboms([sbom])
        
        assert result["specVersion"] == "1.6"
        assert result["bomFormat"] == "CycloneDX"
