"""Tests unitaires pour trivy_scan.py"""
import pytest
from pathlib import Path
import tempfile
import shutil

from trivy_scan import (
    extract_build_args, 
    find_dockerfiles, 
    find_dependency_files, 
    find_github_workflows, 
    extract_actions_from_workflow
)


class TestExtractBuildArgs:
    """Tests pour la fonction extract_build_args"""
    
    def test_extract_build_args_with_defaults(self, tmp_path):
        """Test extraction des ARG avec valeurs par défaut"""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.11
ARG GO_VERSION=1.23
ARG CUSTOM_ARG=default_value
RUN echo "Test"
""")
        
        result = extract_build_args(dockerfile)
        
        assert "GO_VERSION" in result
        assert result["GO_VERSION"] == "1.24"  # Remplacé par DEFAULT_VERSIONS
        assert "CUSTOM_ARG" in result
        assert result["CUSTOM_ARG"] == "default_value"
    
    def test_extract_build_args_without_defaults(self, tmp_path):
        """Test extraction des ARG sans valeurs par défaut"""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM node:22
ARG NODE_VERSION
ARG UNKNOWN_ARG
RUN npm install
""")
        
        result = extract_build_args(dockerfile)
        
        assert "NODE_VERSION" in result
        assert result["NODE_VERSION"] == "22"  # De DEFAULT_VERSIONS
        assert "UNKNOWN_ARG" in result
        assert result["UNKNOWN_ARG"] == "latest"  # Valeur par défaut
    
    def test_extract_build_args_no_args(self, tmp_path):
        """Test avec Dockerfile sans ARG"""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM alpine:latest
RUN echo "No args"
""")
        
        result = extract_build_args(dockerfile)
        
        assert result == {}
    
    def test_extract_build_args_multiple_versions(self, tmp_path):
        """Test avec plusieurs ARG de versions"""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM ubuntu:22.04
ARG GO_VERSION
ARG PYTHON_VERSION
ARG RUST_VERSION
ARG JAVA_VERSION
""")
        
        result = extract_build_args(dockerfile)
        
        assert result["GO_VERSION"] == "1.24"
        assert result["PYTHON_VERSION"] == "3.13"
        assert result["RUST_VERSION"] == "1.83"
        assert result["JAVA_VERSION"] == "21"


class TestFindDockerfiles:
    """Tests pour la fonction find_dockerfiles"""
    
    def test_find_dockerfiles_root(self, tmp_path):
        """Test détection Dockerfile à la racine"""
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        
        result = find_dockerfiles(tmp_path)
        
        assert len(result) == 1
        assert result[0].name == "Dockerfile"
    
    def test_find_dockerfiles_multiple(self, tmp_path):
        """Test détection de plusieurs Dockerfiles"""
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        (tmp_path / "Dockerfile.dev").write_text("FROM alpine")
        (tmp_path / "app.dockerfile").write_text("FROM alpine")
        
        result = find_dockerfiles(tmp_path)
        
        assert len(result) == 3
        names = [f.name for f in result]
        assert "Dockerfile" in names
        assert "Dockerfile.dev" in names
        assert "app.dockerfile" in names
    
    def test_find_dockerfiles_subdirectories(self, tmp_path):
        """Test détection dans sous-dossiers"""
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "Dockerfile").write_text("FROM alpine")
        (tmp_path / "worker").mkdir()
        (tmp_path / "worker" / "Dockerfile.prod").write_text("FROM alpine")
        
        result = find_dockerfiles(tmp_path)
        
        assert len(result) == 2
    
    def test_find_dockerfiles_max_depth(self, tmp_path):
        """Test respect de la profondeur maximale"""
        # Créer une arborescence profonde
        deep_path = tmp_path / "a" / "b" / "c" / "d"
        deep_path.mkdir(parents=True)
        (deep_path / "Dockerfile").write_text("FROM alpine")
        
        # Avec max_depth=3, ne devrait pas trouver le Dockerfile
        result = find_dockerfiles(tmp_path, max_depth=3)
        
        assert len(result) == 0
    
    def test_find_dockerfiles_case_insensitive(self, tmp_path):
        """Test insensibilité à la casse"""
        (tmp_path / "dockerfile").write_text("FROM alpine")
        (tmp_path / "DOCKERFILE.TEST").write_text("FROM alpine")
        
        result = find_dockerfiles(tmp_path)
        
        assert len(result) == 2
    
    def test_find_dockerfiles_ignore_non_dockerfiles(self, tmp_path):
        """Test ignore les fichiers non-Dockerfile"""
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        (tmp_path / "README.md").write_text("# Test")
        (tmp_path / "script.sh").write_text("#!/bin/bash")
        (tmp_path / "notadockerfile.txt").write_text("test")
        
        result = find_dockerfiles(tmp_path)
        
        assert len(result) == 1
        assert result[0].name == "Dockerfile"


class TestFindDependencyFiles:
    """Tests pour la fonction find_dependency_files"""
    
    def test_find_dependency_files_python(self, tmp_path):
        """Test détection fichiers Python"""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0")
        (tmp_path / "poetry.lock").write_text("")
        
        result = find_dependency_files(tmp_path)
        
        assert len(result) == 2
        names = [f.name for f in result]
        assert "requirements.txt" in names
        assert "poetry.lock" in names
    
    def test_find_dependency_files_nodejs(self, tmp_path):
        """Test détection fichiers Node.js"""
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "yarn.lock").write_text("")
        
        result = find_dependency_files(tmp_path)
        
        assert len(result) == 2
    
    def test_find_dependency_files_multiple_languages(self, tmp_path):
        """Test détection multi-langages"""
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "package-lock.json").write_text("")
        (tmp_path / "go.sum").write_text("")
        (tmp_path / "Cargo.lock").write_text("")
        (tmp_path / "composer.lock").write_text("")
        
        result = find_dependency_files(tmp_path)
        
        assert len(result) == 5
    
    def test_find_dependency_files_subdirectories(self, tmp_path):
        """Test détection dans sous-dossiers"""
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "requirements.txt").write_text("")
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "package-lock.json").write_text("")
        
        result = find_dependency_files(tmp_path)
        
        assert len(result) == 2
    
    def test_find_dependency_files_max_depth(self, tmp_path):
        """Test respect de la profondeur maximale"""
        deep_path = tmp_path / "a" / "b" / "c" / "d" / "e"
        deep_path.mkdir(parents=True)
        (deep_path / "requirements.txt").write_text("")
        
        # Avec max_depth=4, ne devrait pas trouver le fichier
        result = find_dependency_files(tmp_path, max_depth=4)
        
        assert len(result) == 0
    
    def test_find_dependency_files_empty_directory(self, tmp_path):
        """Test avec dossier vide"""
        result = find_dependency_files(tmp_path)
        
        assert len(result) == 0
    
    def test_find_dependency_files_only_other_files(self, tmp_path):
        """Test avec seulement des fichiers non supportés"""
        (tmp_path / "README.md").write_text("")
        (tmp_path / "config.yml").write_text("")
        (tmp_path / "script.py").write_text("")
        
        result = find_dependency_files(tmp_path)
        
        assert len(result) == 0


class TestFindGitHubWorkflows:
    """Tests pour la fonction find_github_workflows"""
    
    def test_find_workflows_yml(self, tmp_path):
        """Test détection des workflows .yml"""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "test.yml").write_text("name: Test")
        (workflows_dir / "build.yml").write_text("name: Build")
        
        result = find_github_workflows(tmp_path)
        
        assert len(result) == 2
        names = [f.name for f in result]
        assert "test.yml" in names
        assert "build.yml" in names
    
    def test_find_workflows_yaml(self, tmp_path):
        """Test détection des workflows .yaml"""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "deploy.yaml").write_text("name: Deploy")
        
        result = find_github_workflows(tmp_path)
        
        assert len(result) == 1
        assert result[0].name == "deploy.yaml"
    
    def test_find_workflows_mixed_extensions(self, tmp_path):
        """Test détection mélange .yml et .yaml"""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI")
        (workflows_dir / "cd.yaml").write_text("name: CD")
        
        result = find_github_workflows(tmp_path)
        
        assert len(result) == 2
    
    def test_find_workflows_no_directory(self, tmp_path):
        """Test sans répertoire .github/workflows"""
        result = find_github_workflows(tmp_path)
        
        assert len(result) == 0
    
    def test_find_workflows_empty_directory(self, tmp_path):
        """Test avec répertoire vide"""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        
        result = find_github_workflows(tmp_path)
        
        assert len(result) == 0
    
    def test_find_workflows_ignore_other_files(self, tmp_path):
        """Test ignore les fichiers non-workflow"""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "test.yml").write_text("name: Test")
        (workflows_dir / "README.md").write_text("# Workflows")
        (workflows_dir / "config.json").write_text("{}")
        
        result = find_github_workflows(tmp_path)
        
        assert len(result) == 1
        assert result[0].name == "test.yml"


class TestExtractActionsFromWorkflow:
    """Tests pour la fonction extract_actions_from_workflow"""
    
    def test_extract_single_action(self, tmp_path):
        """Test extraction d'une seule action"""
        workflow = tmp_path / "test.yml"
        workflow.write_text("""
name: Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 1
        assert result[0]['owner'] == "actions"
        assert result[0]['repo'] == "checkout"
        assert result[0]['version'] == "v4"
        assert result[0]['full_name'] == "actions/checkout@v4"
    
    def test_extract_multiple_actions(self, tmp_path):
        """Test extraction de plusieurs actions"""
        workflow = tmp_path / "ci.yml"
        workflow.write_text("""
name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - uses: actions/upload-artifact@v4
""")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 3
        names = [a['full_name'] for a in result]
        assert "actions/checkout@v4" in names
        assert "actions/setup-python@v5" in names
        assert "actions/upload-artifact@v4" in names
    
    def test_extract_multiple_jobs(self, tmp_path):
        """Test extraction depuis plusieurs jobs"""
        workflow = tmp_path / "workflow.yml"
        workflow.write_text("""
name: Multi-Job
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
  build:
    steps:
      - uses: actions/setup-node@v4
""")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 2
    
    def test_ignore_local_actions(self, tmp_path):
        """Test ignore les actions locales"""
        workflow = tmp_path / "test.yml"
        workflow.write_text("""
name: Test
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/local-action
      - uses: ./scripts/custom-action
""")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 1
        assert result[0]['full_name'] == "actions/checkout@v4"
    
    def test_extract_no_uses(self, tmp_path):
        """Test workflow sans actions uses"""
        workflow = tmp_path / "test.yml"
        workflow.write_text("""
name: Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run command
        run: echo "Hello"
""")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 0
    
    def test_invalid_yaml(self, tmp_path):
        """Test avec YAML invalide"""
        workflow = tmp_path / "invalid.yml"
        workflow.write_text("invalid: yaml: content: ][")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 0
    
    def test_empty_workflow(self, tmp_path):
        """Test workflow vide"""
        workflow = tmp_path / "empty.yml"
        workflow.write_text("")
        
        result = extract_actions_from_workflow(workflow)
        
        assert len(result) == 0
