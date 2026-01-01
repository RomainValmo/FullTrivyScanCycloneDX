"""Fixtures pytest communes pour tous les tests"""
import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def temp_dir():
    """Crée un dossier temporaire pour les tests"""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_dockerfile(tmp_path):
    """Crée un Dockerfile d'exemple"""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
""")
    return dockerfile


@pytest.fixture
def sample_requirements(tmp_path):
    """Crée un fichier requirements.txt d'exemple"""
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("""
requests==2.31.0
flask==2.3.0
pytest==7.4.0
""")
    return requirements


@pytest.fixture
def sample_sbom():
    """Retourne un SBOM CycloneDX d'exemple"""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-123",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "tools": {
                "components": [
                    {"name": "trivy", "version": "0.50.0"}
                ]
            },
            "component": {
                "bom-ref": "test-app",
                "type": "application",
                "name": "test-app"
            }
        },
        "components": [
            {
                "bom-ref": "pkg:pypi/requests@2.31.0",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0"
            }
        ],
        "dependencies": [],
        "vulnerabilities": []
    }
