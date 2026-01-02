#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Full Trivy Scan with CycloneDX SBOM
Copyright (c) 2025 RomainValmo
Licensed under the MIT License - see LICENSE file for details

This module handles Trivy scanning for Dockerfiles and dependency files.
"""

import os
import subprocess
from pathlib import Path
import logging
import re
import json
import uuid
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)


DEPENDENCY_FILES = [
    "requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock", "packages.lock.json", "pom.xml", "build.gradle"
]

DEFAULT_VERSIONS = {
    "GO_VERSION": "1.24",
    "NODE_VERSION": "22",
    "PYTHON_VERSION": "3.13",
    "RUST_VERSION": "1.83",
    "JAVA_VERSION": "21",
    "PHP_VERSION": "8.2",
}

def extract_build_args(dockerfile: Path) -> dict:
    """
    Extrait les ARG depuis un Dockerfile et retourne les build-args à passer.
    """
    build_args = {}
    with open(dockerfile, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Trouver tous les ARG dans le Dockerfile
    arg_pattern = r'ARG\s+([A-Z_]+)(?:=([^\s]+))?'
    for match in re.finditer(arg_pattern, content):
        arg_name = match.group(1)
        default_value = match.group(2)
        
        # Utiliser la valeur par défaut du Dockerfile ou notre mapping
        if arg_name in DEFAULT_VERSIONS:
            build_args[arg_name] = DEFAULT_VERSIONS[arg_name]
        elif default_value:
            build_args[arg_name] = default_value
        else:
            # Si pas de défaut, essayer de deviner
            build_args[arg_name] = DEFAULT_VERSIONS.get(arg_name, "latest")
    
    return build_args

def detect_runtime_components(image_tag: str) -> list:
    """
    Détecte les runtimes (PHP, Python, Node, Ruby, etc.) installés dans l'image
    et retourne une liste de composants CycloneDX.
    """
    components = []
    
    # Détection PHP
    try:
        php_check = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint=", image_tag, "which", "php"],
            capture_output=True, text=True, timeout=10
        )
        if php_check.returncode == 0:
            php_version_output = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint=", image_tag, "php", "-v"],
                capture_output=True, text=True, timeout=10
            )
            if php_version_output.returncode == 0:
                # Extraire version PHP (ex: PHP 8.2.15)
                match = re.search(r'PHP (\d+\.\d+\.\d+)', php_version_output.stdout)
                if match:
                    php_version = match.group(1)
                    components.append({
                        "bom-ref": str(uuid.uuid4()),
                        "type": "application",
                        "name": "php",
                        "version": php_version,
                        "purl": f"pkg:generic/php@{php_version}",
                        "properties": [
                            {"name": "aquasecurity:trivy:PkgType", "value": "runtime"}
                        ]
                    })
                    logger.info(f"✅ Détecté PHP {php_version}")
                    
                    # Détecter les extensions PHP
                    php_modules = subprocess.run(
                        ["docker", "run", "--rm", "--entrypoint=", image_tag, "php", "-m"],
                        capture_output=True, text=True, timeout=10
                    )
                    if php_modules.returncode == 0:
                        for line in php_modules.stdout.split('\n'):
                            ext = line.strip()
                            if ext and not ext.startswith('[') and ext not in ['Zend', 'Core']:
                                components.append({
                                    "bom-ref": str(uuid.uuid4()),
                                    "type": "library",
                                    "name": f"php-{ext.lower()}",
                                    "version": php_version,
                                    "purl": f"pkg:generic/php-{ext.lower()}@{php_version}",
                                    "properties": [
                                        {"name": "aquasecurity:trivy:PkgType", "value": "php-extension"}
                                    ]
                                })
    except Exception as e:
        logger.debug(f"PHP detection failed: {e}")
    
    # Détection Python
    try:
        python_check = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint=", image_tag, "sh", "-c", "which python3 || which python"],
            capture_output=True, text=True, timeout=10
        )
        if python_check.returncode == 0:
            python_cmd = "python3" if "python3" in python_check.stdout else "python"
            python_version_output = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint=", image_tag, python_cmd, "--version"],
                capture_output=True, text=True, timeout=10
            )
            if python_version_output.returncode == 0:
                match = re.search(r'Python (\d+\.\d+\.\d+)', python_version_output.stdout)
                if match:
                    python_version = match.group(1)
                    components.append({
                        "bom-ref": str(uuid.uuid4()),
                        "type": "application",
                        "name": "python",
                        "version": python_version,
                        "purl": f"pkg:generic/python@{python_version}",
                        "properties": [
                            {"name": "aquasecurity:trivy:PkgType", "value": "runtime"}
                        ]
                    })
                    logger.info(f"✅ Détecté Python {python_version}")
    except Exception as e:
        logger.debug(f"Python detection failed: {e}")
    
    # Détection Node.js
    try:
        node_check = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint=", image_tag, "which", "node"],
            capture_output=True, text=True, timeout=10
        )
        if node_check.returncode == 0:
            node_version_output = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint=", image_tag, "node", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if node_version_output.returncode == 0:
                node_version = node_version_output.stdout.strip().lstrip('v')
                components.append({
                    "bom-ref": str(uuid.uuid4()),
                    "type": "application",
                    "name": "node",
                    "version": node_version,
                    "purl": f"pkg:generic/node@{node_version}",
                    "properties": [
                        {"name": "aquasecurity:trivy:PkgType", "value": "runtime"}
                    ]
                })
                logger.info(f"✅ Détecté Node.js {node_version}")
    except Exception as e:
        logger.debug(f"Node.js detection failed: {e}")
    
    # Détection Ruby
    try:
        ruby_check = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint=", image_tag, "which", "ruby"],
            capture_output=True, text=True, timeout=10
        )
        if ruby_check.returncode == 0:
            ruby_version_output = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint=", image_tag, "ruby", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if ruby_version_output.returncode == 0:
                match = re.search(r'ruby (\d+\.\d+\.\d+)', ruby_version_output.stdout)
                if match:
                    ruby_version = match.group(1)
                    components.append({
                        "bom-ref": str(uuid.uuid4()),
                        "type": "application",
                        "name": "ruby",
                        "version": ruby_version,
                        "purl": f"pkg:generic/ruby@{ruby_version}",
                        "properties": [
                            {"name": "aquasecurity:trivy:PkgType", "value": "runtime"}
                        ]
                    })
                    logger.info(f"✅ Détecté Ruby {ruby_version}")
    except Exception as e:
        logger.debug(f"Ruby detection failed: {e}")
    
    return components

def merge_cyclonedx_sboms(base_sbom_path: Path, runtime_components: list) -> None:
    """
    Fusionne les composants runtime détectés dans le SBOM CycloneDX existant.
    """
    try:
        # Lire le fichier généré par Trivy
        with open(base_sbom_path, 'r', encoding='utf-8') as f:
            sbom = json.load(f)
        
        if "components" not in sbom:
            sbom["components"] = []
        
        # Ajouter les composants runtime
        sbom["components"].extend(runtime_components)
        
        # Mettre à jour le timestamp
        if "metadata" not in sbom:
            sbom["metadata"] = {}
        sbom["metadata"]["timestamp"] = datetime.now(datetime.UTC).isoformat().replace('+00:00', 'Z')
        
        # Supprimer l'ancien fichier et créer un nouveau avec les bonnes permissions
        os.remove(base_sbom_path)
        with open(base_sbom_path, 'w', encoding='utf-8') as f:
            json.dump(sbom, f, indent=2)
        
        logger.info(f"✅ SBOM enrichi avec {len(runtime_components)} composants runtime")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la fusion des SBOM: {e}")

def find_dockerfiles(root_dir: Path, max_depth: int = 3):
    dockerfiles = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        rel_path = Path(dirpath).relative_to(root_dir)
        if len(rel_path.parts) > max_depth:
            continue
        for fname in filenames:
            if fname.lower().startswith("dockerfile") or fname.lower().endswith(".dockerfile"):
                dockerfiles.append(Path(dirpath) / fname)
    return dockerfiles

def find_dependency_files(root_dir: Path, max_depth: int = 4):
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        rel_path = Path(dirpath).relative_to(root_dir)
        if len(rel_path.parts) > max_depth:
            continue
        for fname in filenames:
            if fname in DEPENDENCY_FILES:
                files.append(Path(dirpath) / fname)
    return files

if __name__ == "__main__":
    root_dir = Path.cwd()
    sbom_dir = root_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)
    logger.info(f"Recherche des fichiers de dépendances dans : {root_dir}")
    dep_files = find_dependency_files(root_dir)
    logger.info(f"Fichiers trouvés : {dep_files}")

    for dep_file in dep_files:
        out_file = sbom_dir / (dep_file.name + ".cdx.json")

        logger.info(f"Scan Trivy CycloneDX : {dep_file} -> {out_file}")

        out_file_posix = str(out_file.relative_to(root_dir)).replace('\\', '/')
        dep_file_posix = str(dep_file.relative_to(root_dir)).replace('\\', '/')
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{root_dir}:/project",
            "aquasec/trivy:latest", "fs",
            "--format", "cyclonedx",
            "--scanners", "vuln",
            "--output", f"/project/sbom/{dep_file.name}.cdx.json",
            f"/project/{dep_file_posix}"
        ]
        subprocess.run(cmd, check=True)
    
    logger.info(f"Scan terminé. Tous les SBOM sont dans : {sbom_dir}")

    dockerfiles = find_dockerfiles(root_dir)
    logger.info(f"Dockerfiles trouvés : {dockerfiles}")
    
    for dockerfile in dockerfiles:
        build_args = extract_build_args(dockerfile)
        logger.info(f"📝 Build args détectés pour {dockerfile.name}: {build_args}")
        
        image_tag = f"sbom-scan-{dockerfile.parent.name.lower()}"
        logger.info(f"Build de l'image Docker : {dockerfile} -> {image_tag}")
        
        build_cmd = [
            "docker", "build",
            "-f", str(dockerfile),
            "-t", image_tag,
        ]
        
        for arg_name, arg_value in build_args.items():
            build_cmd.extend(["--build-arg", f"{arg_name}={arg_value}"])
        
        build_cmd.append(str(dockerfile.parent))
        
        logger.info(f"🔨 Commande: {' '.join(build_cmd)}")
        subprocess.run(build_cmd, check=True)
        
        out_file = sbom_dir / (dockerfile.parent.name + "-image.cdx.json")
        logger.info(f"Scan Trivy CycloneDX de l'image : {image_tag} -> {out_file}")
        scan_cmd = [
            "docker", "run", "--rm",
            "-v", f"{root_dir}:/project",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "aquasec/trivy:latest", "image",
            "--format", "cyclonedx",
            "--scanners", "vuln",
            "--output", f"/project/sbom/{dockerfile.parent.name}-image.cdx.json",
            image_tag
        ]
        subprocess.run(scan_cmd, check=True)
        
        # Détection des runtimes
        logger.info(f"🔍 Détection des runtimes dans {image_tag}...")
        runtime_components = detect_runtime_components(image_tag)
        
        if runtime_components:
            merge_cyclonedx_sboms(out_file, runtime_components)
        
        # Cleanup de l'image
        subprocess.run(["docker", "rmi", image_tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
