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
from datetime import datetime, timezone
import argparse
import yaml
import shutil
import tempfile
import shutil
import tempfile
import shutil
import tempfile

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
        sbom["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
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


def find_github_workflows(root_dir: Path) -> list:
    """
    Détecte les fichiers workflow GitHub Actions dans .github/workflows/
    
    Args:
        root_dir: Répertoire racine du projet
        
    Returns:
        Liste des chemins vers les fichiers workflow trouvés
    """
    workflows_dir = root_dir / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    
    workflows = []
    for file in workflows_dir.glob("*.yml"):
        workflows.append(file)
    for file in workflows_dir.glob("*.yaml"):
        workflows.append(file)
    
    logger.info(f"📋 Workflows GitHub Actions trouvés : {len(workflows)}")
    return workflows


def extract_actions_from_workflow(workflow_file: Path) -> list:
    """
    Parse un fichier workflow YAML et extrait toutes les actions GitHub utilisées.
    
    Args:
        workflow_file: Chemin vers le fichier workflow
        
    Returns:
        Liste de dictionnaires avec owner, repo, version, full_name pour chaque action
    """
    try:
        with open(workflow_file, 'r', encoding='utf-8') as f:
            workflow = yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"⚠️ Impossible de parser {workflow_file}: {e}")
        return []
    
    if not workflow or not isinstance(workflow, dict):
        return []
    
    actions = []
    jobs = workflow.get('jobs', {})
    
    for job_name, job_config in jobs.items():
        if not isinstance(job_config, dict):
            continue
        steps = job_config.get('steps', [])
        for step in steps:
            if isinstance(step, dict) and 'uses' in step:
                action = step['uses']
                # Filtrer les actions locales (./....)
                if not action.startswith('./'):
                    # Parser l'action: owner/repo@version ou owner/repo/path@version
                    if '@' in action:
                        action_name, version = action.rsplit('@', 1)
                    else:
                        action_name = action
                        version = "main"  # Par défaut main au lieu de latest
                    
                    # Parser owner/repo (ignorer les sous-chemins)
                    parts = action_name.split('/')
                    if len(parts) >= 2:
                        owner = parts[0]
                        repo = parts[1]
                        
                        actions.append({
                            'owner': owner,
                            'repo': repo,
                            'version': version,
                            'full_name': f"{owner}/{repo}@{version}"
                        })
    
    return actions


def clone_github_action_repo(owner: str, repo: str, version: str, base_temp_dir: Path) -> Path:
    """
    Clone un repo GitHub Action dans un dossier temporaire.
    
    Args:
        owner: Propriétaire du repo (ex: 'actions')
        repo: Nom du repo (ex: 'checkout')
        version: Branche, tag ou SHA (ex: 'v4', 'main')
        base_temp_dir: Répertoire temporaire de base
        
    Returns:
        Chemin vers le repo cloné
    """
    repo_url = f"https://github.com/{owner}/{repo}.git"
    clone_dir = base_temp_dir / f"{owner}-{repo}-{version.replace('/', '-')}"
    
    # Supprimer si existe déjà (pour éviter les conflits)
    if clone_dir.exists():
        shutil.rmtree(clone_dir)
    
    logger.info(f"📥 Clonage de {repo_url} @ {version}...")
    
    try:
        # Clone shallow avec une seule branche
        cmd = [
            "git", "clone",
            "--depth", "1",
            "--branch", version,
            "--single-branch",
            repo_url,
            str(clone_dir)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            # Si la branche n'existe pas, essayer sans --branch (pour les SHA)
            logger.info(f"  Tentative de clone sans branche spécifique...")
            cmd_no_branch = [
                "git", "clone",
                "--depth", "1",
                repo_url,
                str(clone_dir)
            ]
            subprocess.run(cmd_no_branch, check=True, capture_output=True, timeout=60)
            
            # Checkout de la version spécifique
            subprocess.run(
                ["git", "checkout", version],
                cwd=str(clone_dir),
                check=True,
                capture_output=True,
                timeout=30
            )
        
        logger.info(f"✅ Repo cloné dans {clone_dir}")
        return clone_dir
    
    except subprocess.TimeoutExpired:
        logger.error(f"❌ Timeout lors du clone de {owner}/{repo}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Erreur lors du clone de {owner}/{repo}: {e.stderr}")
        raise


def scan_github_action_repo(action_info: dict, clone_dir: Path, sbom_dir: Path, root_dir: Path):
    """
    Scanne un repo GitHub Action cloné avec les méthodes existantes.
    
    Args:
        action_info: Dict avec owner, repo, version, full_name
        clone_dir: Répertoire du repo cloné
        sbom_dir: Répertoire de sortie pour les SBOM
        root_dir: Répertoire racine du projet principal (pour Docker)
    """
    owner = action_info['owner']
    repo = action_info['repo']
    version = action_info['version']
    full_name = action_info['full_name']
    
    logger.info(f"\n🔍 Scan de {full_name}...")
    
    # Scanner les fichiers de dépendances
    dep_files = find_dependency_files(clone_dir, max_depth=4)
    logger.info(f"  Fichiers de dépendances trouvés : {len(dep_files)}")
    
    for dep_file in dep_files:
        out_file = sbom_dir / f"{owner}-{repo}-{dep_file.name}.cdx.json"
        logger.info(f"  Scan Trivy : {dep_file.name}")
        
        dep_file_posix = dep_file.relative_to(clone_dir).as_posix()
        
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{clone_dir}:/project",
            "aquasec/trivy:latest", "fs",
            "--format", "cyclonedx",
            "--scanners", "vuln",
            "--output", f"/project/{out_file.name}",
            f"/project/{dep_file_posix}"
        ]
        
        try:
            subprocess.run(cmd, check=True, timeout=120)
            
            # Déplacer le fichier généré vers sbom_dir
            generated_file = clone_dir / out_file.name
            if generated_file.exists():
                shutil.move(str(generated_file), str(out_file))
                
                # Enrichir le SBOM avec les métadonnées de l'action
                with open(out_file, 'r', encoding='utf-8') as f:
                    sbom = json.load(f)
                
                # Ajouter des propriétés à tous les composants
                for component in sbom.get('components', []):
                    if 'properties' not in component:
                        component['properties'] = []
                    component['properties'].extend([
                        {"name": "github-action:owner", "value": owner},
                        {"name": "github-action:repo", "value": repo},
                        {"name": "github-action:version", "value": version},
                        {"name": "source-file", "value": dep_file.name}
                    ])
                
                with open(out_file, 'w', encoding='utf-8') as f:
                    json.dump(sbom, f, indent=2)
                
                logger.info(f"  ✅ SBOM généré : {out_file.name}")
        
        except subprocess.TimeoutExpired:
            logger.warning(f"  ⚠️ Timeout lors du scan de {dep_file.name}")
        except Exception as e:
            logger.warning(f"  ⚠️ Erreur lors du scan de {dep_file.name}: {e}")
    
    # Scanner les Dockerfiles
    dockerfiles = find_dockerfiles(clone_dir, max_depth=3)
    logger.info(f"  Dockerfiles trouvés : {len(dockerfiles)}")
    
    for dockerfile in dockerfiles:
        try:
            build_args = extract_build_args(dockerfile)
            logger.info(f"  📝 Build args pour {dockerfile.name}: {build_args}")
            
            image_tag = f"sbom-action-{owner}-{repo}-{dockerfile.parent.name.lower()}"
            logger.info(f"  Build Docker : {image_tag}")
            
            build_cmd = [
                "docker", "build",
                "-f", str(dockerfile),
                "-t", image_tag,
            ]
            
            for arg_name, arg_value in build_args.items():
                build_cmd.extend(["--build-arg", f"{arg_name}={arg_value}"])
            
            build_cmd.append(str(dockerfile.parent))
            
            subprocess.run(build_cmd, check=True, timeout=300)
            
            out_file = sbom_dir / f"{owner}-{repo}-{dockerfile.parent.name}-image.cdx.json"
            scan_cmd = [
                "docker", "run", "--rm",
                "-v", f"{root_dir}:/project",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "aquasec/trivy:latest", "image",
                "--format", "cyclonedx",
                "--scanners", "vuln",
                "--output", f"/project/sbom/{out_file.name}",
                image_tag
            ]
            subprocess.run(scan_cmd, check=True, timeout=120)
            
            # Enrichir avec métadonnées
            if out_file.exists():
                with open(out_file, 'r', encoding='utf-8') as f:
                    sbom = json.load(f)
                
                for component in sbom.get('components', []):
                    if 'properties' not in component:
                        component['properties'] = []
                    component['properties'].extend([
                        {"name": "github-action:owner", "value": owner},
                        {"name": "github-action:repo", "value": repo},
                        {"name": "github-action:version", "value": version},
                        {"name": "source-file", "value": dockerfile.name}
                    ])
                
                with open(out_file, 'w', encoding='utf-8') as f:
                    json.dump(sbom, f, indent=2)
            
            logger.info(f"  ✅ Image scannée : {image_tag}")
            
            # Cleanup
            subprocess.run(["docker", "rmi", image_tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        except subprocess.TimeoutExpired:
            logger.warning(f"  ⚠️ Timeout lors du build/scan de {dockerfile.name}")
        except Exception as e:
            logger.warning(f"  ⚠️ Erreur lors du scan de {dockerfile.name}: {e}")


if __name__ == "__main__":
    # Parser les arguments de ligne de commande
    parser = argparse.ArgumentParser(description="Full Trivy Scan with CycloneDX SBOM")
    parser.add_argument(
        "--scan-github-actions",
        type=str,
        default="false",
        help="Scan GitHub Actions workflows (true/false)"
    )
    args = parser.parse_args()
    
    # Convertir la chaîne en booléen
    scan_github_actions = args.scan_github_actions.lower() in ('true', '1', 'yes')
    
    root_dir = Path.cwd()
    sbom_dir = root_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)
    
    logger.info("=== Full Trivy Scan avec CycloneDX SBOM ===")
    logger.info(f"Répertoire racine : {root_dir}")
    logger.info(f"Scan GitHub Actions : {scan_github_actions}")
    
    # Scan des fichiers de dépendances
    dep_files = find_dependency_files(root_dir)
    logger.info(f"Fichiers de dépendances trouvés : {dep_files}")
    
    for dep_file in dep_files:
        out_file = sbom_dir / (dep_file.name + ".cdx.json")
        logger.info(f"Scan Trivy CycloneDX : {dep_file} -> {out_file}")
        
        dep_file_posix = dep_file.relative_to(root_dir).as_posix()
        
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

    # Scan des Dockerfiles
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
    
    # Scan des workflows GitHub Actions (si activé)
    if scan_github_actions:
        logger.info("\n=== Scan des workflows GitHub Actions ===")
        workflows = find_github_workflows(root_dir)
        
        if workflows:
            # Créer un dossier temporaire pour cloner les repos
            temp_dir = Path(tempfile.mkdtemp(prefix="github-actions-"))
            logger.info(f"📁 Dossier temporaire : {temp_dir}")
            
            try:
                # Extraire toutes les actions uniques
                all_actions = {}
                for workflow in workflows:
                    logger.info(f"\n📋 Analyse du workflow : {workflow.name}")
                    actions = extract_actions_from_workflow(workflow)
                    
                    for action in actions:
                        full_name = action['full_name']
                        if full_name not in all_actions:
                            all_actions[full_name] = action
                            logger.info(f"  ✓ {full_name}")
                
                if all_actions:
                    logger.info(f"\n🔍 {len(all_actions)} actions uniques à scanner")
                    
                    # Scanner chaque action
                    for action_info in all_actions.values():
                        try:
                            # Clone le repo
                            clone_dir = clone_github_action_repo(
                                action_info['owner'],
                                action_info['repo'],
                                action_info['version'],
                                temp_dir
                            )
                            
                            # Scanne le repo cloné
                            scan_github_action_repo(action_info, clone_dir, sbom_dir, root_dir)
                            
                        except Exception as e:
                            logger.error(f"❌ Erreur lors du scan de {action_info['full_name']}: {e}")
                            continue
                else:
                    logger.info("Aucune action externe trouvée dans les workflows")
            
            finally:
                # Cleanup du dossier temporaire
                logger.info(f"\n🗑️ Nettoyage du dossier temporaire...")
                shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            logger.info("Aucun workflow GitHub Actions trouvé dans .github/workflows/")
    
    logger.info("\n✅ Scan terminé avec succès")
