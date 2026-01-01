import os
import subprocess
from pathlib import Path
import re

# Liste des fichiers de dépendances à scanner
DEPENDENCY_FILES = [
    "requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock", "packages.lock.json", "pom.xml", "build.gradle"
]

# Versions stables par défaut
DEFAULT_VERSIONS = {
    "GO_VERSION": "1.24",
    "NODE_VERSION": "22",
    "PYTHON_VERSION": "3.13",
    "RUST_VERSION": "1.83",
    "JAVA_VERSION": "21",
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
    # Utiliser le répertoire de travail actuel (dépôt appelant)
    root_dir = Path.cwd()
    sbom_dir = root_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)
    print(f"Recherche des fichiers de dépendances dans : {root_dir}")
    dep_files = find_dependency_files(root_dir)
    print(f"Fichiers trouvés : {dep_files}")

    for dep_file in dep_files:
        # Tous les fichiers de sortie dans sbom/ avec nom unique
        out_file = sbom_dir / (dep_file.name + ".cdx.json")

        print(f"Scan Trivy CycloneDX : {dep_file} -> {out_file}")
        # Conversion des chemins relatifs en format POSIX pour Docker
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
    
    print(f"Scan terminé. Tous les SBOM sont dans : {sbom_dir}")
    dockerfiles = find_dockerfiles(root_dir)
    print(f"Dockerfiles trouvés : {dockerfiles}")
    
    for dockerfile in dockerfiles:
        # Extraire les build args nécessaires
        build_args = extract_build_args(dockerfile)
        print(f"📝 Build args détectés pour {dockerfile.name}: {build_args}")
        
        image_tag = f"sbom-scan-{dockerfile.parent.name.lower()}"
        print(f"Build de l'image Docker : {dockerfile} -> {image_tag}")
        
        # Construire la commande avec les build-args
        build_cmd = [
            "docker", "build",
            "-f", str(dockerfile),
            "-t", image_tag,
        ]
        
        # Ajouter les --build-arg
        for arg_name, arg_value in build_args.items():
            build_cmd.extend(["--build-arg", f"{arg_name}={arg_value}"])
        
        build_cmd.append(str(dockerfile.parent))
        
        print(f"🔨 Commande: {' '.join(build_cmd)}")
        subprocess.run(build_cmd, check=True)
        
        # Scan de l'image Docker
        out_file = sbom_dir / (dockerfile.parent.name + "-image.cdx.json")
        print(f"Scan Trivy CycloneDX de l'image : {image_tag} -> {out_file}")
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
