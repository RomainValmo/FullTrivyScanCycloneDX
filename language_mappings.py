"""
Mappings des composants par langage pour catégoriser les sources correctement.
"""
import re


def detect_runtime_versions(sbom_data: dict) -> dict:
    """
    Détecte les versions des runtimes (Go, Python, Node, etc.) depuis un SBOM
    pour enrichir les outils toolchain qui n'ont pas de version
    
    Returns:
        dict: {"go": "v1.24.11", "python": "3.11.2", ...}
    """
    versions = {}
    
    for component in sbom_data.get("components", []):
        name = component.get("name", "")
        purl = component.get("purl", "")
        version = component.get("version")
        
        # Go stdlib
        if name == "stdlib" and purl.startswith("pkg:golang/stdlib") and version:
            versions["go"] = version
        
        # Python runtime
        if "python" in name.lower() and purl.startswith("pkg:pypi/") and version:
            if "python" not in versions:
                versions["python"] = version
        
        # Node.js runtime
        if name == "node" and purl.startswith("pkg:npm/") and version:
            versions["nodejs"] = version
        
        # Java runtime
        if any(x in name.lower() for x in ["openjdk", "jre", "jdk"]) and version:
            if "java" not in versions:
                versions["java"] = version
        
        # Ruby runtime
        if name == "ruby" and version:
            versions["ruby"] = version
        
        # Rust toolchain
        if "rustc" in name.lower() and version:
            versions["rust"] = version
    
    return versions


def extract_distro_from_purl(purl: str, default: str) -> str:
    """
    Extrait le nom de la distribution depuis un purl
    Exemple: pkg:apk/alpine/bash@5.3.3-r1 -> alpine
             pkg:deb/debian/curl@7.88.1 -> debian
             pkg:deb/ubuntu/curl@7.88.1 -> ubuntu
    """
    match = re.search(r'pkg:(apk|deb|rpm)/([^/]+)/', purl)
    if match:
        distro = match.group(2).lower()
        return distro
    return default

def categorize_component(purl: str, name: str, source_type: str, original_source_file: str, runtime_versions: dict = None) -> dict:
    """
    Catégorise un composant selon son type (langage, OS, toolchain, etc.)
    
    Args:
        purl: Package URL
        name: Nom du composant
        source_type: Type de source (docker-image, dependency-file)
        original_source_file: Fichier source original
        runtime_versions: Dict des versions runtime détectées (ex: {"go": "v1.24.11"})
    
    Returns:
        dict avec 'source_type', 'source_file' et optionnellement 'version'
    """
    if runtime_versions is None:
        runtime_versions = {}
    
    if source_type != "docker-image":
        # Pour les scans directs de fichiers de dépendances
        return categorize_dependency_file(original_source_file)
    
    # Pour les composants d'images Docker
    result = {"source_type": "", "source_file": original_source_file}
    
    # === Go ===
    if purl.startswith("pkg:golang/"):
        if "stdlib" in name or name == "stdlib":
            result["source_type"] = "go-runtime"
        elif any(x in name for x in ["usr/local/go/pkg/tool/", "usr/local/go/bin/"]):
            result["source_type"] = "go-toolchain"
            # Enrichir avec version Go si disponible
            if "go" in runtime_versions:
                result["version"] = runtime_versions["go"]
        else:
            result["source_type"] = "go-dependency"
            result["source_file"] = "go.sum"
        return result
    
    # Outils Go sans purl (fichiers binaires détectés par scan filesystem)
    if any(x in name for x in ["usr/local/go/pkg/tool/", "usr/local/go/bin/"]):
        result["source_type"] = "go-toolchain"
        if "go" in runtime_versions:
            result["version"] = runtime_versions["go"]
        return result
    
    # === Python ===
    if purl.startswith("pkg:pypi/"):
        if "python" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "site-packages"]):
            result["source_type"] = "python-runtime"
        else:
            result["source_type"] = "python-dependency"
            result["source_file"] = detect_python_file(original_source_file)
        return result
    
    # === Node.js / JavaScript ===
    if purl.startswith("pkg:npm/"):
        if "node" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "/opt/"]):
            result["source_type"] = "nodejs-runtime"
        else:
            result["source_type"] = "nodejs-dependency"
            result["source_file"] = detect_nodejs_file(original_source_file)
        return result
    
    # === Java ===
    if purl.startswith("pkg:maven/") or purl.startswith("pkg:gradle/"):
        if "jdk" in name.lower() or "jre" in name.lower() or "openjdk" in name.lower():
            result["source_type"] = "java-runtime"
        else:
            result["source_type"] = "java-dependency"
            result["source_file"] = detect_java_file(original_source_file)
        return result
    
    # === Ruby ===
    if purl.startswith("pkg:gem/"):
        if "ruby" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "/opt/"]):
            result["source_type"] = "ruby-runtime"
        else:
            result["source_type"] = "ruby-dependency"
            result["source_file"] = "Gemfile.lock"
        return result
    
    # === Rust ===
    if purl.startswith("pkg:cargo/"):
        if "rust" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "rustc", "cargo"]):
            result["source_type"] = "rust-toolchain"
        else:
            result["source_type"] = "rust-dependency"
            result["source_file"] = "Cargo.lock"
        return result
    
    # === PHP ===
    if purl.startswith("pkg:composer/"):
        if "php" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "/opt/"]):
            result["source_type"] = "php-runtime"
        else:
            result["source_type"] = "php-dependency"
            result["source_file"] = "composer.lock"
        return result
    
    # === .NET / C# ===
    if purl.startswith("pkg:nuget/"):
        if "dotnet" in name.lower() or "aspnet" in name.lower():
            result["source_type"] = "dotnet-runtime"
        else:
            result["source_type"] = "dotnet-dependency"
            result["source_file"] = "packages.lock.json"
        return result
    
    # === Packages OS ===
    if purl.startswith("pkg:apk/"):
        distro = extract_distro_from_purl(purl, "alpine")
        result["source_type"] = f"os-package-{distro}"
        return result
    if purl.startswith("pkg:deb/"):
        distro = extract_distro_from_purl(purl, "debian")
        result["source_type"] = f"os-package-{distro}"
        return result
    if purl.startswith("pkg:rpm/"):
        distro = extract_distro_from_purl(purl, "rhel")
        result["source_type"] = f"os-package-{distro}"
        return result
    
    # === Images OS de base ===
    if name.lower() in ["alpine", "debian", "ubuntu", "centos", "fedora", "rhel", "rocky", "amazonlinux"] and not purl:
        result["source_type"] = f"os-image-{name.lower()}"
        return result
    
    # === Binaires applicatifs ===
    if name.startswith(("bin/", "usr/bin/", "usr/local/bin/", "opt/")):
        result["source_type"] = "application-binary"
        return result
    
    # === Par défaut ===
    result["source_type"] = "docker-image"
    return result


def categorize_dependency_file(source_file: str) -> dict:
    """
    Catégorise un fichier de dépendances selon son extension/nom
    """
    # Go
    if source_file.endswith((".sum", "go.mod")) or "go.sum" in source_file:
        return {"source_type": "go-dependency", "source_file": source_file}
    
    # Python
    if source_file.endswith(("requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock")):
        return {"source_type": "python-dependency", "source_file": source_file}
    
    # Node.js
    if source_file.endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        return {"source_type": "nodejs-dependency", "source_file": source_file}
    
    # Ruby
    if source_file.endswith("Gemfile.lock"):
        return {"source_type": "ruby-dependency", "source_file": source_file}
    
    # Rust
    if source_file.endswith("Cargo.lock"):
        return {"source_type": "rust-dependency", "source_file": source_file}
    
    # PHP
    if source_file.endswith("composer.lock"):
        return {"source_type": "php-dependency", "source_file": source_file}
    
    # Java
    if source_file.endswith(("pom.xml", "build.gradle", "gradle.lockfile")):
        return {"source_type": "java-dependency", "source_file": source_file}
    
    # .NET
    if source_file.endswith("packages.lock.json"):
        return {"source_type": "dotnet-dependency", "source_file": source_file}
    
    # Par défaut
    return {"source_type": "dependency-file", "source_file": source_file}


def detect_python_file(dockerfile_name: str) -> str:
    """Détecte le fichier de dépendances Python le plus probable"""
    # On pourrait améliorer en lisant les fichiers présents dans sbom/
    return "requirements.txt"


def detect_nodejs_file(dockerfile_name: str) -> str:
    """Détecte le fichier de dépendances Node.js le plus probable"""
    return "package-lock.json"


def detect_java_file(dockerfile_name: str) -> str:
    """Détecte le fichier de dépendances Java le plus probable"""
    return "pom.xml"
