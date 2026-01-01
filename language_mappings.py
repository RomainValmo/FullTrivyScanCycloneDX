"""
Mappings des composants par langage pour catégoriser les sources correctement.
"""

def categorize_component(purl: str, name: str, source_type: str, original_source_file: str) -> dict:
    """
    Catégorise un composant selon son type (langage, OS, toolchain, etc.)
    
    Returns:
        dict avec 'source_type' et 'source_file'
    """
    if source_type != "docker-image":
        # Pour les scans directs de fichiers de dépendances
        return categorize_dependency_file(original_source_file)
    
    # Pour les composants d'images Docker
    
    # === Go ===
    if purl.startswith("pkg:golang/"):
        if "stdlib" in name or name == "stdlib":
            return {"source_type": "go-runtime", "source_file": original_source_file}
        elif "usr/local/go" in name or "bin/go" in name:
            return {"source_type": "go-toolchain", "source_file": original_source_file}
        else:
            return {"source_type": "go-dependency", "source_file": "go.sum"}
    
    # === Python ===
    if purl.startswith("pkg:pypi/"):
        if "python" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "site-packages"]):
            return {"source_type": "python-runtime", "source_file": original_source_file}
        else:
            return {"source_type": "python-dependency", "source_file": detect_python_file(original_source_file)}
    
    # === Node.js / JavaScript ===
    if purl.startswith("pkg:npm/"):
        if "node" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "/opt/"]):
            return {"source_type": "nodejs-runtime", "source_file": original_source_file}
        else:
            return {"source_type": "nodejs-dependency", "source_file": detect_nodejs_file(original_source_file)}
    
    # === Java ===
    if purl.startswith("pkg:maven/") or purl.startswith("pkg:gradle/"):
        if "jdk" in name.lower() or "jre" in name.lower() or "openjdk" in name.lower():
            return {"source_type": "java-runtime", "source_file": original_source_file}
        else:
            return {"source_type": "java-dependency", "source_file": detect_java_file(original_source_file)}
    
    # === Ruby ===
    if purl.startswith("pkg:gem/"):
        if "ruby" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "/opt/"]):
            return {"source_type": "ruby-runtime", "source_file": original_source_file}
        else:
            return {"source_type": "ruby-dependency", "source_file": "Gemfile.lock"}
    
    # === Rust ===
    if purl.startswith("pkg:cargo/"):
        if "rust" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "rustc", "cargo"]):
            return {"source_type": "rust-toolchain", "source_file": original_source_file}
        else:
            return {"source_type": "rust-dependency", "source_file": "Cargo.lock"}
    
    # === PHP ===
    if purl.startswith("pkg:composer/"):
        if "php" in name.lower() and any(x in name for x in ["/usr/", "/bin/", "/opt/"]):
            return {"source_type": "php-runtime", "source_file": original_source_file}
        else:
            return {"source_type": "php-dependency", "source_file": "composer.lock"}
    
    # === .NET / C# ===
    if purl.startswith("pkg:nuget/"):
        if "dotnet" in name.lower() or "aspnet" in name.lower():
            return {"source_type": "dotnet-runtime", "source_file": original_source_file}
        else:
            return {"source_type": "dotnet-dependency", "source_file": "packages.lock.json"}
    
    # === Packages OS ===
    if purl.startswith(("pkg:apk/", "pkg:deb/", "pkg:rpm/")):
        return {"source_type": "os-package", "source_file": original_source_file}
    
    # === Images OS de base ===
    if name in ["alpine", "debian", "ubuntu", "centos", "fedora", "rhel"] and not purl:
        return {"source_type": "os-image", "source_file": original_source_file}
    
    # === Binaires applicatifs ===
    if name.startswith(("bin/", "usr/bin/", "usr/local/bin/", "opt/")):
        return {"source_type": "application-binary", "source_file": original_source_file}
    
    # === Par défaut ===
    return {"source_type": "docker-image", "source_file": original_source_file}


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
