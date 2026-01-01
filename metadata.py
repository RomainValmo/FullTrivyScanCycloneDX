# generate_metadata.py
import json
from pathlib import Path
import os

def generate_metadata():
    """Génère un fichier metadata.json avec les infos de source pour chaque composant"""
    root_dir = Path.cwd()
    sbom_dir = root_dir / "sbom"
    
    # Charger le SBOM fusionné
    merged_sbom_file = sbom_dir / "merged-sbom.cdx.json"
    if not merged_sbom_file.exists():
        print("SBOM fusionné introuvable")
        return
    
    with open(merged_sbom_file, 'r', encoding='utf-8') as f:
        merged_sbom = json.load(f)
    
    # Créer un mapping bom-ref -> source file
    component_sources = {}
    
    # Parcourir tous les fichiers SBOM individuels pour tracer la source
    for sbom_file in sbom_dir.glob("*.cdx.json"):
        if sbom_file.name == "merged-sbom.cdx.json":
            continue
        
        # Extraire le nom du fichier source depuis le nom du SBOM
        # Ex: "requirements.txt.cdx.json" -> "requirements.txt"
        # Ex: "backend-image.cdx.json" -> "Dockerfile (backend)"
        source_name = sbom_file.stem.replace(".cdx", "")
        
        # Déterminer le type de source
        if "-image.cdx" in sbom_file.name:
            source_type = "docker-image"
            source_file = f"Dockerfile ({source_name.replace('-image', '')})"
        else:
            source_type = "dependency-file"
            source_file = source_name
        
        # Charger le SBOM individuel
        with open(sbom_file, 'r', encoding='utf-8') as f:
            sbom = json.load(f)
        
        # Mapper chaque composant à sa source
        for component in sbom.get("components", []):
            bom_ref = component.get("bom-ref")
            purl = component.get("purl")
            comp_key = bom_ref or purl
            
            if comp_key and comp_key not in component_sources:
                component_sources[comp_key] = {
                    "source_file": source_file,
                    "source_type": source_type,
                    "package_name": component.get("name"),
                    "version": component.get("version"),
                    "purl": purl
                }
    
    # Enrichir avec les informations de vulnérabilités
    vulnerabilities_metadata = []
    for vuln in merged_sbom.get("vulnerabilities", []):
        vuln_id = vuln.get("id")
        
        # Extraire les packages affectés avec leur source
        affected_packages = []
        for affect in vuln.get("affects", []):
            ref = affect.get("ref")
            if ref in component_sources:
                source_info = component_sources[ref]
                
                # Extraire la version fixée
                fixed_version = None
                for version_info in affect.get("versions", []):
                    status = version_info.get("status", "").lower()
                    version = version_info.get("version")
                    # Chercher une version fixée
                    if status in ["unaffected", "fixed"] and version:
                        fixed_version = version
                        break
                
                affected_packages.append({
                    "package_name": source_info["package_name"],
                    "installed_version": source_info["version"],
                    "fixed_version": fixed_version,
                    "source_file": source_info["source_file"],
                    "source_type": source_info["source_type"],
                    "purl": source_info["purl"]
                })
        
        if affected_packages:
            vulnerabilities_metadata.append({
                "vulnerability_id": vuln_id,
                "affected_packages": affected_packages
            })
    
    # Créer le fichier metadata.json
    metadata = {
        "generated_at": merged_sbom.get("metadata", {}).get("timestamp"),
        "repository": os.environ.get('GITHUB_REPOSITORY', 'unknown/unknown'),
        "branch": os.environ.get('GITHUB_REF_NAME', 'unknown'),
        "commit": os.environ.get('GITHUB_SHA', 'unknown'),
        "run_id": os.environ.get('GITHUB_RUN_ID', 'unknown'),
        "component_sources": component_sources,
        "vulnerabilities": vulnerabilities_metadata,
        "stats": {
            "total_components": len(component_sources),
            "total_vulnerabilities": len(vulnerabilities_metadata)
        }
    }
    
    # Sauvegarder
    metadata_file = sbom_dir / "metadata.json"
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Métadonnées générées : {metadata_file}")
    print(f"   - {len(component_sources)} composants tracés")
    print(f"   - {len(vulnerabilities_metadata)} vulnérabilités enrichies")

if __name__ == "__main__":
    generate_metadata()