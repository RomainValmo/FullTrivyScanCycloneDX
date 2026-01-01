import json
from pathlib import Path
from datetime import datetime
import uuid

def load_sbom_files(sbom_dir: Path):
    """Charge tous les fichiers .cdx.json du dossier sbom/"""
    sbom_files = list(sbom_dir.glob("*.cdx.json"))
    sboms = []
    for sbom_file in sbom_files:
        with open(sbom_file, 'r', encoding='utf-8') as f:
            sboms.append(json.load(f))
    return sboms

def merge_sboms(sboms: list) -> dict:
    """Fusionne plusieurs SBOM CycloneDX en un seul, sans doublons"""
    if not sboms:
        return {}
    
    # Structure de base du SBOM fusionné
    merged = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": {
                "components": []
            },
            "component": {
                "bom-ref": str(uuid.uuid4()),
                "type": "application",
                "name": "supply-chain-detector",
                "properties": []
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": []
    }
    
    # Pour déduplication
    seen_components = {}  # bom-ref ou purl -> component
    seen_vulnerabilities = {}  # id -> vuln
    seen_dependencies = {}  # ref -> dep
    seen_tools = {}  # name+version -> tool
    
    for sbom in sboms:
        # Fusionner les outils
        if "metadata" in sbom and "tools" in sbom["metadata"]:
            tools_comps = sbom["metadata"]["tools"].get("components", [])
            for tool in tools_comps:
                tool_key = f"{tool.get('name', '')}@{tool.get('version', '')}"
                if tool_key not in seen_tools:
                    seen_tools[tool_key] = tool
                    merged["metadata"]["tools"]["components"].append(tool)
        
        # Fusionner les composants
        for component in sbom.get("components", []):
            # Clé unique : bom-ref ou purl ou name+version
            bom_ref = component.get("bom-ref")
            purl = component.get("purl")
            name = component.get("name", "")
            version = component.get("version", "")
            
            comp_key = bom_ref or purl or f"{name}@{version}"
            
            if comp_key and comp_key not in seen_components:
                seen_components[comp_key] = component
                merged["components"].append(component)
        
        # Fusionner les dépendances
        for dep in sbom.get("dependencies", []):
            dep_ref = dep.get("ref")
            if dep_ref and dep_ref not in seen_dependencies:
                seen_dependencies[dep_ref] = dep
                merged["dependencies"].append(dep)
        
        # Fusionner les vulnérabilités (si présentes)
        for vuln in sbom.get("vulnerabilities", []):
            vuln_id = vuln.get("id")
            if vuln_id and vuln_id not in seen_vulnerabilities:
                seen_vulnerabilities[vuln_id] = vuln
                merged["vulnerabilities"].append(vuln)
    
    # Nettoyer les listes vides
    if not merged["vulnerabilities"]:
        del merged["vulnerabilities"]
    
    return merged

if __name__ == "__main__":
    # Utiliser le répertoire de travail actuel (dépôt appelant)
    root_dir = Path.cwd()
    sbom_dir = root_dir / "sbom"
    
    if not sbom_dir.exists():
        print(f"Dossier {sbom_dir} introuvable.")
        exit(1)
    
    print(f"Chargement des fichiers SBOM depuis : {sbom_dir}")
    sboms = load_sbom_files(sbom_dir)
    print(f"Fichiers SBOM trouvés : {len(sboms)}")
    
    if not sboms:
        print("Aucun fichier SBOM à fusionner.")
        exit(0)
    
    print("Fusion des SBOM...")
    merged_sbom = merge_sboms(sboms)
    
    # Statistiques
    total_components = len(merged_sbom.get("components", []))
    total_vulns = len(merged_sbom.get("vulnerabilities", []))
    print(f"SBOM fusionné : {total_components} composants, {total_vulns} vulnérabilités")
    
    # Sauvegarde du SBOM fusionné
    output_file = sbom_dir / "merged-sbom.cdx.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(merged_sbom, f, indent=2, ensure_ascii=False)
    
    print(f"SBOM fusionné sauvegardé dans : {output_file}")
