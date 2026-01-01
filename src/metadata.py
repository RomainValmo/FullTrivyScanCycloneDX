#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Full Trivy Scan with CycloneDX SBOM
Copyright (c) 2025 RomainValmo
Licensed under the MIT License - see LICENSE file for details

This module generates enriched metadata from merged SBOMs with Trivy vulnerability data.
"""

import json
from pathlib import Path
import os
import subprocess
from language_mappings import categorize_component, detect_runtime_versions
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)


def run_trivy_sbom_enrichment(sbom_dir: Path) -> tuple[Path, dict]:
    """
    Enrichit le SBOM avec Trivy (fixed_version, status, etc.)
    Retourne le SBOM enrichi + un mapping CVE -> FixedVersion
    """
    input_sbom = sbom_dir / "merged-sbom.cdx.json"
    output_sbom = sbom_dir / "merged-sbom.enriched.cdx.json"
    output_json = sbom_dir / "merged-sbom.enriched.json"

    print("🔎 Enrichissement SBOM via Trivy…")

    # Scan CycloneDX
    subprocess.run(
        [
            "trivy", "sbom",
            str(input_sbom),
            "--scanners", "vuln",
            "--format", "cyclonedx",
            "--output", str(output_sbom),
            "--skip-db-update",
            "--quiet",
        ],
        check=True,
    )

    # Scan JSON pour extraire les FixedVersion
    subprocess.run(
        [
            "trivy", "sbom",
            str(input_sbom),
            "--scanners", "vuln",
            "--format", "json",
            "--output", str(output_json),
            "--skip-db-update",
            "--quiet",
        ],
        check=True,
    )

    # Extraire les FixedVersion depuis le JSON
    vuln_fixed_versions = {}
    with open(output_json, "r", encoding="utf-8") as f:
        trivy_json = json.load(f)
    
    for result in trivy_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vuln_id = vuln.get("VulnerabilityID")
            fixed_version = vuln.get("FixedVersion")
            if vuln_id and fixed_version:
                # Stocker toutes les fixed versions pour cette CVE
                if vuln_id not in vuln_fixed_versions:
                    vuln_fixed_versions[vuln_id] = []
                if fixed_version not in vuln_fixed_versions[vuln_id]:
                    vuln_fixed_versions[vuln_id].append(fixed_version)

    return output_sbom, vuln_fixed_versions


def detect_fix_status(fixed_version, version_infos):
    """
    Détermine un statut humainement compréhensible
    """
    if fixed_version:
        return "fixed"

    for v in version_infos:
        if v.get("status") == "affected" and not v.get("version"):
            return "patched-no-version-bump"

    return "unknown"


def generate_metadata():
    root_dir = Path.cwd()
    sbom_dir = root_dir / "sbom"

    # 🔥 Enrichissement Trivy (CycloneDX + JSON pour FixedVersion)
    enriched_sbom_file, vuln_fixed_versions = run_trivy_sbom_enrichment(sbom_dir)

    with open(enriched_sbom_file, "r", encoding="utf-8") as f:
        merged_sbom = json.load(f)

    component_sources = {}
    runtime_versions = {}  # Cache pour les versions runtime détectées

    # Première passe : détecter les versions runtime depuis tous les SBOMs
    for sbom_file in sbom_dir.glob("*.cdx.json"):
        if "merged-sbom" in sbom_file.name:
            continue
        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom = json.load(f)
        detected = detect_runtime_versions(sbom)
        if detected:
            logger.info(f"  Détecté dans {sbom_file.name}: {detected}")
        runtime_versions.update(detected)
    
    if runtime_versions:
        logger.info(f"🔍 Versions runtime détectées (total) : {runtime_versions}")
    else:
        logger.warning("⚠️ Aucune version runtime détectée !")

    # Créer un mapping ref -> source pour déterminer d'où vient chaque composant
    ref_to_source = {}
    for sbom_file in sbom_dir.glob("*.cdx.json"):
        if "merged-sbom" in sbom_file.name:
            continue

        source_name = sbom_file.stem.replace(".cdx", "")

        if "-image" in sbom_file.name:
            source_type = "docker-image"
            source_file = f"Dockerfile ({source_name.replace('-image', '')})"
        else:
            source_type = "dependency-file"
            source_file = source_name

        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom = json.load(f)

        for component in sbom.get("components", []):
            ref = component.get("bom-ref") or component.get("purl")
            if ref and ref not in ref_to_source:
                ref_to_source[ref] = {
                    "source_type": source_type,
                    "source_file": source_file,
                }

    # Deuxième passe : modifier les composants dans le SBOM fusionné
    for component in merged_sbom.get("components", []):
        ref = component.get("bom-ref") or component.get("purl")
        name = component.get("name", "")
        version = component.get("version")
        purl = component.get("purl", "")
        
        if not ref:
            continue
            
        # Récupérer la source d'origine
        source_info = ref_to_source.get(ref, {"source_type": "unknown", "source_file": "unknown"})
        
        # Catégoriser le composant
        category = categorize_component(purl, name, source_info["source_type"], source_info["source_file"], runtime_versions)
        
        # Debug pour les outils toolchain
        if "toolchain" in category.get("source_type", ""):
            logger.info(f"  🔧 Toolchain: {name} -> type={category['source_type']}, version={category.get('version', 'NONE')}")
        
        # Enrichir la version si disponible
        if "version" in category:
            version = category["version"]
            component["version"] = version
        
        # Nettoyer le nom du package pour les outils toolchain/binaires
        clean_name = name
        if category["source_type"] in ["go-toolchain", "application-binary"]:
            clean_name = name.split("/")[-1] if "/" in name else name
            component["name"] = clean_name
        
        # Stocker dans component_sources
        component_sources[ref] = {
            "package_name": clean_name,
            "version": version,
            "purl": purl,
            "source_file": category["source_file"],
            "source_type": category["source_type"],
        }

    vulnerabilities_metadata = []

    for vuln in merged_sbom.get("vulnerabilities", []):
        vuln_id = vuln.get("id")
        affected_packages = []

        for affect in vuln.get("affects", []):
            ref = affect.get("ref")
            if ref not in component_sources:
                continue

            source_info = component_sources[ref]
            fixed_version = None

            # Essayer d'abord depuis le CycloneDX
            for v in affect.get("versions", []):
                if v.get("status") in ["fixed", "unaffected"] and v.get("version"):
                    fixed_version = v["version"]
                    break

            # Si pas trouvé, utiliser le JSON
            if not fixed_version and vuln_id in vuln_fixed_versions:
                # Prendre la première version disponible (ou les joindre si multiples)
                fixed_versions_list = vuln_fixed_versions[vuln_id]
                fixed_version = ", ".join(fixed_versions_list) if len(fixed_versions_list) > 1 else fixed_versions_list[0]

            fix_status = detect_fix_status(fixed_version, affect.get("versions", []))

            affected_packages.append({
                "package_name": source_info["package_name"],
                "installed_version": source_info["version"],
                "fixed_version": fixed_version,
                "fix_status": fix_status,
                "source_file": source_info["source_file"],
                "source_type": source_info["source_type"],
                "purl": source_info["purl"],
            })

        if affected_packages:
            vulnerabilities_metadata.append({
                "vulnerability_id": vuln_id,
                "affected_packages": affected_packages,
            })

    metadata = {
        "generated_at": merged_sbom.get("metadata", {}).get("timestamp"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "unknown/unknown"),
        "branch": os.environ.get("GITHUB_REF_NAME", "unknown"),
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
        "component_sources": component_sources,
        "vulnerabilities": vulnerabilities_metadata,
        "stats": {
            "total_components": len(component_sources),
            "total_vulnerabilities": len(vulnerabilities_metadata),
        },
    }

    output = sbom_dir / "metadata.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    merged_sbom_original = sbom_dir / "merged-sbom.cdx.json"
    with open(merged_sbom_original, "w", encoding="utf-8") as f:
        json.dump(merged_sbom, f, indent=2, ensure_ascii=False)

    logger.info("✨ metadata.json généré avec succès")
    logger.info(f"   • composants : {len(component_sources)}")
    logger.info(f"   • vulnérabilités : {len(vulnerabilities_metadata)}")
    logger.info("✨ SBOMs mis à jour avec les noms propres et versions enrichies")

if __name__ == "__main__":
    generate_metadata()
