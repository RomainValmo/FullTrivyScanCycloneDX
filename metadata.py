# generate_metadata.py
import json
from pathlib import Path
import os
import subprocess


def run_trivy_sbom_enrichment(sbom_dir: Path) -> Path:
    """
    Enrichit le SBOM avec Trivy (fixed_version, status, etc.)
    """
    input_sbom = sbom_dir / "merged-sbom.cdx.json"
    output_sbom = sbom_dir / "merged-sbom.enriched.cdx.json"

    if output_sbom.exists():
        return output_sbom

    print("🔎 Enrichissement SBOM via Trivy…")

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

    return output_sbom


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

    # 🔥 Enrichissement Trivy
    enriched_sbom_file = run_trivy_sbom_enrichment(sbom_dir)

    with open(enriched_sbom_file, "r", encoding="utf-8") as f:
        merged_sbom = json.load(f)

    component_sources = {}

    # Mapper les composants → sources
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
            if ref and ref not in component_sources:
                component_sources[ref] = {
                    "package_name": component.get("name"),
                    "version": component.get("version"),
                    "purl": component.get("purl"),
                    "source_file": source_file,
                    "source_type": source_type,
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

            for v in affect.get("versions", []):
                if v.get("status") in ["fixed", "unaffected"] and v.get("version"):
                    fixed_version = v["version"]
                    break

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

    print("✨ metadata.json généré avec succès")
    print(f"   • composants : {len(component_sources)}")
    print(f"   • vulnérabilités : {len(vulnerabilities_metadata)}")


if __name__ == "__main__":
    generate_metadata()
