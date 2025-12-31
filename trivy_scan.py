#!/usr/bin/env python3
"""
Trivy Scan GitHub Action
Performs security scanning and generates CycloneDX SBOM using Trivy
"""

import os
import sys
import subprocess
import json


def set_output(name, value):
    """Set GitHub Action output"""
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}")


def run_trivy_scan(scan_type, target, format_type, output_file, severity, vuln_type, exit_code, trivy_version):
    """Run Trivy scan with specified parameters"""
    
    print(f"Starting Trivy scan...")
    print(f"Scan type: {scan_type}")
    print(f"Target: {target}")
    print(f"Format: {format_type}")
    print(f"Output file: {output_file}")
    print(f"Severity: {severity}")
    print(f"Vulnerability types: {vuln_type}")
    
    # Build the Trivy command
    cmd = [
        "trivy",
        scan_type,
        target,
        "--format", format_type,
        "--output", output_file,
        "--severity", severity,
        "--vuln-type", vuln_type,
        "--exit-code", exit_code
    ]
    
    # Add additional flags based on scan type
    if scan_type == "fs":
        cmd.extend(["--scanners", "vuln,config,secret"])
    
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True
        )
        
        print(f"Trivy scan completed with exit code: {result.returncode}")
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        # Set outputs
        set_output("sbom-file", output_file)
        
        # Generate scan summary
        summary = generate_summary(output_file, format_type, result.returncode)
        set_output("scan-summary", summary)
        
        # Check if output file was created
        if os.path.exists(output_file):
            print(f"✓ SBOM file created successfully: {output_file}")
            file_size = os.path.getsize(output_file)
            print(f"  File size: {file_size} bytes")
        else:
            print(f"⚠ Warning: Output file not created: {output_file}")
        
        return result.returncode
        
    except Exception as e:
        print(f"Error running Trivy scan: {e}")
        return 1


def generate_summary(output_file, format_type, exit_code):
    """Generate a summary of the scan results"""
    summary = f"Scan completed with exit code {exit_code}"
    
    if os.path.exists(output_file):
        try:
            file_size = os.path.getsize(output_file)
            summary += f" | Output: {output_file} ({file_size} bytes)"
            
            # If format is JSON, try to parse and count findings
            if format_type in ["cyclonedx", "json"] and file_size > 0:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                    # CycloneDX format
                    if "components" in data:
                        component_count = len(data.get("components", []))
                        summary += f" | Components: {component_count}"
                    
                    # Regular Trivy JSON format
                    if "Results" in data:
                        vuln_count = sum(
                            len(result.get("Vulnerabilities", []))
                            for result in data.get("Results", [])
                        )
                        summary += f" | Vulnerabilities: {vuln_count}"
        except Exception as e:
            print(f"Error generating detailed summary: {e}")
    
    return summary


def main():
    """Main entry point for the action"""
    print("=" * 60)
    print("Full Trivy Scan with CycloneDX SBOM Generator")
    print("=" * 60)
    
    # Get inputs from command line arguments
    if len(sys.argv) < 8:
        print("Error: Missing required arguments")
        sys.exit(1)
    
    scan_type = sys.argv[1]
    target = sys.argv[2]
    format_type = sys.argv[3]
    output_file = sys.argv[4]
    severity = sys.argv[5]
    vuln_type = sys.argv[6]
    exit_code = sys.argv[7]
    trivy_version = sys.argv[8] if len(sys.argv) > 8 else "latest"
    
    # Run the scan
    result_code = run_trivy_scan(
        scan_type,
        target,
        format_type,
        output_file,
        severity,
        vuln_type,
        exit_code,
        trivy_version
    )
    
    print("=" * 60)
    print(f"Scan finished with exit code: {result_code}")
    print("=" * 60)
    
    sys.exit(result_code)


if __name__ == "__main__":
    main()
