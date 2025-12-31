# Full Trivy Scan with CycloneDX SBOM

A reusable GitHub Action to perform comprehensive security scanning using Trivy and generate CycloneDX Software Bill of Materials (SBOM).

## Features

- 🔍 Comprehensive security scanning with Trivy
- 📋 CycloneDX SBOM generation
- 🐳 Containerized for consistent execution
- 🔧 Highly configurable scan parameters
- 📊 Multiple output formats supported
- 🚀 Easy to integrate into any workflow

## Usage

### Basic Example

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy SBOM Scan
        uses: RomainValmo/FullTrivyScanCycloneDX@main
        with:
          scan-type: 'fs'
          target: '.'
          format: 'cyclonedx'
          output-file: 'sbom.json'
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### Advanced Example

```yaml
- name: Full Security Scan
  uses: RomainValmo/FullTrivyScanCycloneDX@main
  with:
    scan-type: 'fs'
    target: '.'
    format: 'cyclonedx'
    output-file: 'security-sbom.json'
    severity: 'HIGH,CRITICAL'
    vuln-type: 'os,library'
    exit-code: '1'
```

### Container Image Scanning

```yaml
- name: Scan Docker Image
  uses: RomainValmo/FullTrivyScanCycloneDX@main
  with:
    scan-type: 'image'
    target: 'myapp:latest'
    format: 'cyclonedx'
    output-file: 'image-sbom.json'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan-type` | Type of scan (`fs`, `image`, `config`, etc.) | No | `fs` |
| `target` | Target to scan (path or image name) | No | `.` |
| `format` | Output format (`cyclonedx`, `json`, `table`, `sarif`) | No | `cyclonedx` |
| `output-file` | Path for scan results | No | `trivy-sbom.json` |
| `severity` | Severities to detect (comma-separated) | No | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL` |
| `vuln-type` | Vulnerability types (`os`, `library`) | No | `os,library` |
| `exit-code` | Exit code when vulnerabilities found | No | `0` |
| `trivy-version` | Trivy version to use | No | `latest` |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom-file` | Path to the generated SBOM file |
| `scan-summary` | Summary of scan results |

## Scan Types

- **`fs`** - Filesystem scan (default)
- **`image`** - Container image scan
- **`config`** - Configuration file scan
- **`repo`** - Repository scan
- **`rootfs`** - Root filesystem scan

## Output Formats

- **`cyclonedx`** - CycloneDX SBOM format (JSON)
- **`json`** - Trivy JSON format
- **`sarif`** - SARIF format (for GitHub Code Scanning)
- **`table`** - Human-readable table format

## Examples by Use Case

### CI/CD Pipeline Integration

```yaml
name: CI Pipeline
on: [push, pull_request]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build application
        run: |
          # Your build steps here
          docker build -t myapp:${{ github.sha }} .
      
      - name: Security Scan
        uses: RomainValmo/FullTrivyScanCycloneDX@main
        with:
          scan-type: 'image'
          target: 'myapp:${{ github.sha }}'
          format: 'cyclonedx'
          output-file: 'sbom-${{ github.sha }}.json'
          exit-code: '1'  # Fail on vulnerabilities
      
      - name: Upload SBOM
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: sbom-${{ github.sha }}.json
```

### Scheduled Security Audits

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 0 * * 0'  # Every Sunday at midnight

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Audit
        uses: RomainValmo/FullTrivyScanCycloneDX@main
        with:
          format: 'cyclonedx'
          severity: 'HIGH,CRITICAL'
      
      - name: Archive Results
        uses: actions/upload-artifact@v4
        with:
          name: weekly-audit-${{ github.run_number }}
          path: trivy-sbom.json
```

## Development

### Project Structure

```
.
├── action.yml           # GitHub Action metadata
├── Dockerfile          # Container definition
├── trivy_scan.py       # Main Python script
├── requirements.txt    # Python dependencies
├── .gitignore         # Git ignore patterns
└── README.md          # This file
```

### Local Testing

You can test the action locally using Docker:

```bash
# Build the Docker image
docker build -t trivy-action .

# Run a scan
docker run -v $(pwd):/scan trivy-action fs /scan cyclonedx output.json UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL os,library 0 latest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About Trivy

[Trivy](https://github.com/aquasecurity/trivy) is a comprehensive and versatile security scanner developed by Aqua Security. It can detect vulnerabilities in:
- Operating system packages
- Application dependencies
- Container images
- Infrastructure as Code (IaC) files
- Kubernetes clusters

## About CycloneDX

[CycloneDX](https://cyclonedx.org/) is a full-stack Bill of Materials (BOM) standard that provides advanced supply chain capabilities for cyber risk reduction.
