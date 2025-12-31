# Quick Start Guide

## What is this action?

A GitHub Action that uses Trivy to scan your code and generate a CycloneDX SBOM (Software Bill of Materials).

## Basic Usage

Add this to your workflow:

```yaml
- name: Scan with Trivy
  uses: RomainValmo/FullTrivyScanCycloneDX@main
```

That's it! By default, it will:
- Scan the current directory
- Generate a CycloneDX SBOM
- Save to `trivy-sbom.json`

## Common Scenarios

### Scan and Upload Results

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main
  
- uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: trivy-sbom.json
```

### Scan Docker Image

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main
  with:
    scan-type: 'image'
    target: 'myapp:latest'
```

### Fail on High/Critical Vulnerabilities

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main
  with:
    severity: 'HIGH,CRITICAL'
    exit-code: '1'
```

### Custom Output Location

```yaml
- uses: RomainValmo/FullTrivyScanCycloneDX@main
  with:
    output-file: 'reports/security-scan.json'
```

## All Available Options

| Option | What it does | Default |
|--------|--------------|---------|
| `scan-type` | What to scan (fs/image/config) | `fs` |
| `target` | What to scan | `.` |
| `format` | Output format | `cyclonedx` |
| `output-file` | Where to save results | `trivy-sbom.json` |
| `severity` | Which severities to report | All |
| `vuln-type` | Types of vulnerabilities | `os,library` |
| `exit-code` | Fail on vulnerabilities? | `0` (no) |

## Getting Results

After the action runs, you can:

1. **Use the output file**: Access the SBOM at the path you specified
2. **Upload as artifact**: Use `actions/upload-artifact@v4`
3. **Read outputs**: Use `${{ steps.scan.outputs.sbom-file }}`

## Need Help?

See the full [README.md](README.md) for detailed examples and documentation.
