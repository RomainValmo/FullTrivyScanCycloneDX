# Contributing to FullTrivyScanCycloneDX

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

### Prerequisites

- Docker installed
- Python 3.11+
- Git

### Local Testing

1. Clone the repository:
```bash
git clone https://github.com/RomainValmo/FullTrivyScanCycloneDX.git
cd FullTrivyScanCycloneDX
```

2. Build the Docker image:
```bash
docker build -t trivy-action-test .
```

3. Test locally:
```bash
docker run -v $(pwd):/scan trivy-action-test fs /scan cyclonedx output.json UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL os,library 0 latest
```

### Testing the Python Script

```bash
# Verify syntax
python3 -m py_compile trivy_scan.py

# Run with test parameters
python3 trivy_scan.py fs . cyclonedx test-output.json HIGH,CRITICAL os,library 0 latest
```

## Project Structure

```
.
├── action.yml           # Action metadata and interface
├── Dockerfile          # Container build instructions
├── trivy_scan.py       # Main Python logic
├── requirements.txt    # Python dependencies
├── .gitignore         # Git ignore rules
├── README.md          # Main documentation
├── QUICKSTART.md      # Quick start guide
└── .github/
    └── workflows/
        └── example.yml # Example workflow
```

## Making Changes

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Keep changes focused and atomic
- Follow existing code style
- Update documentation if needed
- Test thoroughly

### 3. Validate Your Changes

```bash
# Check Python syntax
python3 -m py_compile trivy_scan.py

# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('action.yml'))"

# Build Docker image
docker build -t trivy-action-test .

# Test the action
docker run -v $(pwd):/scan trivy-action-test fs /scan cyclonedx test.json CRITICAL os,library 0 latest
```

### 4. Submit a Pull Request

- Write a clear description of your changes
- Reference any related issues
- Ensure all tests pass
- Wait for review

## Guidelines

### Code Style

- **Python**: Follow PEP 8
- **YAML**: Use 2-space indentation
- **Comments**: Explain "why" not "what"
- **Naming**: Use descriptive variable names

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Keep first line under 50 characters
- Add detailed description if needed

### Documentation

- Update README.md for user-facing changes
- Update QUICKSTART.md for common use cases
- Add comments for complex logic
- Include examples when helpful

## Adding New Features

### New Input Parameters

1. Add to `action.yml` inputs section
2. Update `trivy_scan.py` to handle the parameter
3. Update README.md with usage examples
4. Update QUICKSTART.md if it's a common use case

### New Output Formats

1. Update Trivy command in `trivy_scan.py`
2. Update output parsing logic
3. Add examples to documentation
4. Test with real scans

### New Scan Types

1. Add support in `trivy_scan.py`
2. Update documentation
3. Add example workflow
4. Test thoroughly

## Testing Checklist

Before submitting:

- [ ] Python syntax is valid
- [ ] YAML files are valid
- [ ] Docker image builds successfully
- [ ] Action works with default parameters
- [ ] Action works with custom parameters
- [ ] Documentation is updated
- [ ] Examples are provided
- [ ] No sensitive data is included

## Getting Help

- Check existing issues and PRs
- Read the full documentation
- Ask questions in discussions
- Be patient and respectful

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the project
- Welcome newcomers

Thank you for contributing! 🎉
