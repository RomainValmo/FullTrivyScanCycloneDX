# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete test suite with 61+ tests
  - Unit tests for all main modules
  - Integration tests
  - Performance tests
- CI/CD pipeline with GitHub Actions
  - Automated testing on Python 3.11 and 3.12
  - Code coverage reporting with Codecov
  - Security scanning
- Comprehensive documentation
  - README with usage examples
  - CONTRIBUTING guide
  - QUICKSTART guide
  - TESTING guide
- Open source governance
  - MIT License
  - Code of Conduct (Contributor Covenant 2.0)
  - Security Policy
  - Issue and PR templates
  - Authors file
  - Changelog
- License headers in all Python source files

### Changed
- Updated to use `datetime.now(timezone.utc)` instead of deprecated `datetime.utcnow()`
- Improved error handling in all modules
- Enhanced component categorization logic

### Fixed
- Fixed parameter naming in `categorize_component()` function
- Resolved deprecation warnings for Python 3.12+

## [0.1.0] - Initial Development

### Added
- Docker image scanning with Trivy
- Dependency file scanning (Python, Node.js, Go, Rust, Java, PHP, Ruby)
- CycloneDX SBOM generation (v1.6)
- SBOM merging without duplicates
- Trivy vulnerability enrichment
- Metadata generation with component categorization
- Runtime version detection
- Multi-language support
- GitHub Actions integration

---

## Release Guidelines

### Version Format
- **Major** (1.0.0): Breaking changes
- **Minor** (0.1.0): New features, backward compatible
- **Patch** (0.0.1): Bug fixes, backward compatible

### Release Process
1. Update CHANGELOG.md
2. Update version in action.yml
3. Create GitHub Release
4. Tag with version number
5. Update documentation if needed

[Unreleased]: https://github.com/RomainValmo/FullTrivyScanCycloneDX/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RomainValmo/FullTrivyScanCycloneDX/releases/tag/v0.1.0
