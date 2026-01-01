# Security Policy

## Supported Versions

We actively maintain the following versions:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please follow these steps:

1. **Do NOT** open a public issue
2. Send a detailed report to the repository owner via GitHub Security Advisory
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Release**: Depends on severity (Critical: 7-14 days, High: 14-30 days)

## Security Best Practices

When using this GitHub Action:

- Always pin to a specific commit or version tag instead of `@main`
- Review the code before using it in production
- Keep Trivy database updated (handled automatically by the action)
- Monitor security advisories for dependencies

## Known Limitations

- This action requires Docker access
- Trivy database updates may fail in restricted networks
- Large projects may hit GitHub Actions timeout limits

## Disclosure Policy

We follow responsible disclosure practices:

1. Security issues are fixed privately
2. Fixes are released as soon as possible
3. Public disclosure after fix is available
4. Credit given to reporters (if desired)

## Security Updates

Subscribe to repository releases and security advisories to stay informed about security updates.
