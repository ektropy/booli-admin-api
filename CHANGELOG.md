# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Multi-architecture builds for amd64, arm64, and arm
- Comprehensive security scanning with CodeQL, Gosec, and Trivy
- SBOM generation with Syft
- Artifact signing with Cosign
- Vulnerability checking with govulncheck

### Changed
- Updated GoReleaser configuration to v2
- Improved Docker health checks using curl
- Enhanced CI/CD pipeline with security checks

### Security
- All release artifacts are now signed with Cosign
- Container images include vulnerability scanning
- SBOM files generated for supply chain security