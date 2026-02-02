# Contributing to spdm-x509-rs

Thank you for your interest in contributing to spdm-x509-rs! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Pull Request Process](#pull-request-process)
- [Coding Guidelines](#coding-guidelines)
- [Commit Messages](#commit-messages)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment. Be respectful, considerate, and collaborative.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what is best for the project
- Show empathy towards others

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- Familiarity with X.509 certificates and cryptography (helpful but not required)

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/spdm-x509-rs.git
cd spdm-x509-rs
```

## Development Setup

### Install Dependencies

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install additional tools
cargo install cargo-edit       # For managing dependencies
cargo install cargo-tarpaulin  # For code coverage
cargo install cargo-audit      # For security audits
```

### Build the Project

```bash
# Standard build
cargo build

# With all features
cargo build --all-features

# no_std build (verify compatibility)
cargo build --no-default-features
```

### Run Tests

```bash
# Run all tests
cargo test --all-features

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

## Making Changes

### Branch Naming

Use descriptive branch names:

```
feature/add-ed25519-support
fix/parse-error-in-san
docs/update-spdm-guide
refactor/simplify-validator
```

### Workflow

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the [coding guidelines](#coding-guidelines)

3. **Write/update tests** to cover your changes

4. **Update documentation** if needed

5. **Commit your changes** with clear [commit messages](#commit-messages)

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub

## Testing

### Running Tests

```bash
# Run all tests
cargo test --all-features

# Run specific test suite
cargo test algorithm_tests
cargo test spdm_validation

# Run ignored/integration tests
cargo test -- --ignored

# Check test coverage
cargo tarpaulin --all-features
```

### Writing Tests

- **Write tests for all new features**
- **Update tests when modifying existing features**
- **Include both positive and negative test cases**
- **Test edge cases and error conditions**

Example:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_certificate() {
        let der = include_bytes!("../tests/data/valid_cert.der");
        let result = Certificate::from_der(der);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_certificate_fails() {
        let invalid_der = b"invalid data";
        let result = Certificate::from_der(invalid_der);
        assert!(result.is_err());
    }
}
```

### Test Requirements

- All tests must pass before PR can be merged
- New code should maintain or improve code coverage
- Tests should be deterministic (no random failures)
- Long-running tests should be marked with `#[ignore]`

## Code Quality

### Before Submitting

Run these checks locally:

```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run Clippy
cargo clippy --all-features -- -D warnings

# Build documentation
cargo doc --all-features --no-deps

# Run security audit
cargo audit

# Verify no_std compatibility
cargo build --no-default-features
```

### Automated Checks

Our CI runs the following automatically:

- ✅ Tests on multiple Rust versions (stable, nightly)
- ✅ Tests with all feature flag combinations
- ✅ Clippy linting with warnings as errors
- ✅ Code formatting verification
- ✅ Documentation build
- ✅ Security audit
- ✅ no_std build verification

## Pull Request Process

### Creating a PR

1. **Ensure all tests pass** locally
2. **Update documentation** as needed
3. **Add entry to CHANGELOG.md** (under Unreleased)
4. **Create PR** with clear title and description

### PR Title Format

```
[type]: Brief description

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- refactor: Code refactoring
- test: Test additions/changes
- chore: Build/tooling changes
```

Examples:
```
feat: Add Ed25519 signature support
fix: Correct DER parsing for BMPString
docs: Update SPDM validation guide
refactor: Simplify certificate chain validation
```

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All existing tests pass
- [ ] New tests added
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] no_std compatibility maintained
```

### Review Process

- Maintainers will review your PR
- Address feedback and requested changes
- Keep PR focused and manageable in size
- Be responsive to comments

### Merging

- PRs require approval from at least one maintainer
- All CI checks must pass
- PR will be merged using "Squash and merge" or "Rebase and merge"

## Coding Guidelines

### Rust Style

Follow the [Rust Style Guide](https://rust-lang.github.io/api-guidelines/):

- Use `cargo fmt` for consistent formatting
- Follow naming conventions:
  - `snake_case` for functions, variables, modules
  - `CamelCase` for types, traits
  - `SCREAMING_SNAKE_CASE` for constants
- Use meaningful, descriptive names
- Keep functions focused and concise

### Code Organization

```rust
// Module structure
mod submodule;

// Imports grouped and sorted
use core::fmt;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::certificate::Certificate;

// Public exports
pub use submodule::PublicType;

// Constants
const MAX_SIZE: usize = 1024;

// Types
pub struct MyType {
    // fields
}

// Implementations
impl MyType {
    // methods
}
```

### Error Handling

- Use `Result<T, Error>` for fallible operations
- Provide descriptive error messages
- Use proper error types from `error.rs`
- Never `panic!` in production code
- Use `expect()` only in tests

```rust
// Good
pub fn parse_certificate(data: &[u8]) -> Result<Certificate> {
    let cert = Certificate::from_der(data)
        .map_err(|e| Error::ParseError(e))?;
    Ok(cert)
}

// Bad
pub fn parse_certificate(data: &[u8]) -> Certificate {
    Certificate::from_der(data).unwrap()  // Never do this!
}
```

### no_std Compatibility

- Keep code `no_std` compatible
- Use `alloc` instead of `std` for allocating types
- Use `core` instead of `std` for core functionality
- Gate `std`-only code with `#[cfg(feature = "std")]`

```rust
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

// std-only functionality
#[cfg(feature = "std")]
impl std::error::Error for MyError {}
```

### Documentation

- Add doc comments to all public items
- Use `///` for doc comments
- Include examples in documentation
- Document panics, errors, and safety

```rust
/// Parses an X.509 certificate from DER-encoded bytes.
///
/// # Arguments
///
/// * `data` - DER-encoded certificate bytes
///
/// # Returns
///
/// Returns `Ok(Certificate)` on success, or an error if parsing fails.
///
/// # Errors
///
/// Returns `Error::ParseError` if the DER encoding is invalid or incomplete.
///
/// # Examples
///
/// ```rust
/// use spdm_x509::Certificate;
///
/// let der = include_bytes!("cert.der");
/// let cert = Certificate::from_der(der)?;
/// println!("Subject: {}", cert.tbs_certificate.subject);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn from_der(data: &[u8]) -> Result<Certificate> {
    // implementation
}
```

## Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Build/tooling

### Examples

```
feat(spdm): Add Ed25519 algorithm support

Implements Ed25519 signature verification for SPDM certificates
following DSP0274 specification.

Closes #123
```

```
fix(parser): Handle BMPString encoding correctly

The DER parser was incorrectly handling BMPString encoding in
Distinguished Names. This fix properly decodes UTF-16BE encoded
strings per X.690.

Fixes #456
```

### Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- First line should be 50 characters or less
- Body should explain what and why, not how
- Reference issues and PRs in footer

## Documentation

### API Documentation

- Document all public APIs
- Include usage examples
- Document panics and errors
- Keep docs up to date with code changes

### Guides

When adding features that need explanation:

1. Update relevant guide in `docs/`
2. Add examples to `examples/`
3. Update README.md if it affects public API
4. Add entry to CHANGELOG.md

### Building Docs

```bash
# Build documentation
cargo doc --all-features --no-deps

# Open in browser
cargo doc --all-features --no-deps --open

# Check for broken links
cargo doc --all-features --no-deps 2>&1 | grep warning
```

## Release Process

(For maintainers)

### Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Backwards compatible bug fixes

### Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`:
   - Move Unreleased changes to new version
   - Add release date
   - Add comparison links
3. Update version references in documentation
4. Create git tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
5. Push tag: `git push origin v0.2.0`
6. GitHub Actions will build and publish to crates.io
7. Create GitHub Release with changelog

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Read the documentation in `docs/`
- Check existing issues and PRs

## Thank You!

Your contributions make this project better. We appreciate your time and effort!

---

**License:** By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).
