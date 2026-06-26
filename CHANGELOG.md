# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-06-25

### Security

- **[High] Pinned `cryptography>=48.0.1`** to address CVE-2026-34180 (out-of-bounds read). Previously resolved to 48.0.0 as a transitive dependency.
- **[Medium] Pinned `idna>=3.15`** to address CVE-2026-45409 (ReDoS). Previously resolved to 3.11 as a transitive dependency.
- Removed hardcoded test credential in `tests/test_client.py`; `api_key` now reads from the `THREATLOCKER_API_KEY` environment variable set at the top of the test module (CWE-547).
- Added path validation in `scripts/generate_from_spec.py`: CLI argument is resolved via `os.path.realpath()` and validated as an existing file before use (CWE-23).
- Added `requirements.txt` (generated via `pip-compile`) to lock transitive dependency versions for reproducible installs.

## [0.2.1] - Initial release baseline

See [GitHub releases](https://github.com/Space-C0wboy/ThreatLocker-MCP/releases) for earlier history.
