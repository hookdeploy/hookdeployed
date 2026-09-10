# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-09-10

### Fixed

- A local server closing its connection mid-response could be silently recorded as a successful delivery instead of a failure ([#33](https://github.com/hookdeploy/hookdeployed/pull/33)).

## [0.1.1] - 2026-09-05

### Added

- Optional `-client` identifier on enroll, `rename` command, and `-json` on `list` / `tap list`.
- `-no-tty` for enroll and tap so a GUI or subprocess can supply input.
- Debian package and APT install path.

### Fixed

- Enrollment tokens could be silently truncated by the debconf password widget.
- APT postinst could fail to read the enrollment token.
- Dead credentials could reconnect in a loop; clock skew is now detected.

## [0.1.0] - 2026-08-29

First tagged release (Linux install script, systemd unit, and the signed release pipeline). Earlier history predates this changelog.

[Unreleased]: https://github.com/hookdeploy/hookdeployed/compare/v0.1.1...HEAD
[0.1.2]: https://github.com/hookdeploy/hookdeployed/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/hookdeploy/hookdeployed/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hookdeploy/hookdeployed/releases/tag/v0.1.0
