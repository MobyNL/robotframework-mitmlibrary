# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 1.0.0 are not listed here; the changelog starts with the work leading up
to 1.0.0, which is the first release whose keyword surface is covered by the stability
promise in the README.

## [Unreleased]

### Added

- `Get Proxy Address` returns the host, port and url the proxy is actually listening on.
  It reads the address from the running proxy rather than echoing back the arguments,
  which is what makes `listen_port=0` usable: the operating system picks a free port and
  this keyword reports which one, so suites can run in parallel without agreeing on a
  port in advance.
- The proxy is released when the suite that started it ends, even if the suite never
  called `Stop Mitm Proxy`. A forgotten teardown used to leave the port bound for the
  rest of the run, failing the next suite that wanted it.
- The package now ships a `py.typed` marker, so type checkers in projects that depend on
  MitmLibrary use its annotations instead of treating it as untyped.

### Fixed

- A proxy no longer dies because something unrelated logged an error. mitmproxy's
  `errorcheck` addon watches the root logger and exits the process when an error was
  logged while a master starts, which in a library means a proxy could be killed by a
  message from a proxy that had already stopped. The addon is now removed; startup
  failures were already detected separately, and are reported with their own reason.
- A proxy that fails to start no longer leaves its request logger behind, where the next
  keyword would have used it while no proxy was running.

### Changed

- The proxy lifecycle moved to `MitmLibrary.proxy_controller`, which is now the only
  module that reaches into mitmproxy's internals. This is internal, but it does move
  `MitmLibrary.STARTUP_TIMEOUT` and `MitmLibrary.SHUTDOWN_TIMEOUT` to that module.

[Unreleased]: https://github.com/MobyNL/robotframework-mitmlibrary/compare/v0.3.0...HEAD
