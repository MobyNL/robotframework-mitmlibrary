# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 1.0.0 are not listed here; the changelog starts with the work leading up
to 1.0.0, which is the first release whose keyword surface is covered by the stability
promise in the README.

## [Unreleased]

### Changed - breaking

Every kind of manipulation used to have its own list, its own remove keyword and its own
log keyword, and the blocklist had no alias at all. They are now one rule model, which
means one way to address a rule, the same matching options everywhere, and a defined order
when several rules match the same request. Migrating is a rename plus, for blocking, an
alias:

| Before | Now |
| --- | --- |
| `Add To Blocklist    url` | `Block Requests    alias    url` |
| `Add Custom Response    alias    url    overwrite_headers=    overwrite_body=` | `Set Response    alias    url    headers=    body=` |
| `Add Custom Response Status Code    alias    url    status_code` | `Set Response Status    alias    url    status_code` |
| `Remove Url From Blocklist    url` | `Remove Rule    alias` |
| `Remove Custom Response    alias` | `Remove Rule    alias` |
| `Remove Custom Status Code    alias` | `Remove Rule    alias` |
| `Clear All Proxy Items` | `Clear All Rules` |
| `Log Blocked Urls`, `Log Delayed Responses`, `Log Custom Response Items`, `Log Custom Status Items` | `Log Proxy Rules` |

`Add Response Delay` keeps its name and arguments.

Two behaviour changes come with it:

- **A blocked request is answered with `403` instead of having its connection dropped.**
  The documentation always said it was a 403; the code killed the connection. Answering
  is now the default because every HTTP client reports it the same way, where a dropped
  connection surfaces as a different exception in each of them. Pass `mode=RESET` for the
  old behaviour.
- **All matching rules are applied, in a defined order.** A blocking rule ends the
  request and nothing after it runs. Otherwise `Set Response` runs before rules that
  change part of a response, which run before delays, and delays add up. Previously a
  later custom response could silently throw away an earlier status change.

### Added

- Every rule keyword takes `method`, `match` and `times`. `match` is `SUBSTRING` (the
  default, and what the library did before), `REGEX` or `GLOB`. `method` restricts a rule
  to one HTTP method. `times` limits how often a rule may be applied, and an exhausted
  rule stays visible in `Get Proxy Rules` with `remaining=0` rather than disappearing.
  An unusable regular expression fails the keyword that configured it, not the proxy
  later.
- Request-side manipulation, which the library could not do at all before: it could
  change what came back but never what was sent.
  - `Set Request Headers` and `Set Response Headers` set and remove named headers,
    merging rather than replacing, so adding one header does not mean restating the
    others.
  - `Set Request Body` and `Set Response Body` replace a body and update its
    `content-length` to match.
  - `Rewrite Request Url` sends a request to a different url entirely.
  - `Redirect Requests To Host` sends it to a different host, keeping the path and
    query, and updates the `Host` header so the receiving server is addressed by a name
    it answers to.
- Traffic can be recorded and asserted on, which the library could not do at all before:
  it could change what came back but never report what the application actually sent.
  `Start Recording`, or `record=True` on `Start Mitm Proxy`, turns it on, and
  `Get Recorded Requests`, `Get Request Count`, `Request Should Have Been Made`,
  `Request Should Not Have Been Made` and `Wait Until Request Is Made` ask about it.
  Recording is off by default and capped in two directions - how many requests are kept
  and how many bytes of each body - so a long run does not quietly grow without limit.
  When the first cap is reached the oldest request is dropped and the number dropped is
  reported in assertion failures rather than hidden, so an assertion against a shortened
  recording cannot look complete. Requests that failed are recorded too, so a blocked
  call can be asserted on.
- `Get Proxy Rules` returns the loaded rules in the order they are applied.
- Blocking rules have an alias, like every other rule, so they are removed the same way.
- Rules survive a restart of the proxy: the registry outlives it, and only the addon
  reading it is rebuilt.
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
