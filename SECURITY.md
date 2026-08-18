# Security

## Reporting a vulnerability

Please report security issues by opening a
[GitHub issue](https://github.com/MobyNL/robotframework-mitmlibrary/issues) or through the
[Slack channel](https://robotframework.slack.com/archives/C06M2J3J8AC).

## Running the proxy safely

`Start Mitm Proxy` listens on `127.0.0.1` by default. Passing `0.0.0.0` exposes an
intercepting TLS proxy on every network interface of the machine, which lets anyone who can
reach it route their traffic through your certificate authority. Only do that when you
actually need the proxy to be reachable from another machine or container, and only on a
trusted network.

## Known dependency advisories

`poetry.lock` pins the development and CI environment; it is not installed by consumers of
the published package. It is kept up to date, but a few advisories cannot currently be
resolved because `mitmproxy` declares upper bounds on the affected packages:

| Package | Locked | Advisory needs | Blocked by |
| --- | --- | --- | --- |
| `cryptography` | 48.0.1 | 49.0.0 / 50.0.0 | `mitmproxy` requires `cryptography<=48.1` |
| `tornado` | 6.5.5 | 6.5.6 / 6.5.7 | `mitmproxy` requires `tornado<=6.5.5` |
| `msgpack` | 1.1.2 | 1.2.1 | `mitmproxy` requires `msgpack<=1.1.2` |
| `h2` | 4.3.0 | 4.4.1 | `mitmproxy` pins `h2==4.3.0` |

These will clear as soon as a `mitmproxy` release widens the bounds. Forcing the newer
versions produces an unsupported `mitmproxy` installation, so they are deliberately left as
they are rather than overridden.
