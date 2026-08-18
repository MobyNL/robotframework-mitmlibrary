# Robot Framework MITM Library

![MitmLibrary Icon](https://github.com/MobyNL/robotframework-mitmlibrary/blob/main/MITMLibrary_small.png)

## Keyword
[Keyword documentation](https://mobynl.github.io/robotframework-mitmlibrary/MitmLibraryKeywords.html)

## Overview

The Robot Framework MITM Library is a custom library for [Robot Framework](https://robotframework.org/) that enables integration with the Python package [mitm](https://github.com/mitmproxy/mitmproxy). This library allows you to automate and test scenarios involving Man-in-the-Middle (MITM) proxy functionality within your Robot Framework test suites.

If you need help, have suggestions or want to discuss anything, feel free to contact through the [slack channel](https://robotframework.slack.com/archives/C06M2J3J8AC).

## Features

- **Change what comes back.** Replace a response, or only its status, headers or body,
  for requests matching a url, a method, or a regular expression.
- **Change what goes out.** Add or remove request headers, replace a request body, or
  send a request to a different url or host entirely.
- **Assert on what was sent.** Record the traffic that passed through and ask whether a
  request was made, how often, and with what — the half of testing a proxy is usually not
  used for.
- **Break things on purpose.** Block a request, drop a connection, hold a request until
  the client gives up, or cut a response short while it still claims its full length.
- **Sit wherever the traffic is.** A forward proxy by default, or in front of a service,
  or chained through the network's own proxy.

Every rule is addressed by an alias, matched the same way, and removed the same way.

## Installation

1. Install Robot Framework (if not already installed):
2. Install mitm library using pip:
```
pip install robotframework-mitmlibrary
```

Requires Python 3.12 or newer, which is mitmproxy's own floor.


## Usage

1. Import the MITM Library in your Robot Framework test suite:
```robotframework
*** Settings ***
Library       MitmLibrary
```

2. Use the available keywords to interact with the MITM proxy and manipulate network traffic as needed:
```robotframework
*** Settings ***
Library       MitmLibrary

*** Test Cases ***
Block and Delay Websites
    Start Mitm Proxy

    # Answer requests to the Robot Framework website with 403 instead of passing them on
    Block Requests      ads           robotframework.org

    # Delay requests to Google
    Add Response Delay  GoogleDelay   https://www.google.com  5  # Delay for 5 seconds

    # Perform tests that involve network traffic manipulation
    # ...

    Stop Mitm Proxy

```

### Rules

Everything the proxy does is a rule, and every rule is addressed the same way: an alias, a
url pattern, and optionally an HTTP method. `Remove Rule` removes any of them,
`Clear All Rules` removes all of them, and `Get Proxy Rules` reports what is loaded.

Every rule keyword takes the same matching arguments:

```robotframework
Set Response Status   flaky   /api/orders   500   method=POST   match=REGEX   times=1
```

- `match` is `SUBSTRING` (the default), `REGEX` or `GLOB`. A glob is matched against the
  whole url, so `*/api/*` matches where `api` alone does not.
- `method` restricts the rule to one HTTP method; `ANY`, the default, matches all of them.
- `times` limits how often the rule may be applied; `0`, the default, means unlimited.

All matching rules are applied. A rule that blocks a request ends it and nothing after it
runs; otherwise `Set Response` runs before rules that change part of a response, which run
before delays, so combinations behave predictably rather than overwriting each other.

### Simulating failures

Most rules make a request succeed differently. These make it fail the way a network does:

```robotframework
Simulate Timeout                hang   /api/orders   hold=30s
Simulate Truncated Response     cut    /api/orders   keep_bytes=10
Block Requests                  drop   /api/orders   mode=RESET
```

How a client reports any of these depends on the HTTP library it uses, so assert that the
request failed rather than on the particular error.

Bandwidth throttling is not supported: mitmproxy hands a response body to a synchronous
callback with no way to wait between chunks, so the only implementable version would delay
the whole body and deliver it in one piece — which is what `Add Response Delay` already
does, honestly named.

### Recording

The proxy can also remember what went through it, so a suite can assert on what the
application under test actually sent rather than only on what came back:

```robotframework
Start Mitm Proxy    record=True
# ... drive the application ...
Request Should Have Been Made       /api/orders    method=POST
Request Should Not Have Been Made   /api/telemetry
${requests}    Get Recorded Requests    /api/orders
Should Be Equal    ${requests}[0][request_body]    {"id": 1}
```

`Wait Until Request Is Made` covers traffic a test does not trigger directly, such as a
call a page makes after it has loaded.

Recording is off by default, and what it keeps is capped both in number of requests and in
bytes per body, so a long run does not grow without limit. When the request cap is reached
the oldest is dropped, and assertion failures say so rather than presenting a shortened
recording as if it were complete.

By default the proxy listens on `127.0.0.1:8080`. Pass a different host explicitly if the
proxy must be reachable from another machine or container:

```robotframework
Start Mitm Proxy    0.0.0.0    8080
```

Be aware that `0.0.0.0` exposes an intercepting proxy on every network interface, so anyone
who can reach the machine can route their traffic through it.


### Proxy modes

By default the proxy is a forward proxy: a client is configured to send traffic through
it. `mode` changes that:

```robotframework
# Stand in front of a service, so a client needs no proxy settings at all
Start Mitm Proxy    mode=reverse:http://127.0.0.1:5000

# Send everything on through the network's own proxy
Start Mitm Proxy    mode=upstream:http://corporate-proxy:3128
```

`transparent` and `socks5` are passed through to mitmproxy too. A mode that cannot be
understood fails `Start Mitm Proxy` rather than leaving the proxy to fail to start for an
unstated reason. `proxy_auth` requires clients to authenticate before the proxy serves
them.

### Why use Mitm?
Mitm allows manipulation on single browser instance, by using a proxy. It does not
require you to set up stubs or mocks that might influence the entire application at
once, also resulting in stubbed/mocked behaviour while manual testing.

Examples where Mitm is useful: 
- When running in parallel, if you do not want your other instances to be influenced. 
- Manipulate the response of a request to see how the front end handles it
- When stubs or mocks are not available or their behaviour is not sufficient for your testing needs.
- When you want to have full control as tester, without dependency on a developer

### Mitm Certificates
To test with SSL verification, or use a browser without ignoring certificates,
you will need to set up the certificates related to
mitm. Follow the guide on the 
[Mitm website](https://docs.mitmproxy.org/stable/concepts-certificates/)

## Documentation

The [keyword documentation](https://mobynl.github.io/robotframework-mitmlibrary/MitmLibraryKeywords.html)
describes every keyword, its arguments and examples.

It is published per version, so you can read the documentation for the version you
actually have installed rather than for whatever is newest:

- [latest release](https://mobynl.github.io/robotframework-mitmlibrary/latest/MitmLibraryKeywords.html)
- [all versions](https://mobynl.github.io/robotframework-mitmlibrary/)
- [current main, unreleased](https://mobynl.github.io/robotframework-mitmlibrary/dev/MitmLibraryKeywords.html)

## API stability

From 1.0.0 onwards the keyword surface is stable:

- Keyword names, argument names and their order will not change in a 1.x release.
- New arguments are only ever added at the end, with defaults, so existing calls keep
  working whether they pass arguments positionally or by name.
- The rule model is part of that promise, not just the signatures: how patterns are
  matched, the order in which several matching rules are applied, and what `times` means
  will not change either.

Anything not listed above is internal and may change: module layout, class names, and
everything with a leading underscore. Import keywords through Robot Framework rather than
calling into the package directly, and none of that will reach you.

Breaking changes wait for 2.0 and are recorded in the [CHANGELOG](CHANGELOG.md).

### Migrating from 0.3.0

1.0.0 reworked the keywords once so that every kind of rule is addressed the same way.
The [CHANGELOG](CHANGELOG.md) has the full table; in short:

| Before | Now |
| --- | --- |
| `Add To Blocklist    url` | `Block Requests    alias    url` |
| `Add Custom Response    alias    url    overwrite_headers=    overwrite_body=` | `Set Response    alias    url    headers=    body=` |
| `Add Custom Response Status Code` | `Set Response Status` |
| `Remove Url From Blocklist`, `Remove Custom Response`, `Remove Custom Status Code` | `Remove Rule    alias` |
| `Clear All Proxy Items` | `Clear All Rules` |
| the four `Log ...` keywords | `Log Proxy Rules` |

Two behaviour changes come with it: a blocked request is answered with `403` rather than
having its connection dropped (`mode=RESET` restores the old behaviour), and when several
rules match one request all of them apply, in a defined order, instead of the last one
silently winning.

## Contributing
Contributions are welcome! If you encounter any issues, have suggestions for improvements, or would like to add new features, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

Note: This project is not officially affiliated with or endorsed by the mitmproxy project or robotframework.
