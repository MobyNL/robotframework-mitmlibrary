# Robot Framework MITM Library

![MitmLibrary Icon](https://github.com/MobyNL/robotframework-mitmlibrary/blob/main/MITMLibrary_small.png)

## Keyword
[Keyword documentation](https://mobynl.github.io/robotframework-mitmlibrary/MitmLibraryKeywords.html)

## Overview

The Robot Framework MITM Library is a custom library for [Robot Framework](https://robotframework.org/) that enables integration with the Python package [mitm](https://github.com/mitmproxy/mitmproxy). This library allows you to automate and test scenarios involving Man-in-the-Middle (MITM) proxy functionality within your Robot Framework test suites.

If you need help, have suggestions or want to discuss anything, feel free to contact through the [slack channel](https://robotframework.slack.com/archives/C06M2J3J8AC).

## Features

- Interact with MITM proxy using Robot Framework keywords.
- Manipulate network traffic for testing purposes.
- Easily simulate different network conditions and responses.
- Integrate MITM proxy capabilities into your existing Robot Framework tests.

## Installation

1. Install Robot Framework (if not already installed):
2. Install mitm library using pip:
```
pip install robotframework-mitmlibrary
```


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
For detailed information on the available keywords and usage examples, please refer to the [Keyword Documentation](https://mobynl.github.io/robotframework-mitmlibrary/MitmLibraryKeywords.html)

## API stability

The keyword surface is **not yet stable**. Keyword names, argument names and their order
may still change while the library is on 0.x, and the [CHANGELOG](CHANGELOG.md) records
those changes.

1.0.0 fixes the surface: it reworks the keywords once, deliberately and with a documented
migration path, and from that release onwards names and argument order will not change
within 1.x.

## Contributing
Contributions are welcome! If you encounter any issues, have suggestions for improvements, or would like to add new features, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

Note: This project is not officially affiliated with or endorsed by the mitmproxy project or robotframework.
