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

    # Block requests to Robot Framework website
    Add To Blocklist    robotframework.org

    # Delay requests to Google
    Add Response Delay  GoogleDelay   https://www.google.com  5  # Delay for 5 seconds

    # Perform tests that involve network traffic manipulation
    # ...

    Stop Mitm Proxy

```


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

## Contributing
Contributions are welcome! If you encounter any issues, have suggestions for improvements, or would like to add new features, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

Note: This project is not officially affiliated with or endorsed by the mitmproxy project or robotframework.
