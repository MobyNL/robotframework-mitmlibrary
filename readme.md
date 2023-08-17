# Robot Framework MITM Library

![Robot Framework Logo](https://robotframework.org/robotframework/latest/RobotFrameworkLogo.png)

## Overview

The Robot Framework MITM Library is a custom library for [Robot Framework](https://robotframework.org/) that enables seamless integration with the Python package [mitm](https://github.com/mitmproxy/mitmproxy). This library allows you to automate and test scenarios involving Man-in-the-Middle (MITM) proxy functionality within your Robot Framework test suites.

## Features

- Interact with MITM proxy using Robot Framework keywords.
- Capture and manipulate network traffic for testing purposes.
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
Library       MITMLibrary
```

Use the available keywords to interact with the MITM proxy and manipulate network traffic as needed:
```robotframework
*** Test Cases ***
Test MITM Proxy
    Start MITM Proxy   # Start the MITM proxy server
    <!-- TODO: Add keywords -->
    Stop MITM Proxy    # Stop the MITM proxy server
```
## Documentation
For detailed information on the available keywords and usage examples, please refer to the Library Documentation.

## Contributing
Contributions are welcome! If you encounter any issues, have suggestions for improvements, or would like to add new features, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

Note: This project is not officially affiliated with or endorsed by the mitmproxy project or robotframework.
