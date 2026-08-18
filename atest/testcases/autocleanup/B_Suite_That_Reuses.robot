*** Settings ***
Documentation       Reuses the port the previous suite left behind.
...                 Fails if the library did not release it, which is the regression this
...                 guards against.

Library             OperatingSystem
Library             MitmLibrary

Suite Teardown      Stop Mitm Proxy


*** Test Cases ***
The Port Of The Previous Suite Is Available Again
    ${port}    Get File    ${OUTPUT_DIR}/leaked_port.txt
    Start Mitm Proxy    127.0.0.1    ${port}
    ${address}    Get Proxy Address
    Should Be Equal As Integers    ${address.port}    ${port}
