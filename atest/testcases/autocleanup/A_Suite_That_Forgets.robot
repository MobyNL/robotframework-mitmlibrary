*** Settings ***
Documentation       Starts a proxy and deliberately never stops it.
...                 The suite that follows reuses the same port, which only works if the
...                 library released it when this suite ended.

Library             OperatingSystem
Library             MitmLibrary
Library             ${CURDIR}/../../resources/servers.py


*** Test Cases ***
A Suite That Forgets To Stop Its Proxy
    ${port}    Get Free Port
    Start Mitm Proxy    127.0.0.1    ${port}
    ${address}    Get Proxy Address
    Should Be Equal As Integers    ${address.port}    ${port}
    # Handed to the next suite, which has no other way of knowing which port to expect.
    Create File    ${OUTPUT_DIR}/leaked_port.txt    ${port}
    # No Stop Mitm Proxy, and no suite teardown, on purpose.
