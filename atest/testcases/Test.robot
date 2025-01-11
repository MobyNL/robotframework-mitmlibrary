*** Settings ***
Library             Collections
Library             Dialogs
Library             Process
Library             Browser
Library             RequestsLibrary
Library             MitmLibrary

Suite Setup         Setup Flask
Suite Teardown      Teardown Flask
Test Setup          Clear All Proxy Items
Test Teardown       Clear All Proxy Items


*** Variables ***
&{PROXY_DICT}           server=http://localhost:8080
&{BROWSER_ARGS}         proxy=${PROXY_DICT}
@{BROWSER_ARGS_LIST}    --ignore-certificate-errors
&{REQUESTS_PROXY}       http=http://localhost:8080    http://host.name=http://localhost:8080
&{DEFAULT_HEADERS}
...                     Server=Werkzeug/2.2.2 Python/3.11.1
...                     Date=Fri, 21 Jul 2023 16:27:23 GMT
...                     Content-Type=text/html; charset=utf-8
...                     Content-Length=41
...                     Connection=close


*** Test Cases ***
Block A Website
    New Browser    browser=chromium    headless=True    proxy=${PROXY_DICT}
    New Context
    New Page
    Add To Blocklist    robotframework
    ${status}    Run keyword And Return Status    Go To    https://robotframework.org/
    Log Blocked Urls
    Should Not Be True    ${status}

Custom Response With Post And Custom Status Code
    Create Session    alias=proxy    url=http://localhost:5000    proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response Status Code    alias=number_post    url=test_post    status_code=${404}
    Log Custom Status Items
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Body
    Create Session    alias=proxy    url=http://localhost:5000    proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response    alias=number_post    url=test_post    overwrite_body=<number_size>not_found</number_size>
    Log Custom Response Items
    Check POST Response Of test_post    <number_size>not_found</number_size>    ${200}

Custom Response With Post And Custom StatusCode Using Add Custom Response
    Create Session    alias=proxy    url=http://localhost:5000    proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response    alias=number_post    url=test_post    status_code=404
    Check POST Response Of test_post    ${None}    ${404}

Custom Response With Post And Custom Headers
    Create Session    alias=proxy    url=http://localhost:5000    proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    &{new_headers}    Create Dictionary    Content-Type=application/json
    Add Custom Response    alias=number_post    url=test_post    overwrite_headers=${new_headers}
    Check POST Response Of test_post    ${None}    ${200}    ${new_headers}

Custom Response With Post And Full Custom Response
    Create Session    alias=proxy    url=http://localhost:5000    proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    &{new_headers}    Create Dictionary    Content-Type=application/json
    Add Custom Response
    ...    alias=number_post
    ...    url=test_post
    ...    overwrite_headers=${new_headers}
    ...    status_code=${202}
    ...    overwrite_body=<number_size>test successful</number_size>
    Check POST Response Of test_post    <number_size>test successful</number_size>    ${202}    ${new_headers}

Delayed Response With Post
    Create Session    alias=proxy    url=http://localhost:5000    proxies=${REQUESTS_PROXY}    timeout=10
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Response Delay    alias=delay    url=test_post    delay=5s
    Log Delayed Responses
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}

Turn Logging Off And On
    New Browser    browser=chromium    headless=True    proxy=${PROXY_DICT}
    New Context
    New Page
    Turn Mitm Console Logging Off
    Add To Blocklist    robotframework
    ${status}    Run keyword And Return Status    Go To    https://robotframework.org/
    Turn Mitm Console Logging On


*** Keywords ***
Check POST Response Of test_post
    [Arguments]    ${expected_text}    ${expected_status_code}    ${expected_headers}=None
    ${response}    POST On Session    alias=proxy    url=test_post/1    expected_status=any
    Should Be Equal As Strings    ${response.text}    ${expected_text}
    Should Be Equal As Integers    ${response.status_code}    ${expected_status_code}
    IF    ${expected_headers}
        Dictionary Should Contain Item    ${response.headers}    key=Content-Type    value=application/json
    END

Setup Flask
    ${subprocess_id}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website    run
    Start Mitm Proxy    localhost    ${8080}    certificates_directory=${CURDIR}/../resources/certificates
    VAR    ${SUBPROCESS}    ${subprocess_id}    scope=suite

Teardown Flask
    Stop Mitm Proxy
    Terminate Process    ${SUBPROCESS}
