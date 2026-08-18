*** Settings ***
Library             Collections
Library             Process
Library             Browser
Library             RequestsLibrary
Library             MitmLibrary
Library             ${CURDIR}/../resources/servers.py

Suite Setup         Start Servers
Suite Teardown      Stop Servers
Test Setup          Clear All Proxy Items
Test Teardown       Clear All Proxy Items


*** Variables ***
@{BROWSER_ARGS_LIST}    --ignore-certificate-errors


*** Test Cases ***
Block A Website
    Open Browser Through Proxy
    Add To Blocklist    ${HTTP_HOST}
    ${status}    Run Keyword And Return Status    Go To    ${HTTP_URL}/
    Log Blocked Urls
    Should Not Be True    ${status}

Block A Website On A Path Fragment
    Add To Blocklist    /test_post
    Log Blocked Urls
    Run Keyword And Expect Error    *    POST On Session    alias=proxy    url=test_post/1

Removing A Url From The Blocklist Unblocks It
    Add To Blocklist    /test_post
    Run Keyword And Expect Error    *    POST On Session    alias=proxy    url=test_post/1
    Remove Url From Blocklist    /test_post
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}

Custom Response With Post And Custom Status Code
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response Status Code    alias=number_post    url=test_post    status_code=${404}
    Log Custom Status Items
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Body
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response    alias=number_post    url=test_post    overwrite_body=<number_size>not_found</number_size>
    Log Custom Response Items
    Check POST Response Of test_post    <number_size>not_found</number_size>    ${200}

Custom Response With Post And Custom StatusCode Using Add Custom Response
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response    alias=number_post    url=test_post    status_code=404
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Headers
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    &{new_headers}    Create Dictionary    Content-Type=application/json
    Add Custom Response    alias=number_post    url=test_post    overwrite_headers=${new_headers}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}    ${new_headers}

Custom Response With Post And Full Custom Response
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    &{new_headers}    Create Dictionary    Content-Type=application/json
    Add Custom Response
    ...    alias=number_post
    ...    url=test_post
    ...    overwrite_headers=${new_headers}
    ...    status_code=${202}
    ...    overwrite_body=<number_size>test successful</number_size>
    Check POST Response Of test_post    <number_size>test successful</number_size>    ${202}    ${new_headers}

Reusing An Alias Replaces The Custom Response
    Add Custom Response    alias=reused    url=test_post    overwrite_body=first
    Add Custom Response    alias=reused    url=test_post    overwrite_body=second
    Check POST Response Of test_post    second    ${200}
    Remove Custom Response    reused
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}

Removing A Custom Status Code Restores The Original
    Add Custom Response Status Code    alias=number_post    url=test_post    status_code=${418}
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${418}
    Remove Custom Status Code    number_post
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}

Clear All Proxy Items Removes Everything
    Add To Blocklist    /never_called
    Add Custom Response    alias=number_post    url=test_post    overwrite_body=stubbed
    Add Custom Response Status Code    alias=status    url=test_post    status_code=${500}
    Check POST Response Of test_post    stubbed    ${500}
    Clear All Proxy Items
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}

Delayed Response With Post
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    Add Response Delay    alias=delay    url=test_post    delay=5s
    Log Delayed Responses
    ${start}    Get Time    epoch
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}
    ${end}    Get Time    epoch
    Should Be True    ${end} - ${start} >= 5    Response was not delayed by 5 seconds

Invalid Response Delay Fails Immediately
    Run Keyword And Expect Error    ValueError: Invalid time string 'not-a-delay'.
    ...    Add Response Delay    alias=delay    url=test_post    delay=not-a-delay
    Log Delayed Responses

Custom Response Over Https
    Check HTTPS POST Response    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response
    ...    alias=secure
    ...    url=test_post
    ...    status_code=${203}
    ...    overwrite_body=<number_size>intercepted over tls</number_size>
    Check HTTPS POST Response    <number_size>intercepted over tls</number_size>    ${203}

Block A Website Over Https
    Add To Blocklist    /test_post
    Run Keyword And Expect Error    *    POST On Session    alias=secure    url=test_post/1

Turn Logging Off And On
    Add To Blocklist    /test_post
    Turn Mitm Console Logging Off
    Run Keyword And Expect Error    *    POST On Session    alias=proxy    url=test_post/1
    Turn Mitm Console Logging On
    Run Keyword And Expect Error    *    POST On Session    alias=proxy    url=test_post/1
    # The blocking itself must keep working regardless of the logging setting.
    Remove Url From Blocklist    /test_post
    Check POST Response Of test_post    <number_size>smaller than 2</number_size>    ${200}


*** Keywords ***
Check POST Response Of test_post
    [Arguments]    ${expected_text}    ${expected_status_code}    ${expected_headers}=None
    ${response}    POST On Session    alias=proxy    url=test_post/1    expected_status=any
    Should Be Equal As Strings    ${response.text}    ${expected_text}
    Should Be Equal As Integers    ${response.status_code}    ${expected_status_code}
    IF    ${expected_headers}
        Dictionary Should Contain Item    ${response.headers}    key=Content-Type    value=application/json
    END

Check HTTPS POST Response
    [Arguments]    ${expected_text}    ${expected_status_code}
    ${response}    POST On Session    alias=secure    url=test_post/1    expected_status=any
    Should Be Equal As Strings    ${response.text}    ${expected_text}
    Should Be Equal As Integers    ${response.status_code}    ${expected_status_code}

Open Browser Through Proxy
    &{proxy_dict}    Create Dictionary    server=http://localhost:${PROXY_PORT}
    New Browser    browser=chromium    headless=True    proxy=${proxy_dict}
    New Context    ignoreHTTPSErrors=${True}
    New Page

Start Servers
    ${http_port}    Get Free Port
    ${https_port}    Get Free Port
    ${proxy_port}    Get Free Port
    VAR    ${PROXY_PORT}    ${proxy_port}    scope=suite
    VAR    ${HTTP_HOST}    localhost:${http_port}    scope=suite
    VAR    ${HTTP_URL}    http://localhost:${http_port}    scope=suite
    VAR    ${HTTPS_URL}    https://localhost:${https_port}    scope=suite

    ${http_process}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website
    ...    run    --port    ${http_port}
    ${https_process}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website
    ...    run    --port    ${https_port}    --cert    adhoc
    VAR    ${HTTP_PROCESS}    ${http_process}    scope=suite
    VAR    ${HTTPS_PROCESS}    ${https_process}    scope=suite
    Wait Until Server Is Up    ${HTTP_URL}/
    Wait Until Server Is Up    ${HTTPS_URL}/

    # ssl_insecure is required because the local HTTPS server uses a self-signed
    # certificate, which the proxy would otherwise refuse to connect to.
    Start Mitm Proxy    localhost    ${proxy_port}
    ...    certificates_directory=${CURDIR}/../resources/certificates
    ...    ssl_insecure=${True}

    &{requests_proxy}    Create Dictionary    http=http://localhost:${proxy_port}
    ...    https=http://localhost:${proxy_port}
    Create Session    alias=proxy    url=${HTTP_URL}    proxies=${requests_proxy}    timeout=30
    Create Session    alias=secure    url=${HTTPS_URL}    proxies=${requests_proxy}
    ...    verify=${False}    timeout=30

Stop Servers
    Stop Mitm Proxy
    Terminate Process    ${HTTP_PROCESS}
    Terminate Process    ${HTTPS_PROCESS}
