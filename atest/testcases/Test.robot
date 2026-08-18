*** Settings ***
Library             Collections
Library             OperatingSystem
Library             Process
Library             Browser
Library             RequestsLibrary
Library             MitmLibrary
Library             ${CURDIR}/../resources/servers.py

Suite Setup         Start Servers
Suite Teardown      Stop Servers
Test Setup          Clear All Proxy Items
Test Teardown       Clear All Proxy Items


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
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Custom Response With Post And Custom Status Code
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response Status Code    alias=number_post    url=test_post    status_code=${404}
    Log Custom Status Items
    Check POST Response    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Body
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response    alias=number_post    url=test_post    overwrite_body=<number_size>not_found</number_size>
    Log Custom Response Items
    Check POST Response    <number_size>not_found</number_size>    ${200}

Custom Response With Post And Custom StatusCode Using Add Custom Response
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Add Custom Response    alias=number_post    url=test_post    status_code=404
    Check POST Response    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Headers
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    VAR    &{new_headers}    Content-Type=application/json
    Add Custom Response    alias=number_post    url=test_post    overwrite_headers=${new_headers}
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}    ${new_headers}

Custom Response With Post And Full Custom Response
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    VAR    &{new_headers}    Content-Type=application/json
    Add Custom Response
    ...    alias=number_post
    ...    url=test_post
    ...    overwrite_headers=${new_headers}
    ...    status_code=${202}
    ...    overwrite_body=<number_size>test successful</number_size>
    Check POST Response    <number_size>test successful</number_size>    ${202}    ${new_headers}

Reusing An Alias Replaces The Custom Response
    Add Custom Response    alias=reused    url=test_post    overwrite_body=first
    Add Custom Response    alias=reused    url=test_post    overwrite_body=second
    Check POST Response    second    ${200}
    Remove Custom Response    reused
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Removing A Custom Status Code Restores The Original
    Add Custom Response Status Code    alias=number_post    url=test_post    status_code=${418}
    Check POST Response    <number_size>smaller than 2</number_size>    ${418}
    Remove Custom Status Code    number_post
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Clear All Proxy Items Removes Everything
    Add To Blocklist    /never_called
    Add Custom Response    alias=number_post    url=test_post    overwrite_body=stubbed
    Add Custom Response Status Code    alias=status    url=test_post    status_code=${500}
    Check POST Response    stubbed    ${500}
    Clear All Proxy Items
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Delayed Response With Post
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Add Response Delay    alias=delay    url=test_post    delay=5s
    Log Delayed Responses
    ${start}    Get Time    epoch
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
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
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}


*** Keywords ***
Check POST Response
    [Documentation]    Posts through the proxy and checks the body, status and headers.
    [Arguments]    ${expected_text}    ${expected_status_code}    ${expected_headers}=None
    ${response}    POST On Session    alias=proxy    url=test_post/1    expected_status=any
    Should Be Equal As Strings    ${response.text}    ${expected_text}
    Should Be Equal As Integers    ${response.status_code}    ${expected_status_code}
    IF    ${expected_headers}
        Dictionary Should Contain Item    ${response.headers}    key=Content-Type    value=application/json
    END

Check HTTPS POST Response
    [Documentation]    Posts through the proxy over TLS and checks the body and status.
    [Arguments]    ${expected_text}    ${expected_status_code}
    ${response}    POST On Session    alias=secure    url=test_post/1    expected_status=any
    Should Be Equal As Strings    ${response.text}    ${expected_text}
    Should Be Equal As Integers    ${response.status_code}    ${expected_status_code}

Open Browser Through Proxy
    [Documentation]    Opens a headless browser that routes its traffic through the proxy.
    VAR    &{proxy_dict}    server=http://127.0.0.1:${PROXY_PORT}
    New Browser    browser=chromium    headless=True    proxy=${proxy_dict}
    New Context    ignoreHTTPSErrors=${True}
    New Page

Wait For Server
    [Documentation]    Waits for a server, reporting what it printed if it never answers.
    ...    Without this the only signal is a timeout, which says nothing about why.
    [Arguments]    ${url}    ${process}    ${captured_output}
    TRY
        Wait Until Server Is Up    ${url}
    EXCEPT    AS    ${error}
        ${running}    Is Process Running    ${process}
        ${captured}    Run Keyword And Return Status    File Should Exist    ${captured_output}
        IF    ${captured}
            ${contents}    Get File    ${captured_output}
        ELSE
            VAR    ${contents}    <no output captured>
        END
        Log    Server still running: ${running}${\n}Server output:${\n}${contents}    level=ERROR
        Fail    ${error}
    END

Start Servers
    [Documentation]    Starts the local web servers and the proxy, then opens the sessions.
    Start Web Servers
    Start Proxy
    Open Sessions Through Proxy

Start Web Servers
    [Documentation]    Starts a plain and a TLS server on free ports and waits for both.
    ${http_port}    Get Free Port
    ${https_port}    Get Free Port
    VAR    ${HTTP_HOST}    127.0.0.1:${http_port}    scope=suite
    VAR    ${HTTP_URL}    http://127.0.0.1:${http_port}    scope=suite
    VAR    ${HTTPS_URL}    https://127.0.0.1:${https_port}    scope=suite

    ${http_process}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website
    ...    run    --host    127.0.0.1    --port    ${http_port}
    ...    stdout=${OUTPUT_DIR}/flask_http.log    stderr=STDOUT
    ${https_process}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website
    ...    run    --host    127.0.0.1    --port    ${https_port}    --cert    adhoc
    ...    stdout=${OUTPUT_DIR}/flask_https.log    stderr=STDOUT
    VAR    ${HTTP_PROCESS}    ${http_process}    scope=suite
    VAR    ${HTTPS_PROCESS}    ${https_process}    scope=suite

    Wait For Server    ${HTTP_URL}/    ${HTTP_PROCESS}    ${OUTPUT_DIR}/flask_http.log
    Wait For Server    ${HTTPS_URL}/    ${HTTPS_PROCESS}    ${OUTPUT_DIR}/flask_https.log

Start Proxy
    [Documentation]    Starts the proxy under test on a free port.
    ...    ssl_insecure is required because the local HTTPS server uses a self-signed
    ...    certificate, which the proxy would otherwise refuse to connect to.
    ${port}    Get Free Port
    VAR    ${PROXY_PORT}    ${port}    scope=suite
    Start Mitm Proxy    127.0.0.1    ${PROXY_PORT}
    ...    certificates_directory=${CURDIR}/../resources/certificates
    ...    ssl_insecure=${True}

Open Sessions Through Proxy
    [Documentation]    Opens a plain and a TLS session that both route through the proxy.
    VAR    &{requests_proxy}
    ...    http=http://127.0.0.1:${PROXY_PORT}
    ...    https=http://127.0.0.1:${PROXY_PORT}
    Create Session    alias=proxy    url=${HTTP_URL}    proxies=${requests_proxy}    timeout=30
    Create Session    alias=secure    url=${HTTPS_URL}    proxies=${requests_proxy}
    ...    verify=${False}    timeout=30

Stop Servers
    [Documentation]    Stops the proxy and both web servers.
    Stop Mitm Proxy
    Terminate Process    ${HTTP_PROCESS}
    Terminate Process    ${HTTPS_PROCESS}
