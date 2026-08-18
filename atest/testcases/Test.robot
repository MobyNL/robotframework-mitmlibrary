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
Test Setup          Clear All Rules
Test Teardown       Clear All Rules


*** Test Cases ***
Block A Website
    [Documentation]    Reset mode drops the connection, so the navigation fails outright.
    Open Browser Through Proxy
    Block Requests    site    ${HTTP_HOST}    mode=RESET
    ${status}    Run Keyword And Return Status    Go To    ${HTTP_URL}/
    Log Proxy Rules
    Should Not Be True    ${status}

Blocking Answers With A Status Code By Default
    [Documentation]    The default is a real response, which every client reports alike.
    Block Requests    posts    /test_post
    Log Proxy Rules
    Check POST Response    ${EMPTY}    ${403}

Blocking Can Carry A Status Code And A Body
    Block Requests    posts    /test_post    status_code=${503}    body=maintenance
    Check POST Response    maintenance    ${503}

Blocking In Reset Mode Drops The Connection
    Block Requests    posts    /test_post    mode=RESET
    Run Keyword And Expect Error    *    POST On Session    alias=proxy    url=test_post/1

Removing A Blocking Rule Unblocks It
    Block Requests    posts    /test_post
    Check POST Response    ${EMPTY}    ${403}
    Remove Rule    posts
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Custom Response With Post And Custom Status Code
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Set Response Status    alias=number_post    url=test_post    status_code=${404}
    Log Proxy Rules
    Check POST Response    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Body
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Set Response    alias=number_post    url=test_post    body=<number_size>not_found</number_size>
    Log Proxy Rules
    Check POST Response    <number_size>not_found</number_size>    ${200}

Custom Response With Post And Custom StatusCode Using Set Response
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Set Response    alias=number_post    url=test_post    status_code=404
    Check POST Response    <number_size>smaller than 2</number_size>    ${404}

Custom Response With Post And Custom Headers
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    VAR    &{new_headers}    Content-Type=application/json
    Set Response    alias=number_post    url=test_post    headers=${new_headers}
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}    ${new_headers}

Custom Response With Post And Full Custom Response
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    VAR    &{new_headers}    Content-Type=application/json
    Set Response
    ...    alias=number_post
    ...    url=test_post
    ...    headers=${new_headers}
    ...    status_code=${202}
    ...    body=<number_size>test successful</number_size>
    Check POST Response    <number_size>test successful</number_size>    ${202}    ${new_headers}

Reusing An Alias Replaces The Rule
    Set Response    alias=reused    url=test_post    body=first
    Set Response    alias=reused    url=test_post    body=second
    Check POST Response    second    ${200}
    ${rules}    Get Proxy Rules
    Length Should Be    ${rules}    1
    Remove Rule    reused
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Removing A Custom Status Code Restores The Original
    Set Response Status    alias=number_post    url=test_post    status_code=${418}
    Check POST Response    <number_size>smaller than 2</number_size>    ${418}
    Remove Rule    number_post
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Removing A Rule That Does Not Exist Only Warns
    [Documentation]    A teardown must not fail because the test never got that far.
    Remove Rule    never_added

Clear All Rules Removes Everything
    Block Requests    never    /never_called
    Set Response    alias=number_post    url=test_post    body=stubbed
    Set Response Status    alias=status    url=test_post    status_code=${500}
    Check POST Response    stubbed    ${500}
    Clear All Rules
    ${rules}    Get Proxy Rules
    Should Be Empty    ${rules}
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

A Replacement And A Status Change Combine
    [Documentation]    Both rules apply: the response is built, then its status is set.
    ...    The old model let whichever ran last throw the other away.
    Set Response    alias=body    url=test_post    body=combined
    Set Response Status    alias=status    url=test_post    status_code=${418}
    Check POST Response    combined    ${418}

Rules Can Be Limited To A Number Of Requests
    Set Response    alias=once    url=test_post    body=first only    times=1
    Check POST Response    first only    ${200}
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    ${rules}    Get Proxy Rules
    Should Be Equal As Integers    ${rules}[0][used]    1
    Should Be Equal As Integers    ${rules}[0][remaining]    0

Rules Can Be Limited To One Http Method
    Set Response Status    alias=posts    url=test_    status_code=${418}    method=POST
    Check POST Response    <number_size>smaller than 2</number_size>    ${418}
    ${response}    GET On Session    alias=proxy    url=test_get    expected_status=any
    Should Be Equal As Integers    ${response.status_code}    ${200}

Rules Can Match On A Regular Expression
    Set Response Status    alias=posts    url=/test_post/\\d+    status_code=${418}    match=REGEX
    Check POST Response    <number_size>smaller than 2</number_size>    ${418}

Rules Can Match On A Glob
    Set Response Status    alias=posts    url=*/test_post/*    status_code=${418}    match=GLOB
    Check POST Response    <number_size>smaller than 2</number_size>    ${418}

An Invalid Regular Expression Fails Immediately
    Run Keyword And Expect Error    *not a valid regular expression*
    ...    Set Response Status    alias=bad    url=[unclosed    status_code=${418}    match=REGEX

Request Headers Can Be Added And Removed
    [Documentation]    The request really reaches the server, carrying the new headers.
    ...    The fake server echoes nothing back, so this asserts through the proxy's own
    ...    view of the rule instead of the response body.
    VAR    &{headers}    Authorization=Bearer test-token
    Set Request Headers    auth    /test_post    headers=${headers}    remove=['X-Drop']
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    ${rules}    Get Proxy Rules
    Should Be Equal    ${rules}[0][type]    request_headers
    Should Be Equal As Integers    ${rules}[0][used]    1

Request Body Can Be Replaced
    [Documentation]    The path decides the answer, so replacing the body must not
    ...    change it: this proves the request still completed after being rewritten.
    Set Request Body    payload    /test_post    {"replaced": true}    method=POST
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Requests Can Be Redirected To Another Host
    [Documentation]    Sends a request for post 1 to the TLS server instead, keeping the
    ...    path. The answer proves the request was really re-routed rather than faked:
    ...    a stubbed response could not have come from a different server.
    Redirect Requests To Host    stub    /test_post    127.0.0.1
    ...    port=${HTTPS_PORT}    scheme=https
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}

Request Urls Can Be Rewritten
    [Documentation]    Rewrites a request for a path that returns "smaller than 2" into
    ...    one for a path that returns "larger than 2".
    Rewrite Request Url    v2    /test_post/1    ${HTTP_URL}/test_post/3
    Check POST Response    <number_size>larger than 2</number_size>    ${200}

Response Headers Are Merged Rather Than Replaced
    VAR    &{headers}    Cache-Control=no-store
    Set Response Headers    caching    test_post    headers=${headers}
    ${response}    POST On Session    alias=proxy    url=test_post/1    expected_status=any
    Should Be Equal    ${response.headers}[Cache-Control]    no-store
    # The original content type survives, which is the difference from Set Response.
    Should Contain    ${response.headers}[Content-Type]    text/html

Response Body Can Be Replaced On Its Own
    Set Response Body    body    test_post    replaced body
    Check POST Response    replaced body    ${200}

Traffic Can Be Recorded And Asserted On
    [Documentation]    The library could always change traffic; this asserts on what the
    ...    application under test actually sent, which it could not do before.
    Start Recording
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Request Should Have Been Made    /test_post/1    method=POST
    Request Should Not Have Been Made    /never_called
    ${requests}    Get Recorded Requests    /test_post
    Length Should Be    ${requests}    1
    Should Be Equal As Integers    ${requests}[0][status_code]    ${200}
    Should Contain    ${requests}[0][response_body]    smaller than 2
    [Teardown]    Stop Recording

Recorded Requests Can Be Counted And Cleared
    Start Recording
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    ${count}    Get Request Count    /test_post    method=POST
    Should Be Equal As Integers    ${count}    2
    Request Should Have Been Made    /test_post    times=2
    Clear Recorded Requests
    ${count}    Get Request Count
    Should Be Equal As Integers    ${count}    0
    [Teardown]    Stop Recording

A Blocked Request Is Recorded Too
    [Documentation]    A request that never reached the server is exactly the kind a
    ...    suite wants to assert on.
    Start Recording
    Block Requests    posts    /test_post
    Check POST Response    ${EMPTY}    ${403}
    Request Should Have Been Made    /test_post
    [Teardown]    Stop Recording

Waiting For A Request That Has Already Been Made Returns At Once
    Start Recording
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    ${requests}    Wait Until Request Is Made    /test_post    timeout=5s
    Length Should Be    ${requests}    1
    [Teardown]    Stop Recording

Waiting For A Request That Never Comes Fails
    Start Recording
    Run Keyword And Expect Error    *Waited*
    ...    Wait Until Request Is Made    /never_called    timeout=500 ms
    [Teardown]    Stop Recording

Recording Keywords Explain Themselves When Recording Is Off
    Run Keyword And Expect Error    *Start Recording*    Get Recorded Requests

Delayed Response With Post
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    Add Response Delay    alias=delay    url=test_post    delay=5s
    Log Proxy Rules
    ${start}    Get Time    epoch
    Check POST Response    <number_size>smaller than 2</number_size>    ${200}
    ${end}    Get Time    epoch
    Should Be True    ${end} - ${start} >= 5    Response was not delayed by 5 seconds

Invalid Response Delay Fails Immediately
    Run Keyword And Expect Error    ValueError: Invalid time string 'not-a-delay'.
    ...    Add Response Delay    alias=delay    url=test_post    delay=not-a-delay
    Log Proxy Rules

Custom Response Over Https
    Check HTTPS POST Response    <number_size>smaller than 2</number_size>    ${200}
    Set Response
    ...    alias=secure
    ...    url=test_post
    ...    status_code=${203}
    ...    body=<number_size>intercepted over tls</number_size>
    Check HTTPS POST Response    <number_size>intercepted over tls</number_size>    ${203}

Block A Website Over Https
    Block Requests    posts    /test_post    mode=RESET
    Run Keyword And Expect Error    *    POST On Session    alias=secure    url=test_post/1

Turn Logging Off And On
    Block Requests    posts    /test_post
    Turn Mitm Console Logging Off
    Check POST Response    ${EMPTY}    ${403}
    Turn Mitm Console Logging On
    Check POST Response    ${EMPTY}    ${403}
    # The blocking itself must keep working regardless of the logging setting.
    Remove Rule    posts
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
    ${plain_port}    Get Free Port
    ${secure_port}    Get Free Port
    VAR    ${HTTP_PORT}    ${plain_port}    scope=suite
    VAR    ${HTTPS_PORT}    ${secure_port}    scope=suite
    VAR    ${HTTP_HOST}    127.0.0.1:${HTTP_PORT}    scope=suite
    VAR    ${HTTP_URL}    http://127.0.0.1:${HTTP_PORT}    scope=suite
    VAR    ${HTTPS_URL}    https://127.0.0.1:${HTTPS_PORT}    scope=suite

    ${http_process}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website
    ...    run    --host    127.0.0.1    --port    ${HTTP_PORT}
    ...    stdout=${OUTPUT_DIR}/flask_http.log    stderr=STDOUT
    ${https_process}    Start Process    flask    --app    ${CURDIR}/../resources/fake_website
    ...    run    --host    127.0.0.1    --port    ${HTTPS_PORT}    --cert    adhoc
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
