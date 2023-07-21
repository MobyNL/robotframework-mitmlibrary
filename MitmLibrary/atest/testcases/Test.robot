*** Settings ***
Library  ../../MitmLibrary.py
Library  Process
# Library  Browser
Library  RequestsLibrary
Library  Collections

Suite Setup     Setup Flask
Suite Teardown  Teardown Flask
Test Setup      Clear All Proxy Items
Test Teardown   Clear All Proxy Items

*** Variables ***
&{PROXY_DICT}  server=http://localhost:8080
&{BROWSER_ARGS}  proxy=${PROXY_DICT}
&{REQUESTS_PROXY}  http=http://localhost:8080  http://host.name=http://localhost:8080
&{DEFAULT_HEADERS}  Server=Werkzeug/2.2.2 Python/3.11.1  Date=Fri, 21 Jul 2023 16:27:23 GMT  Content-Type=text/html; charset=utf-8  Content-Length=41  Connection=close
*** Test Cases ***
# Do A Test
#     [Setup]  Start Proxy  localhost  ${8080}  certificates_directory=./certificates
#     New Browser  browser=chromium  headless=False  proxy=${PROXY_DICT}
#     New Context
#     New Page  https://www.hollandsnieuwe.nl/
#     ${body}  Create Dictionary  id=300  type=MEMBER_GET_MEMBER  subType=MGM_MIJNHN
#     ${body}  Create List  ${body}
#     Add Custom Response    alias=features  url=cm/online/features  overwrite_body=${body}
#     Reload
#     Sleep  2s
#     Add To Blocklist  hollandsnieuwe
#     ${status}  Run keyword and return status  Go To  https://www.hollandsnieuwe.nl/
#     Sleep  2s
#     Add To Blocklist  google
#     ${status}  Run keyword and return status  Go To  https://www.google.nl/
#     Sleep  2s
#     Should be True  not ${status}
#     ${status}  Run keyword and return status  Go To  https://www.hollandsnieuwe.nl/
#     Sleep  2s
#     Should be True  not ${status}
#     Log Blocked Urls
#     Remove Url From Blocklist    hollandsnieuwe
#     Go To  https://www.hollandsnieuwe.nl/
#     Sleep  2s
#     Log Blocked Urls
#     Log Custom Response Items
#     Remove Custom Response  alias=features
#     Log Custom Response Items
#     [Teardown]  Stop Proxy

Custom Response With Post And Custom Body
    Create Session  alias=proxy  url=http://localhost:5000  proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post  <number_size>smaller than 2</number_size>  ${200}
    Add Custom Response  alias=number_post  url=test_post  overwrite_body=<number_size>not_found</number_size>
    Check POST Response Of test_post  <number_size>not_found</number_size>  ${200}

Custom Response With Post And Custom StatusCode
    Create Session  alias=proxy  url=http://localhost:5000  proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post  <number_size>smaller than 2</number_size>  ${200}
    Add Custom Response  alias=number_post  url=test_post  status_code=404
    Check POST Response Of test_post  ${None}  ${404}

Custom Response With Post And Custom Headers
    Create Session  alias=proxy  url=http://localhost:5000  proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post  <number_size>smaller than 2</number_size>  ${200}
    &{new_headers}  Create Dictionary  Content-Type=application/json
    Add Custom Response  alias=number_post  url=test_post  overwrite_headers=${new_headers}
    Check POST Response Of test_post  ${None}  ${200}  ${new_headers}

Custom Response With Post And Full Custom Response
    Create Session  alias=proxy  url=http://localhost:5000  proxies=${REQUESTS_PROXY}
    Check POST Response Of test_post  <number_size>smaller than 2</number_size>  ${200}
    &{new_headers}  Create Dictionary  Content-Type=application/json
    Add Custom Response  alias=number_post  url=test_post  overwrite_headers=${new_headers}  status_code=${202}  overwrite_body=<number_size>test successful</number_size>
    Check POST Response Of test_post  <number_size>test successful</number_size>  ${202}  ${new_headers}

Delayed Response With Post
    Create Session  alias=proxy  url=http://localhost:5000  proxies=${REQUESTS_PROXY}  timeout=10
    Check POST Response Of test_post  <number_size>smaller than 2</number_size>  ${200}
    Add Response Delay  alias=delay  url=test_post  delay=5s
    Log Delayed Responses
    Check POST Response Of test_post  <number_size>smaller than 2</number_size>  ${200}

*** Keywords ***
Check POST Response Of test_post
    [Arguments]  ${expected_text}  ${expected_status_code}  ${expected_headers}=None
    ${response}  POST on session  alias=proxy  url=test_post/1  expected_status=any
    Should Be Equal As Strings  ${response.text}  ${expected_text}
    Should Be Equal As Integers  ${response.status_code}  ${expected_status_code}
    IF  ${expected_headers}  Dictionary Should Contain Item  ${response.headers}  key=Content-Type  value=application/json

Setup Flask
    ${SUBPROCESS}  Start Process  flask  --app  ${CURDIR}/../resources/fake_website  run
    Start Proxy  localhost  ${8080}  certificates_directory=./certificates
    Set Suite Variable  ${SUBPROCESS}

Teardown Flask
    Stop Proxy
    Terminate Process  ${SUBPROCESS}