*** Settings ***
Library  ../../MitmLibrary.py
Library  Browser
Library  Dialogs
Library  RequestsLibrary

*** Variables ***
&{PROXY_DICT}  server=http://localhost:8080
&{BROWSER_ARGS}  proxy=${PROXY_DICT}
&{REQUESTS_PROXY}  http=http://localhost:8080  http://host.name=http://localhost:8080

*** Test Cases ***
Do A Test
    [Setup]  Start Proxy  localhost  ${8080}  certificates_directory=./certificates
    New Browser  browser=chromium  headless=False  proxy=${PROXY_DICT}
    New Context
    New Page  https://www.hollandsnieuwe.nl/
    ${body}  Create Dictionary  id=300  type=MEMBER_GET_MEMBER  subType=MGM_MIJNHN
    ${body}  Create List  ${body}
    Add Custom Response    alias=features  url=cm/online/features  overwrite_body=${body}
    Reload
    Sleep  2s
    Add To Blocklist  hollandsnieuwe
    ${status}  Run keyword and return status  Go To  https://www.hollandsnieuwe.nl/
    Sleep  2s
    Add To Blocklist  google
    ${status}  Run keyword and return status  Go To  https://www.google.nl/
    Sleep  2s
    Should be True  not ${status}
    ${status}  Run keyword and return status  Go To  https://www.hollandsnieuwe.nl/
    Sleep  2s
    Should be True  not ${status}
    Log Blocked Urls
    Remove Url From Blocklist    hollandsnieuwe
    Go To  https://www.hollandsnieuwe.nl/
    Sleep  2s
    Log Blocked Urls
    Log Custom Response Items
    Remove Custom Response  alias=features
    Log Custom Response Items
    [Teardown]  Stop Proxy

Do a post
    [Setup]  Start Proxy  localhost  ${8080}  certificates_directory=./certificates
    Create Session  alias=proxy  url=http://localhost:5000  proxies=${REQUESTS_PROXY}
    ${response}  POST on session  alias=proxy  url=test_post/1
    Should be equal  ${response.text}  <number_size>smaller than 2</number_size>
    Add Custom Response  alias=number_post  url=test_post  overwrite_body=<number_size>not_found</number_size>  status_code=404
    Log Custom Response Items
    Sleep  5s
    ${response}  POST on session  alias=proxy  url=test_post/1
    Should be equal  ${response.text}  <number_size>not_found</number_size>
    [Teardown]  Stop Proxy
