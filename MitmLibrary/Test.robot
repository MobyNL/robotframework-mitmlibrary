*** Settings ***
Library  MitmLibrary.py
Library  Browser
Library    Dialogs

*** Variables ***
&{PROXY_DICT}  server=http://localhost:8080
&{BROWSER_ARGS}  proxy=${PROXY_DICT}

*** Test Cases ***
Do A Test
    Start Proxy  localhost  ${8080}  certificates_directory=./certificates
    New Browser  browser=chromium  headless=False  proxy=${PROXY_DICT}  devtools=True
    New Context
    New Page  https://www.hollandsnieuwe.nl/
    ${body}  Create Dictionary  id=300  type=MEMBER_GET_MEMBER  subType=MGM_MIJNHN
    ${body}  Create List  ${body}
    Add Custom Response    alias=features  url=cm/online/features  overwrite_body=${body}
    Reload
    Sleep  2s
    Add To Blocklist  hollandsnieuwe
    ${status}  Run keyword and return status  Go To  https://www.hollandsnieuwe.nl/
    Add To Blocklist  google
    ${status}  Run keyword and return status  Go To  https://www.google.nl/
    Should be True  not ${status}
    ${status}  Run keyword and return status  Go To  https://www.hollandsnieuwe.nl/
    Should be True  not ${status}
    Show Blocked Urls
    Remove From Blocklist    hollandsnieuwe
    Go To  https://www.hollandsnieuwe.nl/
    Show Blocked Urls
    Show Custom Response Items
    Remove Custom Response  alias=features
    Show Custom Response Items
    [Teardown]  Stop Proxy