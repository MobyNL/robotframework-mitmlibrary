from robot.api.deco import library
from .version import VERSION
from .MitmKeywords import MitmKeywords

@library(scope='SUITE', version=VERSION, auto_keywords=True)
class MitmKeywords(MitmKeywords):
    """MitmLibrary is a library that implements the mitmproxy package into 
    robotframework. Mitmproxy can be used to listen, intercept and manipulate network
    traffic. This enables us to manipulate our traffic on request level, without needing
    to build stubs or mocks.

    = Why use Mitm? =
    Mitm allows manipulation on single browser instance, by using a proxy. It does not
    require you to set up stubs or mocks that might influence the entire application at
    once, also resulting in stubbed/mocked behaviour while manual testing.

    Examples where Mitm is useful: 
    - When running in parallel, if you do not want your other instances to be influenced. 
    - Manipulate the response of a request to see how the front end handles it for a integrated service that is always up.
    - Or if stubs or mocks are not available (yet).
    - Or if their behaviour is not sufficient.

    = Mitm Certificates =
    To test with SSL verification, or use a browser without ignoring certificates,
    you will need to set up the certificates related to
    mitm. Follow the guide on the 
    [https://docs.mitmproxy.org/stable/concepts-certificates/|Mitm website]
    """
