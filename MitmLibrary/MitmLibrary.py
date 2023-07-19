import asyncio

from mitmproxy import options
from mitmproxy.tools import dump

from robot.api.deco import library, not_keyword
from robot.api import logger

from version import VERSION
from async_loop_thread import AsyncLoopThread
from request_logger import RequestLogger


@library(scope='SUITE', version=VERSION, auto_keywords=True)
class MitmLibrary:
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
    To test with SSL verification, you will need to set up the certificates related to
    mitm. Follow the guide on the 
    [https://docs.mitmproxy.org/stable/concepts-certificates/|Mitm website]
    """

    @not_keyword
    def __init__(self):
        self.proxy_master = ""
        self.request_logger = ""
        self.loop_handler = AsyncLoopThread()
        self.loop_handler.start()

    async def start_proxy(self, listen_host='0.0.0.0', listen_port=8080,
                          certificates_directory=None, ssl_insecure=False):
        """Starts a proxy at the given host and port. Default host is ``localhost``.
         It is possible to add ssl-verification by loading the mitm certificates.
         See the `Mitm Certificates` section for more information."""
        opts = options.Options(listen_host=listen_host, listen_port=listen_port,
                               confdir=certificates_directory, ssl_insecure=ssl_insecure)
        self.proxy_master = dump.DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        self.request_logger = RequestLogger(self.proxy_master)
        self.proxy_master.addons.add(self.request_logger)
        asyncio.run_coroutine_threadsafe(self.proxy_master.run(),
                                         self.loop_handler.loop)

    async def stop_proxy(self):
        """Stops the proxy."""
        self.proxy_master.shutdown()

    def add_to_blocklist(self, url):
        """Adds a (partial) url to the list of blocked urls. If the url is found in any
        part of the pretty_url of the host it will be blocked."""
        self.request_logger.add_to_blocklist(url)

    def add_custom_response(self, alias, url, overwrite_headers=None,
                            overwrite_body=None, status_code=200):
        """Adds a custom response based on a (partial) url to the list of blocked urls.
        If the (partial) url is found in any part of the pretty_url of the it's response
        will be changed ."""
        self.request_logger.add_custom_response_item(alias, url, overwrite_headers,
                                                     overwrite_body, status_code)

    def add_custom_response_status_code(self,alias, url, status_code=200):
        """Adds a custom response status_code to each request where the url matches with
        the url of the custom status_code.
        
        Often used status codes:
        - 200. Success
        - 401. 
        - 403. Unauthorized
        - 404. Not found
        - 500. Server error
        """

    def log_custom_response_items(self):
        """Logs the current list of url that will result in a custom response, if the 
        url is found in the pretty_url of a host.

        Will also log the custom response items themselves."""
        custom_responses = ", ".join(self.request_logger.custom_response_urls)
        logger.info(f"The following custom response are currently loaded: "
                    f"{custom_responses}.")

    def log_blocked_urls(self):
        """Logs the current list of items that will result in a block, if the url is
        found in the pretty_url of a host."""
        block_items = ", ".join(self.request_logger.block_list)
        logger.info(f"URLs containing any of the following in their url will "
                    f"be blocked: {block_items}.")

    def remove_url_from_blocklist(self, url):
        """Removes a custom (partial) url from the list."""
        self.request_logger.remove_from_blocklist(url)

    def remove_custom_response(self, alias):
        """Removes a custom response from the list, based on it's alias."""
        self.request_logger.remove_custom_response_item(alias)

    def remove_custom_status_code(self, alias):
        """Removes a custom status_code from the list."""
        self.request_logger.remove_custom_status(alias)
