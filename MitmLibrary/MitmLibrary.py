import asyncio
from version import VERSION

from async_loop_thread import AsyncLoopThread
from request_logger import RequestLogger

from mitmproxy import options
from mitmproxy.tools import dump

from robot.api.deco import library, not_keyword

@library(scope='SUITE',version=VERSION, auto_keywords=True)
class MitmLibrary:
    @not_keyword
    def __init__(self):
        self.proxy_master = ""
        self.request_logger = ""
        self.loop_handler = AsyncLoopThread()
        self.loop_handler.start()

    async def start_proxy(self,listen_host='0.0.0.0', listen_port=8080, certificates_directory="", ssl_insecure=False):
        opts = options.Options(listen_host=listen_host, listen_port=listen_port, confdir=certificates_directory, ssl_insecure=ssl_insecure)
        self.proxy_master = dump.DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        self.request_logger = RequestLogger(self.proxy_master)
        self.proxy_master.addons.add(self.request_logger)
        asyncio.run_coroutine_threadsafe(self.proxy_master.run(), self.loop_handler.loop)

    async def stop_proxy(self):
        self.proxy_master.shutdown()

    def add_to_blocklist(self, url):
        self.request_logger.add_to_blocklist(url)

    def remove_from_blocklist(self, url):
        self.request_logger.remove_from_blocklist(url)

    def make_custom_response(self, url, overwrite_headers="", overwrite_body="", status_code=200):
        self.request_logger.add_custom_response_item(url, overwrite_headers, overwrite_body,status_code)