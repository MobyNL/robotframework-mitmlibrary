from mitmproxy import http

from robot.api import logger
from robot.utils import safe_str, DotDict

class RequestLogger:
    def __init__(self, master):
        self.master = master
        self.block_list=[]
        self.custom_response_list=[]
        self.custom_response_urls=[]

    def request(self, flow: http.HTTPFlow) -> None:
        for url in self.block_list:
            if url in flow.request.pretty_host:
                flow.kill()

    def response(self, flow: http.HTTPFlow) -> None:
        if any(url in flow.request.pretty_url for url in self.custom_response_urls):
            for custom_response in self.custom_response_list:
                if custom_response.url in flow.request.pretty_url:
                    self.make_custom_response(flow, custom_response)

    def add_to_blocklist(self, url):
        self.block_list.append(url)

    def remove_from_blocklist(self, url):
        try: self.block_list.remove(url)
        except: logger.warn(f"{url} was not found in blocklist")

    def add_custom_response_item(self, url, overwrite_headers=None ,overwrite_body=None, status_code=200):
        self.custom_response_list.append(DotDict({"url": url, "headers": overwrite_headers, "body": overwrite_body, "status_code": status_code}))
        self.custom_response_urls.append(url)

    def make_custom_response(self, flow, custom_response):
        logger.info(f"Trying to update response for {custom_response.url}",also_console=True)
        try:
            flow.response = http.Response.make(
                    custom_response.status_code,
                    safe_str(custom_response.body),
                    custom_response.headers
                )
            logger.info(f"Succesfully updated response for {custom_response.url}",also_console=True)
        except:
            logger.info(f"Updating response for {custom_response.url} failed",also_console=True)