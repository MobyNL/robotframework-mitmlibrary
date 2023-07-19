from mitmproxy import http

from robot.api import logger
from robot.utils import safe_str, DotDict


class RequestLogger:
    def __init__(self, master):
        self.master = master
        self.block_list = []
        self.custom_response_list = []
        self.custom_response_urls = []
        self.custom_response_status = []

    def request(self, flow: http.HTTPFlow) -> None:
        if any(url in flow.request.pretty_url for url in self.block_list):
            for url in self.block_list:
                if url in flow.request.pretty_host:
                    flow.kill()

    def response(self, flow: http.HTTPFlow) -> None:
        custom_status_urls = [status.url for status in self.custom_response_status]
        custom_response_urls = [response.url for response in self.custom_response_list]
        if any(url in flow.request.pretty_url for url in custom_response_urls):
            for custom_response in self.custom_response_list:
                if custom_response.url in flow.request.pretty_url:
                    self.update_request_with_custom_response(
                        flow, custom_response)
        if any(url in flow.request.pretty_url for url in custom_status_urls):
            for custom_status in self.custom_response_status:
                if custom_status.url in flow.request.pretty_url:
                    flow.response.status_code=custom_status.status_code

    def add_to_blocklist(self, url):
        self.block_list.append(url)

    def remove_from_blocklist(self, url):
        try:
            self.block_list.remove(url)
        except:
            logger.warn(f"{url} was not found in blocklist")

    def add_custom_response_item(self, alias, url, overwrite_headers=None, overwrite_body=None, status_code=200):
        self.custom_response_list.append(DotDict(
            {"alias": alias, "url": url, "headers": overwrite_headers, "body": overwrite_body, "status_code": status_code}))
        self.custom_response_urls.append(url)

    def remove_custom_response_item(self, alias: str):
        alias_index = next((index for (index, d) in enumerate(
            self.custom_response_list) if d["alias"] == alias), None)
        url_to_remove = self.custom_response_list[alias_index].url
        self.custom_response_list.pop(alias_index)
        self.custom_response_urls.remove(url_to_remove)

    def update_request_with_custom_response(self, flow, custom_response):
        logger.info(
            f"Trying to update response for {custom_response.url}", also_console=True)
        try:
            flow.response = http.Response.make(
                custom_response.status_code,
                safe_str(custom_response.body),
                custom_response.headers
            )
            logger.info(
                f"Succesfully updated response for {custom_response.url}", also_console=True)
        except:
            logger.info(
                f"Updating response for {custom_response.url} failed", also_console=True)

    def add_custom_response_status(self, alias, url, status_code):
        self.custom_response_list.append(DotDict(
            {"alias": alias, "url": url, "status_code": status_code}))

    def remove_custom_status(self, alias: str):
        alias_index = next((index for (index, d) in enumerate(
            self.custom_response_status) if d["alias"] == alias), None)
        self.custom_response_status.pop(alias_index)
