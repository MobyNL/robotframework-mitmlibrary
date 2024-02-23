from time import sleep as time_sleep

from mitmproxy import http
from mitmproxy.tools import dump
from robot.api import logger
from robot.utils import DotDict, safe_str, timestr_to_secs


class RequestLogger:
    def __init__(self, master: dump.DumpMaster, log_to_console: bool = True) -> None:
        self.master = master
        self.block_list = []
        self.custom_response_list = []
        self.custom_response_status = []
        self.response_delays_list = []
        self.custom_status_urls = []
        self.custom_response_urls = []
        self.delay_response_urls = []
        self.log_to_console = log_to_console

    def request(self, flow: http.HTTPFlow) -> None:
        if any(url in flow.request.pretty_url for url in self.block_list):
            for url in self.block_list:
                if url in flow.request.pretty_host:
                    flow.kill()
                    logger.info(
                        f"Blocked request for {flow.request.pretty_url}",
                        also_console=self.log_to_console,
                    )

    def response(self, flow: http.HTTPFlow) -> None:
        self.custom_status_urls.extend(
            status.url for status in self.custom_response_status
        )
        self.custom_response_urls.extend(
            response.url for response in self.custom_response_list
        )
        self.delay_response_urls.extend(
            response.url for response in self.response_delays_list
        )
        if any(url in flow.request.pretty_url for url in self.custom_response_urls):
            for custom_response in self.custom_response_list:
                if custom_response.url in flow.request.pretty_url:
                    self.update_request_with_custom_response(flow, custom_response)
        if any(url in flow.request.pretty_url for url in self.custom_status_urls):
            for custom_status in self.custom_response_status:
                if custom_status.url in flow.request.pretty_url:
                    flow.response.status_code = custom_status.status_code

        if any(url in flow.request.pretty_url for url in self.delay_response_urls):
            for response_delay in self.response_delays_list:
                if response_delay.url in flow.request.pretty_url:
                    logger.info(
                        f"Delay response for {response_delay.url} for "
                        f"{response_delay.delay} seconds",
                        also_console=self.log_to_console,
                    )
                    time_sleep(timestr_to_secs(response_delay.delay))

    def add_to_blocklist(self, url: str) -> None:
        self.block_list.append(url)

    def add_response_delay_item(self, alias: str, url: str, delay: str) -> None:
        self.response_delays_list.append(
            DotDict({"alias": alias, "url": url, "delay": delay})
        )

    def clear_all_proxy_items(self) -> None:
        self.block_list.clear()
        self.custom_response_list.clear()
        self.custom_response_status.clear()
        self.response_delays_list.clear()

    def remove_from_blocklist(self, url: str) -> None:
        try:
            self.block_list.remove(url)
        except:
            logger.warn(f"{url} was not found in blocklist")

    def add_custom_response_item(
        self,
        alias: str,
        url: str,
        overwrite_headers=None,
        overwrite_body=None,
        status_code: int = 200,
    ) -> None:
        self.custom_response_list.append(
            DotDict(
                {
                    "alias": alias,
                    "url": url,
                    "headers": overwrite_headers,
                    "body": overwrite_body,
                    "status_code": status_code,
                }
            )
        )

    def remove_custom_response_item(self, alias: str) -> None:
        alias_index = next(
            (
                index
                for (index, d) in enumerate(self.custom_response_list)
                if d["alias"] == alias
            ),
            None,
        )
        url_to_remove = self.custom_response_list[alias_index].url
        self.custom_response_list.pop(alias_index)
        self.custom_response_urls.remove(url_to_remove)

    def update_request_with_custom_response(
        self, flow: http.HTTPFlow, custom_response
    ) -> None:
        logger.info(
            f"Trying to update response for {custom_response.url}",
            also_console=self.log_to_console,
        )
        if custom_response.headers:
            header_list = []
            for key, value in custom_response.headers.items():
                logger.info(key, also_console=self.log_to_console)
                header_list.append((bytes(key, "utf-8"), bytes(value, "utf-8")))
            headers = http.Headers(header_list)
        elif hasattr(flow, "headers"):
            headers = flow["headers"]
        else:
            headers = http.Headers()
        try:
            flow.response = http.Response.make(
                custom_response.status_code, safe_str(custom_response.body), headers
            )
            logger.info(
                f"Succesfully updated response for {custom_response.url}",
                also_console=self.log_to_console,
            )
        except:
            logger.info(
                f"Updating response for {custom_response.url} failed",
                also_console=self.log_to_console,
            )

    def add_custom_response_status(
        self, alias: str, url: str, status_code: int
    ) -> None:
        self.custom_response_list.append(
            DotDict({"alias": alias, "url": url, "status_code": status_code})
        )

    def remove_custom_status(self, alias: str) -> None:
        alias_index = next(
            (
                index
                for (index, d) in enumerate(self.custom_response_status)
                if d["alias"] == alias
            ),
            None,
        )
        self.custom_response_status.pop(alias_index)

    def set_console_logging(self, value: bool) -> None:
        self.log_to_console = value
