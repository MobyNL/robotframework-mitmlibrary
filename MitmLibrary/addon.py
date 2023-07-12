from mitmproxy import http

class RequestLogger:
    def request(self, flow: http.HTTPFlow):
        print(flow.request)
