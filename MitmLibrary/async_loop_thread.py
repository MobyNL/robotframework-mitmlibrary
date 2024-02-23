import asyncio
from threading import Thread


class AsyncLoopThread(Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.loop = asyncio.new_event_loop()

    def run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
