"""
This file defines the AsyncLoopThread class, which is used to run the MitmProxy instance in a separate asynchronous thread.

This enables Robot Framework tests to interact with the MitmProxy instance without blocking the main test execution thread.
"""

import asyncio
from threading import Thread


class AsyncLoopThread(Thread):
    """
    A class that runs the MitmProxy instance in a separate asynchronous thread.

    This allows Robot Framework tests to interact with the MitmProxy instance without blocking the main test execution thread.
    """

    def __init__(self) -> None:
        """
        Initializes the AsyncLoopThread instance.

        This method creates a new thread and initializes the asyncio event loop.
        """
        super().__init__(daemon=True)
        self.loop = asyncio.new_event_loop()

    def run(self) -> None:
        """
        Runs the asyncio event loop in the separate thread.

        This method sets the event loop for the thread and then runs it forever.
        """
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        except Exception as e:
            print(f"Async loop thread error: {e}")  # Log the error message
