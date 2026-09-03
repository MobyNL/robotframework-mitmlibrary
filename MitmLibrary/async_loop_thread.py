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
        except Exception as e:  # noqa: BLE001 - best-effort loop shutdown, must not raise
            print(f"Async loop thread error: {e}")  # Log the error message

    def stop(self, timeout: float = 5) -> None:
        """Stops the loop, waits for the thread to finish and closes the loop.

        Safe to call more than once, and safe to call on a thread that was never started.
        Closing the loop can raise on Windows, where the proactor loop objects to being
        closed from another thread; that is swallowed because the thread is going away
        regardless and there is nothing the caller could do about it.
        """
        if self.loop.is_closed():
            return
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self.is_alive():
            self.join(timeout=timeout)
        try:
            self.loop.close()
        except Exception as error:  # noqa: BLE001 - best-effort shutdown, must not raise
            print(f"Async loop thread could not be closed: {error}")
