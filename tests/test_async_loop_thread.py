import asyncio
from unittest import TestCase

from MitmLibrary.async_loop_thread import AsyncLoopThread


class TestAsyncLoopThread(TestCase):
    def setUp(self):
        self.thread = AsyncLoopThread()

    def tearDown(self):
        if self.thread.is_alive():
            self.thread.loop.call_soon_threadsafe(self.thread.loop.stop)
            self.thread.join(timeout=5)
        if not self.thread.loop.is_closed():
            self.thread.loop.close()

    def test_init(self):
        """The thread owns its own event loop and is a daemon."""
        self.assertIsInstance(self.thread.loop, asyncio.AbstractEventLoop)
        self.assertTrue(self.thread.daemon)
        self.assertFalse(self.thread.loop.is_running())

    def test_run_event_loop(self):
        """Starting the thread runs the loop, and coroutines can be scheduled on it."""

        async def answer():
            return 42

        self.thread.start()
        future = asyncio.run_coroutine_threadsafe(answer(), self.thread.loop)
        self.assertEqual(future.result(timeout=5), 42)
        self.assertTrue(self.thread.loop.is_running())

    def test_stopping_the_loop_ends_the_thread(self):
        """Stopping the loop lets the thread terminate."""
        self.thread.start()
        # Wait for the loop to actually be running before stopping it.
        asyncio.run_coroutine_threadsafe(asyncio.sleep(0), self.thread.loop).result(
            timeout=5
        )
        self.thread.loop.call_soon_threadsafe(self.thread.loop.stop)
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
