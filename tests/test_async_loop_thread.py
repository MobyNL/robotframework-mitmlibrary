# import asyncio
# import io
# from contextlib import redirect_stderr
# from unittest import TestCase
# from unittest.mock import Mock, patch

# from MitmLibrary.async_loop_thread import AsyncLoopThread


# class TestAsyncLoopThread(TestCase):
#     def setUp(self):
#         self.thread = AsyncLoopThread()

#     def test_init(self):
#         """Tests that the AsyncLoopThread initializes correctly."""
#         self.assertIsInstance(self.thread.loop, asyncio.AbstractEventLoop)

#     def test_run_event_loop(self):
#         """Tests that the run method starts the event loop."""
#         mock_event_loop = Mock(wraps=asyncio.get_event_loop())
#         with patch.object(asyncio, "new_event_loop", return_value=mock_event_loop):
#             thread = AsyncLoopThread()
#             thread.start()
#             thread.join()
#         mock_event_loop.run_forever.assert_called_once()

#     def test_run_event_loop_exception(self):
#         """Tests that exceptions are logged during event loop execution."""
#         with patch.object(
#             asyncio, "new_event_loop", side_effect=RuntimeError("Test exception")
#         ):
#             thread = AsyncLoopThread()
#             captured_logs = io.StringIO()
#             with redirect_stderr(captured_logs):
#                 thread.run()
#             self.assertIn(
#                 "Async loop thread error: Test exception", captured_logs.getvalue()
#             )
