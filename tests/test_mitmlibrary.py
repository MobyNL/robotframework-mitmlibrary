import asyncio
import logging
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from robot.api import logger

from MitmLibrary import MitmLibrary


class TestMitmLibraryGuards(unittest.TestCase):
    def setUp(self):
        self.library = MitmLibrary()

    def tearDown(self):
        self.library.controller.shutdown()

    def test_keyword_before_start_raises_readable_error(self):
        """Using a keyword before starting the proxy must not be an AttributeError."""
        with self.assertRaises(RuntimeError) as context:
            self.library.block_requests("ads", "example.com")
        self.assertIn("Start Mitm Proxy", str(context.exception))

    def test_stop_without_start_is_a_no_op(self):
        self.library.stop_mitm_proxy()  # must not raise

    def test_console_logging_can_be_set_before_start(self):
        self.library.turn_mitm_console_logging_off()
        self.assertFalse(self.library.log_to_console)
        self.library.turn_mitm_console_logging_on()
        self.assertTrue(self.library.log_to_console)

    def test_console_logging_propagates_to_running_proxy(self):
        self.library.interceptor = Mock()
        self.library.turn_mitm_console_logging_off()
        self.library.interceptor.set_console_logging.assert_called_once_with(False)

    def test_start_failure_is_raised(self):
        """A proxy that never binds must fail the keyword, not run green."""
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.STARTUP_TIMEOUT", 0.3),
        ):
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list,
                servers=SimpleNamespace(update=_noop_update),
            ))
            mock_master.return_value.run = lambda: _never_binds()
            with self.assertRaises(RuntimeError) as context:
                self.library.start_mitm_proxy(listen_port=8099)
        self.assertIn("Could not start the proxy", str(context.exception))
        self.assertIsNone(self.library.interceptor)
        self.assertIsNone(self.library.proxy_master)

    def test_start_failure_reports_the_logged_reason(self):
        """The mitmproxy error explaining the failure must reach the user."""
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.STARTUP_TIMEOUT", 0.3),
        ):
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list,
                servers=SimpleNamespace(update=_noop_update),
            ))

            async def failing_run():
                logging.getLogger("mitmproxy").error("address already in use")
                await asyncio.sleep(5)

            mock_master.return_value.run = failing_run
            with self.assertRaises(RuntimeError) as context:
                self.library.start_mitm_proxy(listen_port=8099)
        self.assertIn("address already in use", str(context.exception))

    def test_start_failure_handler_is_removed(self):
        """The temporary log handler must not outlive the startup check."""
        before = list(logging.getLogger().handlers)
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.STARTUP_TIMEOUT", 0.3),
        ):
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list,
                servers=SimpleNamespace(update=_noop_update),
            ))
            mock_master.return_value.run = lambda: _never_binds()
            with self.assertRaises(RuntimeError):
                self.library.start_mitm_proxy(listen_port=8099)
        self.assertEqual(logging.getLogger().handlers, before)

    def test_start_succeeds_when_the_proxy_binds(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy(listen_port=8099)
        self.assertIsNotNone(self.library.interceptor)

    def _bound_master(self, mock_master, port=8099):
        """Makes a patched DumpMaster look like a proxy that came up cleanly.

        Its `run()` stays alive until `shutdown()` is called, mirroring mitmproxy, so the
        shutdown path is exercised for real without waiting out a fixed sleep.
        """
        stop = threading.Event()
        mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
            listen_addrs=lambda: [("127.0.0.1", port)],
            servers=SimpleNamespace(update=_noop_update),
        ))
        mock_master.return_value.shutdown.side_effect = stop.set
        mock_master.return_value.run = lambda: _runs_until_stopped(stop)
        return mock_master.return_value

    def test_certificates_directory_is_passed_as_confdir(self):
        """A given directory must reach mitmproxy as 'confdir'."""
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.options.Options") as mock_options,
        ):
            self._bound_master(mock_master)
            self.library.start_mitm_proxy(certificates_directory="/tmp/certs")
        self.assertEqual(mock_options.call_args.kwargs["confdir"], "/tmp/certs")

    def test_confdir_is_omitted_when_no_directory_is_given(self):
        """Options rejects confdir=None, so the key must be left out entirely."""
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.options.Options") as mock_options,
        ):
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        self.assertNotIn("confdir", mock_options.call_args.kwargs)

    def test_default_listen_host_is_localhost(self):
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.options.Options") as mock_options,
        ):
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        self.assertEqual(mock_options.call_args.kwargs["listen_host"], "127.0.0.1")

    def test_stop_resets_state(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            master = self._bound_master(mock_master)
            self.library.start_mitm_proxy()
            self.library.stop_mitm_proxy()
        master.shutdown.assert_called_once()
        self.assertIsNone(self.library.proxy_master)
        self.assertIsNone(self.library.interceptor)
        self.assertIsNone(self.library.controller.future)

    def test_proxy_dying_immediately_is_raised(self):
        """A proxy whose run() returns straight away must fail the keyword."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list,
                servers=SimpleNamespace(update=_noop_update),
            ))
            mock_master.return_value.run = lambda: _returns_immediately()
            with self.assertRaises(RuntimeError) as context:
                self.library.start_mitm_proxy()
        self.assertIn("stopped immediately", str(context.exception))
        self.assertIsNone(self.library.proxy_master)

    def test_rule_keywords_register_rules(self):
        """Every rule keyword must land in the registry the running proxy reads."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()

        self.library.block_requests("ads", "example.com")
        self.library.set_response("alias", "/api", 201, None, "body")
        self.library.add_response_delay("delay", "/slow", "2s")
        self.library.set_response_status("status", "/api", 418)

        rules = {rule.alias: rule for rule in self.library.get_proxy_rules()}
        self.assertEqual(rules["ads"]["type"], "block")
        self.assertEqual(rules["alias"]["status_code"], 201)
        self.assertEqual(rules["delay"]["delay"], "2s")
        self.assertEqual(rules["status"]["status_code"], 418)

        with patch.object(logger, "info") as mock_info:
            self.library.log_proxy_rules()
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("example.com", logged)
        self.assertIn("/slow", logged)
        self.assertIn("418", logged)

        self.library.remove_rule("ads")
        self.library.remove_rule("alias")
        self.library.remove_rule("status")
        self.assertEqual([rule.alias for rule in self.library.get_proxy_rules()], ["delay"])

        self.library.clear_all_rules()
        self.assertEqual(self.library.get_proxy_rules(), [])

    def test_request_and_response_rule_keywords_register_rules(self):
        """The keywords added for request-side manipulation must reach the registry."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()

        self.library.set_request_headers("req_headers", "/api", {"A": "1"}, ["B"])
        self.library.set_request_body("req_body", "/api", "payload")
        self.library.rewrite_request_url("rewrite", "/api", "http://other/api")
        self.library.redirect_requests_to_host("redirect", "/api", "127.0.0.1", 8000)
        self.library.set_response_headers("resp_headers", "/api", {"C": "2"})
        self.library.set_response_body("resp_body", "/api", "body")

        rules = {rule.alias: rule for rule in self.library.get_proxy_rules()}
        self.assertEqual(rules["req_headers"]["type"], "request_headers")
        self.assertEqual(rules["req_headers"]["remove"], ["B"])
        self.assertEqual(rules["req_body"]["body"], "payload")
        self.assertEqual(rules["rewrite"]["target"], "http://other/api")
        self.assertEqual(rules["redirect"]["port"], 8000)
        self.assertEqual(rules["resp_headers"]["type"], "response_headers")
        self.assertEqual(rules["resp_body"]["type"], "response_body")

    def test_request_rules_are_applied_before_response_rules(self):
        """Get Proxy Rules reports application order, and request rules come first."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        self.library.set_response_body("resp", "/api", "body")
        self.library.set_request_headers("req", "/api", {"A": "1"})
        phases = [rule["phase"] for rule in self.library.get_proxy_rules()]
        self.assertEqual(phases, ["request", "response"])

    def test_logging_rules_when_there_are_none(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        with patch.object(logger, "info") as mock_info:
            self.library.log_proxy_rules()
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("No rules are loaded", logged)

    def test_removing_an_unknown_rule_warns_instead_of_failing(self):
        """A teardown removing a rule a failed test never added must not fail as well."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        with patch.object(logger, "warn") as mock_warn:
            self.library.remove_rule("never-added")
        self.assertIn("never-added", mock_warn.call_args[0][0])

    def test_reusing_an_alias_reports_the_replacement(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        self.library.set_response_status("alias", "/api", 404)
        with patch.object(logger, "info") as mock_info:
            self.library.set_response_status("alias", "/api", 500)
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("Replaced", logged)
        rules = self.library.get_proxy_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["status_code"], 500)

    def test_an_invalid_delay_fails_the_keyword(self):
        """The delay is converted here so a bad value fails the keyword that set it."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        with self.assertRaises(ValueError):
            self.library.add_response_delay("delay", "/slow", "not a time")

    def test_rules_survive_a_restart_of_the_proxy(self):
        """The registry outlives the proxy; only the addon reading it is rebuilt."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
            self.library.block_requests("ads", "example.com")
            self.library.stop_mitm_proxy()
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
        self.assertEqual([rule.alias for rule in self.library.get_proxy_rules()], ["ads"])

    def test_slow_shutdown_warns_instead_of_hanging_forever(self):
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.SHUTDOWN_TIMEOUT", 0.2),
        ):
            self._bound_master(mock_master)
            # A proxy that ignores the shutdown request must not hang the keyword.
            mock_master.return_value.shutdown.side_effect = None
            self.library.start_mitm_proxy()
            with patch.object(logger, "warn") as mock_warn:
                self.library.stop_mitm_proxy()
        self.assertIn("did not shut down", mock_warn.call_args.args[0])
        self.assertIsNone(self.library.proxy_master)

    def test_failure_to_close_servers_is_reported_not_raised(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list, servers=SimpleNamespace(update=_failing_update)
            ))
            with patch.object(logger, "warn") as mock_warn:
                self.library.stop_mitm_proxy()
        self.assertIn("Could not close the proxy servers", mock_warn.call_args.args[0])

    def test_proxy_stopping_with_an_error_is_logged(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            mock_master.return_value.run = lambda: _raises_after_binding()
            self.library.start_mitm_proxy()
            with patch.object(logger, "info") as mock_info:
                self.library.stop_mitm_proxy()
        logged = " ".join(str(call.args[0]) for call in mock_info.call_args_list)
        self.assertIn("stopped with an error", logged)

    def test_close_servers_without_a_proxyserver_addon(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
            mock_master.return_value.addons.get.side_effect = _addons_by_name(None)
            self.library.stop_mitm_proxy()
        self.assertIsNone(self.library.proxy_master)
    def test_get_proxy_address_before_start_raises_readable_error(self):
        with self.assertRaises(RuntimeError) as context:
            self.library.get_proxy_address()
        self.assertIn("Start Mitm Proxy", str(context.exception))

    def test_get_proxy_address_returns_the_bound_address(self):
        """The address must come from the proxy, so port 0 reports the real port."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master, port=8123)
            self.library.start_mitm_proxy(listen_port=0)
            address = self.library.get_proxy_address()
            self.library.stop_mitm_proxy()
        self.assertEqual(address.host, "127.0.0.1")
        self.assertEqual(address.port, 8123)
        self.assertEqual(address.url, "http://127.0.0.1:8123")

    def test_get_proxy_address_reports_the_first_of_several(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=lambda: [("127.0.0.1", 8123), ("::1", 8124)],
                servers=SimpleNamespace(update=_noop_update),
            ))
            stop = threading.Event()
            mock_master.return_value.shutdown.side_effect = stop.set
            mock_master.return_value.run = lambda: _runs_until_stopped(stop)
            self.library.start_mitm_proxy()
            with patch.object(logger, "info") as mock_info:
                address = self.library.get_proxy_address()
            self.library.stop_mitm_proxy()
        self.assertEqual(address.port, 8123)
        logged = " ".join(call.args[0] for call in mock_info.call_args_list)
        self.assertIn("returning the first", logged)

    def test_get_proxy_address_without_a_listening_address_raises(self):
        """A master that is up but bound to nothing must not report a made-up address."""
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            self._bound_master(mock_master)
            self.library.start_mitm_proxy()
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list,
                servers=SimpleNamespace(update=_noop_update),
            ))
            with self.assertRaises(RuntimeError) as context:
                self.library.get_proxy_address()
            self.library.stop_mitm_proxy()
        self.assertIn("not listening", str(context.exception))

    def test_failed_start_clears_the_interceptor(self):
        """An interceptor left behind would belong to a proxy that is not running."""
        with (
            patch("MitmLibrary.dump.DumpMaster") as mock_master,
            patch("MitmLibrary.proxy_controller.STARTUP_TIMEOUT", 0.3),
        ):
            mock_master.return_value.addons.get.side_effect = _addons_by_name(SimpleNamespace(
                listen_addrs=list,
                servers=SimpleNamespace(update=_noop_update),
            ))
            mock_master.return_value.run = _never_binds
            with self.assertRaises(RuntimeError):
                self.library.start_mitm_proxy()
        self.assertIsNone(self.library.interceptor)

    def test_controller_shutdown_stops_a_running_proxy_and_its_thread(self):
        with patch("MitmLibrary.dump.DumpMaster") as mock_master:
            master = self._bound_master(mock_master)
            self.library.start_mitm_proxy()
            self.library.controller.shutdown()
        master.shutdown.assert_called_once()
        self.assertIsNone(self.library.proxy_master)
        self.assertFalse(self.library.loop_handler.is_alive())


def _addons_by_name(proxyserver):
    """Fakes mitmproxy's addon lookup, which answers per name.

    The library asks for "proxyserver" and for "errorcheck", and handing the proxyserver
    stand-in to both would give it something that is not an errorcheck addon.
    """

    def get(name):
        return proxyserver if name == "proxyserver" else None

    return get


async def _returns_immediately():
    return None

async def _failing_update(_modes):
    raise OSError("could not close")


async def _raises_after_binding():
    await asyncio.sleep(0.05)
    raise OSError("proxy crashed")


async def _runs_until_stopped(stop):
    """Stands in for `Master.run()`: alive until shutdown is requested."""
    while not stop.is_set():
        await asyncio.sleep(0.01)


async def _noop_update(_modes):
    return True


async def _never_binds():
    await asyncio.sleep(5)


if __name__ == "__main__":
    unittest.main()
