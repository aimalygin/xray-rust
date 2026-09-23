#!/usr/bin/env python3
"""Process lifetime regressions: normal completion, orphan child and interruption."""
import importlib.util
import errno
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location("collector",Path(__file__).resolve().parents[1]/"run-v07-performance.py")
collector=importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class ProcessLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.log=Path(self.directory.name)/"run.log"

    def tearDown(self):
        self.directory.cleanup()

    def test_normal_exit_has_no_surviving_group(self):
        result=collector.execute([sys.executable,"-c","pass"],self.log)
        self.assertEqual(result["returncode"],0)
        self.assertFalse(result["surviving_process_group"])
        self.assertTrue(result["process_group_empty_after_run"])

    def test_leaked_child_is_killed_and_fails_the_run(self):
        result=collector.execute([sys.executable,"-c","import subprocess; subprocess.Popen(['/bin/sleep','30'])"],self.log)
        self.assertEqual(result["returncode"],125)
        self.assertTrue(result["surviving_process_group"])
        self.assertTrue(result["process_group_empty_after_run"])

    def test_interruption_also_kills_the_process_group(self):
        original=subprocess.Popen.wait
        pids=[]
        def interrupt_once(child,*args,**kwargs):
            if not pids:
                pids.append(child.pid)
                raise KeyboardInterrupt
            return original(child,*args,**kwargs)
        with mock.patch.object(subprocess.Popen,"wait",interrupt_once):
            with self.assertRaises(KeyboardInterrupt):
                collector.execute(["/bin/sleep","30"],self.log)
        self.assertFalse(collector.group_exists(pids[0]))


class FixturePortTests(unittest.TestCase):
    def test_rejects_udp_collision_and_reserved_inbound_before_returning(self):
        tcp = mock.MagicMock()
        udp = mock.MagicMock()
        tcp.__enter__.return_value = tcp
        udp.__enter__.return_value = udp
        tcp.getsockname.side_effect = [("127.0.0.1", n) for n in [40000, 40001, 40002]]
        udp.bind.side_effect = [OSError(errno.EADDRINUSE, "in use"), None]
        with mock.patch.object(collector.socket, "socket", side_effect=[tcp, udp] * 3):
            self.assertEqual(collector.port({40001}), 40002)
        self.assertEqual(udp.bind.call_args_list, [mock.call(("127.0.0.1", 40000)), mock.call(("127.0.0.1", 40002))])

    def test_unexpected_udp_error_is_not_hidden(self):
        tcp = mock.MagicMock()
        udp = mock.MagicMock()
        tcp.__enter__.return_value = tcp
        udp.__enter__.return_value = udp
        tcp.getsockname.return_value = ("127.0.0.1", 40000)
        udp.bind.side_effect = PermissionError(errno.EACCES, "denied")
        with mock.patch.object(collector.socket, "socket", side_effect=[tcp, udp]):
            with self.assertRaises(PermissionError):
                collector.port()


if __name__=="__main__":unittest.main()
