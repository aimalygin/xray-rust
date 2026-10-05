import asyncio
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'android_fixture', Path(__file__).resolve().parents[1] / 'run-v08-android-protocol-fixture.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class Writer:
    def __init__(self):
        self.data = b''
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class AndroidFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_delayed_udp_reply_preserves_nonce_and_waits(self):
        response_ready = asyncio.Event()
        sent = []

        class Transport:
            def is_closing(self):
                return False

            def sendto(self, data, address):
                sent.append((data, address))
                response_ready.set()

        query = (bytes.fromhex('123401000001000000000000') + b'\x25xray-'
                 + b'0123456789abcdef' * 2 + b'\x07example\x03com\x00\x00\x01\x00\x01')
        oracle = FIXTURE.Oracle()
        oracle.connection_made(Transport())
        oracle.delay_seconds = 0.01
        with patch('builtins.print'):
            oracle.datagram_received(query, ('127.0.0.1', 1234))
            self.assertEqual(sent, [])
            await asyncio.wait_for(response_ready.wait(), 1)
        self.assertEqual(sent, [(FIXTURE.oracle_reply(query), ('127.0.0.1', 1234))])

    async def test_hold_is_pending_until_peer_closes(self):
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_data(b'GET /v08-hold/42 HTTP/1.1\r\nHost: synthetic.test\r\n\r\n')
        opened = asyncio.Event()
        events = []

        def log(value, **kwargs):
            row = json.loads(value)
            events.append(row)
            if row['backend'] == 'hold-open':
                opened.set()

        with patch('builtins.print', side_effect=log):
            task = asyncio.create_task(FIXTURE.http_probe(reader, writer))
            await asyncio.wait_for(opened.wait(), 1)
            self.assertFalse(task.done())
            self.assertEqual(writer.data, b'')
            reader.feed_eof()
            await asyncio.wait_for(task, 1)
        self.assertTrue(writer.closed)
        self.assertEqual([(e['backend'], e['id']) for e in events],
                         [('hold-open', 42), ('hold-close', 42)])
        self.assertEqual(events[-1]['reason'], 'eof')

    async def test_ordinary_http_probe_still_returns_204(self):
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_data(b'GET /v08-probe HTTP/1.1\r\nHost: synthetic.test\r\n\r\n')
        with patch('builtins.print'):
            await FIXTURE.http_probe(reader, writer)
        self.assertIn(b'204 No Content', writer.data)
        self.assertTrue(writer.closed)

    async def test_invalid_hold_id_does_not_open_flow(self):
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_data(b'GET /v08-hold/private-data HTTP/1.1\r\n\r\n')
        with patch('builtins.print') as log:
            await FIXTURE.http_probe(reader, writer)
        log.assert_not_called()
        self.assertTrue(writer.closed)


if __name__ == '__main__':
    unittest.main()
