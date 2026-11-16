"""End-to-end and unit tests for the SOCKS5 proxy (RFC 1928).

All servers bind port 0 (ephemeral) on loopback; waits are event-driven
(thread joins / socket reads) with no fixed sleeps acting as logic.
"""

import socket
import struct
import threading
import unittest

import socks5
from socks5 import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CMD_CONNECT,
    ProtocolError,
    REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_CONNECTION_REFUSED,
    Socks5Proxy,
    VERSION,
    connect_through,
    decode_address,
    negotiate,
    recv_exact,
)


class EchoServer:
    """Loopback echo server on an ephemeral port with clean shutdown."""

    def __init__(self, host="127.0.0.1", banner=None):
        self.banner = banner
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(16)
        self._sock.settimeout(0.25)
        self.host, self.port = self._sock.getsockname()[:2]
        self._clients = []
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._clients.append(client)
            threading.Thread(target=self._serve, args=(client,),
                             daemon=True).start()

    def _serve(self, client):
        try:
            if self.banner is not None:
                client.sendall(self.banner)
            while True:
                data = client.recv(65536)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5.0)
        for client in self._clients:
            try:
                client.close()
            except OSError:
                pass


class ProxyTestCase(unittest.TestCase):
    """Shared fixture: one proxy and one echo server per test."""

    def setUp(self):
        self.echo = EchoServer()
        self.proxy = Socks5Proxy(port=0, connect_timeout=3.0)
        self.proxy.start()

    def tearDown(self):
        self.proxy.stop()
        self.echo.stop()


class NegotiationTests(ProxyTestCase):

    def test_greeting_selects_no_auth(self):
        sock = socket.create_connection(self.proxy.address, timeout=3.0)
        try:
            sock.sendall(bytes([VERSION, 2, 0x02, 0x00]))  # offer two, pick none-auth
            self.assertEqual(recv_exact(sock, 2), b"\x05\x00")
        finally:
            sock.close()

    def test_no_acceptable_method_rejected_with_0xff(self):
        sock = socket.create_connection(self.proxy.address, timeout=3.0)
        try:
            sock.sendall(bytes([VERSION, 1, 0x02]))  # offer username/password only
            self.assertEqual(recv_exact(sock, 2), b"\x05\xff")
            # connection must be closed after the rejection
            self.assertEqual(sock.recv(4), b"")
        finally:
            sock.close()

    def test_bad_version_rejected_and_closed(self):
        sock = socket.create_connection(self.proxy.address, timeout=3.0)
        try:
            sock.sendall(b"\x04\x01\x00")  # SOCKS4 greeting
            self.assertEqual(sock.recv(4), b"")  # closed with no valid reply
        finally:
            sock.close()


class ConnectTests(ProxyTestCase):

    def test_connect_ipv4_roundtrip_both_directions(self):
        with connect_through(self.proxy.address,
                             (self.echo.host, self.echo.port)) as sock:
            payload = b"hello through socks5" * 10
            sock.sendall(payload)
            received = b""
            while len(received) < len(payload):
                chunk = sock.recv(65536)
                self.assertTrue(chunk, "connection closed mid-payload")
                received += chunk
            self.assertEqual(received, payload)

    def test_connect_domain_address_type(self):
        with connect_through(self.proxy.address,
                             ("localhost", self.echo.port)) as sock:
            sock.sendall(b"domain-target")
            self.assertEqual(sock.recv(64), b"domain-target")

    def test_target_data_flows_before_client_sends(self):
        banner_server = EchoServer(banner=b"WELCOME\r\n")
        try:
            with connect_through(self.proxy.address,
                                 (banner_server.host, banner_server.port)) as sock:
                self.assertEqual(sock.recv(64), b"WELCOME\r\n")
                sock.sendall(b"after-banner")
                self.assertEqual(sock.recv(64), b"after-banner")
        finally:
            banner_server.stop()

    def test_close_propagates_end_to_end(self):
        sock = connect_through(self.proxy.address,
                               (self.echo.host, self.echo.port))
        try:
            sock.sendall(b"last words")
            self.assertEqual(sock.recv(64), b"last words")
            sock.shutdown(socket.SHUT_WR)  # client half-close
            self.assertEqual(sock.recv(4), b"")  # EOF reaches it again
        finally:
            sock.close()

    def test_large_transfer_1mb_integrity(self):
        payload = bytes((i * 31 + 7) % 256 for i in range(1024 * 1024))
        sock = connect_through(self.proxy.address,
                               (self.echo.host, self.echo.port))
        try:
            sent = threading.Event()
            result = {}

            def sender():
                view = memoryview(payload)
                while view:
                    n = sock.send(view)
                    view = view[n:]
                sent.set()

            def receiver():
                chunks = []
                while sum(len(c) for c in chunks) < len(payload):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                result["data"] = b"".join(chunks)

            sender_thread = threading.Thread(target=sender)
            receiver_thread = threading.Thread(target=receiver)
            sender_thread.start()
            receiver_thread.start()
            sender_thread.join(timeout=30.0)
            receiver_thread.join(timeout=30.0)
            self.assertTrue(sent.is_set(), "sender did not finish")
            self.assertFalse(receiver_thread.is_alive(), "receiver hung")
            self.assertEqual(result["data"], payload)
        finally:
            sock.close()

    def test_concurrent_clients_stay_isolated(self):
        errors = []

        def client(tag):
            try:
                with connect_through(self.proxy.address,
                                     (self.echo.host, self.echo.port)) as sock:
                    payload = tag * 100
                    sock.sendall(payload)
                    received = b""
                    while len(received) < len(payload):
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        received += chunk
                    if received != payload:
                        errors.append(f"{tag!r} mismatch: {received[:20]!r}")
            except Exception as exc:  # pragma: no cover - failure reporting
                errors.append(f"{tag!r}: {exc!r}")

        threads = [threading.Thread(target=client, args=(f"client-{i}".encode(),))
                   for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)
        self.assertFalse(any(t.is_alive() for t in threads), "client hung")
        self.assertEqual(errors, [])

    def test_ipv6_end_to_end_when_available(self):
        # only exercised when the platform has a usable ::1 loopback
        server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            server.bind(("::1", 0))
        except OSError:
            server.close()
            self.skipTest("IPv6 loopback not available")
        server.listen(4)
        server.settimeout(0.25)

        def echo_once():
            try:
                client, _ = server.accept()
            except OSError:
                return
            try:
                data = client.recv(64)
                if data:
                    client.sendall(data)
            finally:
                client.close()

        thread = threading.Thread(target=echo_once, daemon=True)
        thread.start()
        try:
            sock = connect_through(self.proxy.address,
                                   ("::1", server.getsockname()[1]))
            try:
                sock.sendall(b"v6")
                self.assertEqual(sock.recv(64), b"v6")
            finally:
                sock.close()
        finally:
            server.close()
            thread.join(timeout=5.0)


class ErrorReplyTests(ProxyTestCase):

    def _connect_request(self, host, port, atyp=ATYP_IPV4):
        sock = socket.create_connection(self.proxy.address, timeout=3.0)
        try:
            sock.sendall(bytes([VERSION, 1, 0x00]))
            self.assertEqual(recv_exact(sock, 2), b"\x05\x00")
            if atyp == ATYP_IPV4:
                body = socket.inet_pton(socket.AF_INET, host)
                request = bytes([VERSION, CMD_CONNECT, 0, atyp]) + body
            elif atyp == ATYP_DOMAIN:
                encoded = host.encode()
                request = (bytes([VERSION, CMD_CONNECT, 0, atyp, len(encoded)])
                           + encoded)
            else:  # pragma: no cover - unused branch
                request = b""
            sock.sendall(request + struct.pack("!H", port))
            head = recv_exact(sock, 4)
            return sock, head
        except Exception:
            sock.close()
            raise

    def test_connection_refused_maps_to_reply_0x05(self):
        # grab a port that nothing listens on: bind, note it, close
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        sock, head = self._connect_request("127.0.0.1", dead_port)
        try:
            self.assertEqual(head[0], VERSION)
            self.assertEqual(head[1], REPLY_CONNECTION_REFUSED)
        finally:
            sock.close()

    def test_unsupported_command_maps_to_reply_0x07(self):
        sock = socket.create_connection(self.proxy.address, timeout=3.0)
        try:
            sock.sendall(bytes([VERSION, 1, 0x00]))
            self.assertEqual(recv_exact(sock, 2), b"\x05\x00")
            body = socket.inet_pton(socket.AF_INET, "127.0.0.1")
            sock.sendall(bytes([VERSION, 0x02, 0, ATYP_IPV4])  # BIND, not CONNECT
                         + body + struct.pack("!H", self.echo.port))
            head = recv_exact(sock, 4)
            self.assertEqual(head[1], REPLY_COMMAND_NOT_SUPPORTED)
        finally:
            sock.close()

    def test_unsupported_address_type_maps_to_reply_0x08(self):
        sock = socket.create_connection(self.proxy.address, timeout=3.0)
        try:
            sock.sendall(bytes([VERSION, 1, 0x00]))
            self.assertEqual(recv_exact(sock, 2), b"\x05\x00")
            sock.sendall(bytes([VERSION, CMD_CONNECT, 0, 0x09,  # bogus ATYP
                                1, 2, 3, 4]))
            head = recv_exact(sock, 4)
            self.assertEqual(head[1], 0x08)
        finally:
            sock.close()


class ProtocolUnitTests(unittest.TestCase):

    def test_decode_address_ipv6(self):
        class FakeSock:
            def __init__(self, data):
                self._data = data

            def recv(self, n):
                chunk, self._data = self._data[:n], self._data[n:]
                return chunk

        expected = "2001:db8::1"
        raw = (bytes([ATYP_IPV6])
               + socket.inet_pton(socket.AF_INET6, expected)
               + struct.pack("!H", 443))
        atyp, host, port = decode_address(FakeSock(raw))
        self.assertEqual(atyp, ATYP_IPV6)
        self.assertEqual(host, expected)
        self.assertEqual(port, 443)

    def test_decode_address_rejects_unknown_atyp(self):
        class FakeSock:
            def recv(self, n):
                return bytes([0x07])

        with self.assertRaises(ProtocolError) as ctx:
            decode_address(FakeSock())
        self.assertEqual(ctx.exception.reply, 0x08)

    def test_recv_exact_reports_truncation(self):
        class FakeSock:
            def __init__(self):
                self.calls = 0

            def recv(self, n):
                self.calls += 1
                return b"ab" if self.calls == 1 else b""

        with self.assertRaises(ProtocolError):
            recv_exact(FakeSock(), 4)

    def test_negotiate_rejects_socks4(self):
        class FakeSock:
            def __init__(self):
                self.sent = b""

            def recv(self, n):
                return b"\x04\x01"[:n]

            def sendall(self, data):
                self.sent += data

        fake = FakeSock()
        with self.assertRaises(ProtocolError):
            negotiate(fake)
        self.assertEqual(fake.sent, b"")


class LifecycleTests(unittest.TestCase):

    def test_stop_releases_port_for_rebind(self):
        proxy = Socks5Proxy(port=0)
        proxy.start()
        addr = proxy.address
        proxy.stop()
        rebinder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            rebinder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rebinder.bind(addr)  # would raise if the port were still held
        finally:
            rebinder.close()

    def test_restart_after_stop(self):
        proxy = Socks5Proxy(port=0)
        proxy.start()
        proxy.stop()
        proxy.start()
        try:
            echo = EchoServer()
            try:
                with connect_through(proxy.address,
                                     (echo.host, echo.port)) as sock:
                    sock.sendall(b"again")
                    self.assertEqual(sock.recv(16), b"again")
            finally:
                echo.stop()
        finally:
            proxy.stop()


if __name__ == "__main__":
    unittest.main()
