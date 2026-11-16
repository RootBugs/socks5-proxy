#!/usr/bin/env python3
"""SOCKS5 proxy (RFC 1928) built on raw sockets.

The proxy speaks the two-phase SOCKS5 protocol: a method-negotiation
greeting followed by a request (``CONNECT`` only, the command RFC 1928
defines for tunnelling TCP).  Every failure path returns the exact
reply code assigned by the RFC 1928 registry so clients can distinguish
"connection refused" from "host unreachable" from "command not
supported".

Public API
----------
``Socks5Proxy``
    Threaded proxy server with :meth:`Socks5Proxy.start` /
    :meth:`Socks5Proxy.stop` lifecycle.
``connect_through``
    Minimal client helper used by the tests and the README example.
``negotiate`` / ``read_request`` / ``send_reply`` / ``decode_address``
    Protocol primitives, individually testable.
``ProtocolError``
    Raised on malformed traffic or rejected negotiation; ``reply`` holds
    the request-phase reply code to send (or ``None`` if none applies).
"""

from __future__ import annotations

import argparse
import errno
import socket
import struct
import threading

# --- RFC 1928 constants ----------------------------------------------------

VERSION = 0x05
AUTH_NONE = 0x00
AUTH_NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 0x01

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REPLY_SUCCESS = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_NETWORK_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONNECTION_REFUSED = 0x05
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

_BUFFER = 65536

# Platform errno sets for mapping OS connect() failures to SOCKS5 replies.
_REFUSED_ERRNOS = {errno.ECONNREFUSED, 10061}          # 10061 = WSAECONNREFUSED
_NET_UNREACH_ERRNOS = {errno.ENETUNREACH, 10051}       # 10051 = WSAENETUNREACH
_HOST_UNREACH_ERRNOS = {errno.EHOSTUNREACH, 10065,     # 10065 = WSAEHOSTUNREACH
                        errno.ETIMEDOUT, 10060}        # 10060 = WSAETIMEDOUT


class ProtocolError(Exception):
    """Malformed SOCKS5 traffic or rejected negotiation.

    Attributes:
        reply: request-phase reply code the server should send before
            closing, or ``None`` when no reply is defined for the error.
    """

    def __init__(self, message: str, reply: int | None = None) -> None:
        super().__init__(message)
        self.reply = reply


# --- Wire helpers -----------------------------------------------------------


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly *size* bytes or raise ``ProtocolError`` on EOF."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError(
                f"connection closed mid-frame (wanted {size} bytes)")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def negotiate(sock: socket.socket) -> None:
    """Perform the greeting phase and select the no-auth method.

    Raises:
        ProtocolError: the client spoke a non-SOCKS5 version, or offered
            no method this server supports (in which case ``05 FF`` is
            written back before raising).
    """
    version, nmethods = recv_exact(sock, 2)
    if version != VERSION:
        raise ProtocolError(f"unsupported SOCKS version {version:#04x}")
    methods = recv_exact(sock, nmethods)
    if AUTH_NONE not in methods:
        sock.sendall(bytes([VERSION, AUTH_NO_ACCEPTABLE]))
        raise ProtocolError("no acceptable authentication method")
    sock.sendall(bytes([VERSION, AUTH_NONE]))


def decode_address(sock: socket.socket) -> tuple[int, str, int]:
    """Read ``ATYP + address + port``; return ``(atyp, host, port)``."""
    (atyp,) = struct.unpack("!B", recv_exact(sock, 1))
    if atyp == ATYP_IPV4:
        raw = recv_exact(sock, 4)
        host = socket.inet_ntop(socket.AF_INET, raw)
    elif atyp == ATYP_IPV6:
        raw = recv_exact(sock, 16)
        host = socket.inet_ntop(socket.AF_INET6, raw)
    elif atyp == ATYP_DOMAIN:
        (length,) = struct.unpack("!B", recv_exact(sock, 1))
        host = recv_exact(sock, length).decode("utf-8", "replace")
    else:
        raise ProtocolError(
            f"unsupported address type {atyp:#04x}",
            reply=REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
        )
    (port,) = struct.unpack("!H", recv_exact(sock, 2))
    return atyp, host, port


def read_request(sock: socket.socket) -> tuple[str, int]:
    """Read a request phase; return ``(host, port)`` of the CONNECT target.

    Only ``CONNECT`` is implemented (RFC 1928 leaves BIND/UDP ASSOCIATE to
    proxies that need them).  Unsupported commands and address types get
    their registry reply code written back before ``ProtocolError``.
    """
    version, cmd, _rsv = recv_exact(sock, 3)
    if version != VERSION:
        raise ProtocolError(f"unsupported SOCKS version {version:#04x}")
    if cmd != CMD_CONNECT:
        raise ProtocolError(
            f"unsupported command {cmd:#04x}", reply=REPLY_COMMAND_NOT_SUPPORTED
        )
    _atyp, host, port = decode_address(sock)
    return host, port


def send_reply(sock: socket.socket, code: int,
               bound: tuple | None = None) -> None:
    """Write a request-phase reply; *bound* is the upstream ``getsockname()``."""
    if bound is None:
        sock.sendall(bytes([VERSION, code, 0, ATYP_IPV4]) + b"\x00" * 4 + b"\x00\x00")
        return
    host, port = bound[0], bound[1]
    try:
        packed = socket.inet_pton(socket.AF_INET, host)
        atyp = ATYP_IPV4
    except OSError:
        try:
            packed = socket.inet_pton(socket.AF_INET6, host)
            atyp = ATYP_IPV6
        except OSError:
            packed, atyp = b"\x00" * 4, ATYP_IPV4
            port = 0
    sock.sendall(bytes([VERSION, code, 0, atyp]) + packed + struct.pack("!H", port))


def reply_code_for_oserror(exc: OSError) -> int:
    """Map an OS ``connect()`` failure to its RFC 1928 reply code."""
    if isinstance(exc, ConnectionRefusedError):
        return REPLY_CONNECTION_REFUSED
    if isinstance(exc, socket.gaierror):
        return REPLY_HOST_UNREACHABLE
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return REPLY_HOST_UNREACHABLE
    number = exc.errno if exc.errno is not None else getattr(exc, "winerror", None)
    if number in _REFUSED_ERRNOS:
        return REPLY_CONNECTION_REFUSED
    if number in _NET_UNREACH_ERRNOS:
        return REPLY_NETWORK_UNREACHABLE
    if number in _HOST_UNREACH_ERRNOS:
        return REPLY_HOST_UNREACHABLE
    return REPLY_GENERAL_FAILURE


# --- Data path --------------------------------------------------------------


def pipe(src: socket.socket, dst: socket.socket) -> None:
    """Copy *src* → *dst* until EOF, then half-close *dst* for writing.

    Running one :func:`pipe` per direction with both directions live gives
    full-duplex tunneling; half-closing propagates ``FIN`` so the peer on
    the far side observes EOF exactly when the originating side did.
    """
    try:
        while True:
            data = src.recv(_BUFFER)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _tunnel(a: socket.socket, b: socket.socket, timeout: float = 10.0) -> None:
    """Run both :func:`pipe` directions and wait for both to finish."""
    threads = [
        threading.Thread(target=pipe, args=(a, b), name="socks5-up", daemon=True),
        threading.Thread(target=pipe, args=(b, a), name="socks5-down", daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)


def connect_through(proxy: tuple[str, int], target: tuple[str, int],
                    timeout: float = 5.0) -> socket.socket:
    """Open *target* through *proxy* and return the tunneled socket.

    Performs greeting + CONNECT for IPv4 literals and domain names; the
    returned socket behaves like a direct connection to *target*.
    """
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        sock.sendall(bytes([VERSION, 1, AUTH_NONE]))
        version, method = recv_exact(sock, 2)
        if version != VERSION or method != AUTH_NONE:
            raise ProtocolError(
                f"proxy refused negotiation (ver={version} method={method})")
        host, port = target
        if ":" in host:  # IPv6 literal
            packed = socket.inet_pton(socket.AF_INET6, host)
            request = bytes([VERSION, CMD_CONNECT, 0, ATYP_IPV6]) + packed
        else:
            try:
                packed = socket.inet_pton(socket.AF_INET, host)
                request = bytes([VERSION, CMD_CONNECT, 0, ATYP_IPV4]) + packed
            except OSError:
                encoded = host.encode("idna")
                request = (bytes([VERSION, CMD_CONNECT, 0, ATYP_DOMAIN,
                                  len(encoded)]) + encoded)
        sock.sendall(request + struct.pack("!H", port))
        _ver, code, _rsv, atyp = recv_exact(sock, 4)
        if atyp == ATYP_IPV4:
            recv_exact(sock, 4)
        elif atyp == ATYP_IPV6:
            recv_exact(sock, 16)
        elif atyp == ATYP_DOMAIN:
            (length,) = struct.unpack("!B", recv_exact(sock, 1))
            recv_exact(sock, length)
        recv_exact(sock, 2)
        if code != REPLY_SUCCESS:
            raise ConnectionError(f"SOCKS5 connect failed with reply code {code}")
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _close_gracefully(sock: socket.socket, drain_timeout: float = 0.5) -> None:
    """Close without a reset: half-close, drain leftovers, then close.

    Closing a socket that still has unread received bytes makes the OS
    send RST instead of FIN, which would destroy reply data the client
    has not read yet.  Shutting down the write side first (so the peer
    sees a clean EOF) and draining until the peer leaves keeps the close
    graceful on both Windows and POSIX.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    try:
        sock.settimeout(drain_timeout)
        while sock.recv(4096):
            pass
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# --- Server -----------------------------------------------------------------


class Socks5Proxy:
    """Threaded SOCKS5 proxy listening on ``host:port`` (port 0 = ephemeral).

    Args:
        host: bind address; defaults to loopback so the proxy is never
            exposed off-machine by accident.
        port: bind port; ``0`` picks an ephemeral port (tests rely on it).
        connect_timeout: seconds allowed for the upstream ``CONNECT``.
        pipe_timeout: seconds to wait for tunnel threads during shutdown.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 connect_timeout: float = 10.0,
                 pipe_timeout: float = 10.0) -> None:
        self.host = host
        self.connect_timeout = connect_timeout
        self.pipe_timeout = pipe_timeout
        self._requested_port = port
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._handlers: list[threading.Thread] = []
        self._lock = threading.Lock()

    # -- lifecycle --

    def start(self) -> None:
        """Bind, listen and start the accept loop (idempotent guard)."""
        if self._listener is not None:
            raise RuntimeError("proxy already started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(0.25)
        listener.bind((self.host, self._requested_port))
        listener.listen(64)
        self.host, self._bound_port = listener.getsockname()[:2]
        self._listener = listener
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="socks5-accept", daemon=True)
        self._accept_thread.start()

    @property
    def address(self) -> tuple[str, int]:
        """The actual ``(host, port)`` bound (resolves ephemeral ports)."""
        if self._listener is None:
            raise RuntimeError("proxy not started")
        return self.host, self._bound_port

    def wait(self) -> None:
        """Block until the accept loop finishes (i.e. :meth:`stop`)."""
        if self._accept_thread is not None:
            self._accept_thread.join()

    def stop(self) -> None:
        """Stop accepting, drain in-flight handlers, release the port."""
        self._stop.set()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5.0)
            self._accept_thread = None
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        with self._lock:
            handlers = list(self._handlers)
            self._handlers.clear()
        for handler in handlers:
            handler.join(timeout=self.pipe_timeout)

    # -- internals --

    def _accept_loop(self) -> None:
        listener = self._listener
        while not self._stop.is_set():
            try:
                client, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle_client, args=(client,),
                name="socks5-handler", daemon=True)
            with self._lock:
                self._handlers = [t for t in self._handlers if t.is_alive()]
                self._handlers.append(thread)
            thread.start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(self.connect_timeout)
            negotiate(client)
            host, port = read_request(client)
            try:
                upstream = socket.create_connection(
                    (host, port), self.connect_timeout)
            except OSError as exc:
                send_reply(client, reply_code_for_oserror(exc))
                return
            send_reply(client, REPLY_SUCCESS, upstream.getsockname())
            client.settimeout(None)
            upstream.settimeout(None)
            _tunnel(client, upstream, self.pipe_timeout)
        except ProtocolError as exc:
            if exc.reply is not None:
                try:
                    send_reply(client, exc.reply)
                except OSError:
                    pass
        except (OSError, EOFError):
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    _close_gracefully(sock)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: run a standalone SOCKS5 proxy."""
    parser = argparse.ArgumentParser(description="SOCKS5 proxy (RFC 1928)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1080,
                        help="bind port (default: 1080; 0 = ephemeral)")
    parser.add_argument("--connect-timeout", type=float, default=10.0,
                        help="seconds allowed for upstream connects")
    args = parser.parse_args(argv)

    proxy = Socks5Proxy(args.host, args.port,
                        connect_timeout=args.connect_timeout)
    proxy.start()
    host, port = proxy.address
    print(f"SOCKS5 proxy listening on {host}:{port}", flush=True)
    try:
        proxy.wait()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
    finally:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
