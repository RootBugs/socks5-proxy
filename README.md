# socks5-proxy

A SOCKS5 proxy (RFC 1928) that actually tunnels TCP, written from scratch on
raw `socket` + `threading` with zero dependencies.

**Why it's special:** most toy "proxies" just forward bytes; this one speaks
the real two-phase SOCKS5 protocol — method negotiation, `CONNECT` with
IPv4/IPv6/domain address types, and the RFC's full reply-code registry so
clients can tell *connection refused* from *host unreachable* from *command
not supported*. It also gets the nasty parts right: full-duplex piping with
true close propagation (FIN travels end-to-end), and a graceful close that
avoids the Windows RST-vs-FIN trap (closing a socket with unread bytes
resets the connection and destroys replies the client hasn't read yet).

## Architecture

```
client ──greeting──▶ negotiate()        version 5, method 0x00 selected,
                                        0xFF written when nothing matches
        ──request──▶ read_request()     CONNECT only; other commands get
                                        reply 0x07, bad ATYP gets 0x08
        ──connect──▶ upstream socket    OS errors mapped through
                                        reply_code_for_oserror() (0x05
                                        refused, 0x03/0x04 unreachable)
        ──reply────◀ send_reply()       BND.ADDR/BND.PORT = upstream
                                        getsockname()
        ──tunnel───▶ two pipe threads   one per direction; EOF on either
                                        side half-closes the other, so
                                        shutdown/close propagate cleanly
```

- `Socks5Proxy` — threaded server; `start()`/`stop()` lifecycle, port `0`
  binds an ephemeral port, accept loop wakes on a 0.25 s timeout so shutdown
  never races `accept()` (no POSIX-only signals, Windows-safe).
- `connect_through(proxy, target)` — minimal client helper used by the tests
  and the example below.
- Protocol primitives (`negotiate`, `read_request`, `decode_address`,
  `send_reply`, `recv_exact`) are exported individually and unit-tested.

## Runnable example

```python
import socket, threading
from socks5 import Socks5Proxy, connect_through

# a plain TCP echo server acting as the target
echo = socket.socket()
echo.bind(("127.0.0.1", 0))
echo.listen(1)

def serve():
    client, _ = echo.accept()
    while data := client.recv(65536):
        client.sendall(data)
    client.close()

threading.Thread(target=serve, daemon=True).start()

proxy = Socks5Proxy(port=0)          # 0 → ephemeral port
proxy.start()

sock = connect_through(proxy.address, echo.getsockname()[:2])
sock.sendall(b"hello socks5")
print(sock.recv(64))                 # bytes came back through the tunnel
sock.close()
proxy.stop()
echo.close()
```

Output:

```
b'hello socks5'
```

Standalone CLI:

```
python socks5.py --host 127.0.0.1 --port 1080
SOCKS5 proxy listening on 127.0.0.1:1080
```

Then any SOCKS5-aware client can `curl --socks5-hostname 127.0.0.1:1080 ...`.

## Tests

```
python -m unittest discover -s tests -v
```

19 tests cover: negotiation (no-auth selection, `0xFF` rejection, bad
version), end-to-end tunneling (IPv4, domain, IPv6-when-available, target
pushes data first, close propagation), a 1 MB simultaneous bidirectional
transfer, five concurrent isolated clients, error replies (`0x05` refused,
`0x07` command, `0x08` address type), protocol unit tests, and lifecycle
(restart, port release). All servers bind ephemeral loopback ports.
