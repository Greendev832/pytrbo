#!/usr/bin/env python3
import hashlib, json, socket, ssl, sys

SERVER, PORT = "electrum.blockstream.info", 50002
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def b58check_decode(text):
    n = 0
    for c in text:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    data, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != checksum:
        raise ValueError("bad base58 checksum")
    return data

def bech32_polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk

def bech32_decode(text):
    text = text.lower()
    hrp, _, data = text.rpartition("1")
    values = [BECH.index(c) for c in data]
    if bech32_polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values) != 1:
        raise ValueError("bad bech32 checksum")
    return hrp, values[0], values[1:-6]

def convertbits(data, frombits, tobits):
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out

def script_for_address(address):
    if address.lower().startswith("bc1"):
        hrp, version, program5 = bech32_decode(address)
        program = bytes(convertbits(program5, 5, 8))
        if version == 0 and len(program) == 20:
            return b"\x00\x14" + program
        if version == 0 and len(program) == 32:
            return b"\x00\x20" + program
        if version == 1 and len(program) == 32:
            return b"\x51\x20" + program
        raise ValueError("unsupported witness program")
    raw = b58check_decode(address)
    version, h160 = raw[0], raw[1:]
    if version == 0:
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"
    if version == 5:
        return b"\xa9\x14" + h160 + b"\x87"
    raise ValueError("unsupported address")

def electrum_call(method, params):
    ctx = ssl.create_default_context()
    with socket.create_connection((SERVER, PORT), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname=SERVER) as conn:
            def send(req_id, name, args):
                conn.sendall((json.dumps({"id": req_id, "method": name, "params": args}) + "\n").encode())
                buf = b""
                while b"\n" not in buf:
                    buf += conn.recv(65536)
                reply = json.loads(buf.split(b"\n", 1)[0])
                if reply.get("error"):
                    raise RuntimeError(reply["error"])
                return reply["result"]
            send(0, "server.version", ["python", "1.4"])
            return send(1, method, params)

def get_balance(address):
    # address = sys.argv[1]
    script = script_for_address(address)
    scripthash = hashlib.sha256(script).digest()[::-1].hex()
    balance = electrum_call("blockchain.scripthash.get_balance", [scripthash])
    return balance["confirmed"] / 1e8
    # print(balance["confirmed"] / 1e8, "BTC confirmed")
    # print(balance["unconfirmed"] / 1e8, "BTC unconfirmed")