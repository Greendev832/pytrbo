import urllib.request

def convert_txid():
    txid = "1239cc137bd5b8cb9c41c050afe4dd39a77a7bc8c8f8b802f6999dd58fda1e14"
    vout = 0
    inp = bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little")
    print(inp.hex())

def send():
    RAW_TX = "0100000001141eda8fd59d99f602b8f8c8c87b7aa739dde4af50c0419ccbb8d57b13cc3912000000008a47304402203cd44b1fe1b6bd886c84b079ab674ab1d771ac158f1c1aa59f709881325f37df022037425a279dedfe0c5215bf0a980fa48837c2e43bf03b1651dd58cfc7a2d372680141040ab0cc178d88300001d14ef832b1c5a33d2c75c4f27e2e4680cd51647d1983b578df37e18b1910447220f337676eb7d85f39ab875f4a2dc6e7a482e27e4452e9ffffffff0200943577000000001976a914b558feadbf76cec1814f50d9da8a9dafd107722a88ac80ba953e000000001976a9147dab20b9ca82863981464977222067b22ccd59c988ac00000000"

    req = urllib.request.Request(
        "https://blockstream.info/api/tx",
        data=RAW_TX.encode(),
        method="POST",
    )

    try:
        res = urllib.request.urlopen(req)
        print(res.read().decode())
    except urllib.error.HTTPError as e:
        print(e.code, e.read().decode())


convert_txid()