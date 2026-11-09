"""
Every value the broken Dec 2014 RNG could produce.

Uses rng_nan_bug.broken_session + get_big_random (jsbn ECDSA.getBigRandom).

Output: list_256.csv — seed_byte, draw, private_key_hex, both address forms,
and R if that value were used as the ECDSA nonce k.
"""

import csv
import hashlib
import sys

from rng_nan_bug import N, draws, ec_mul

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def address(pub):
    h = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    return b58check(b"\0" + h)


def main(per_seed):
    with open("list_256.txt", "a", newline="") as f:
        out = csv.writer(f)
        # out.writerow(
        #     [
        #         "seed_byte",
        #         "draw",
        #         "private_key_hex",
        #         "address_uncompressed",
        #         "address_compressed",
        #         "R_if_used_as_nonce",
        #     ]
        # )

        for seed in range(256):
            for draw, value in enumerate(draws(seed, per_seed)):
                x, y = ec_mul(value)
                xb = x.to_bytes(32, "big")
                uncompressed = b"\x04" + xb + y.to_bytes(32, "big")
                compressed = (b"\x03" if y & 1 else b"\x02") + xb
                # out.writerow(
                #     [
                #         seed,
                #         draw,
                #         f"{value:064x}",
                #         address(uncompressed),
                #         address(compressed),
                #         f"{x % N:064x}",
                #     ]
                # )
                f.write(address(uncompressed)+"\n")
                f.write(address(compressed)+"\n")
                
            if seed % 32 == 31:
                print(f"  {seed + 1}/256 seeds done", flush=True)
    print(f"wrote list_256.csv: 256 seeds x {per_seed} draws = {256 * per_seed} rows")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 64)
