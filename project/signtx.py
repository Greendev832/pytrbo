import hashlib, os
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def inv(a):
    return pow(a % P, P - 2, P)

def jdouble(Pt):
    if Pt is None: return None
    X, Y, Z = Pt
    if Y == 0 or Z == 0: return None
    Y2 = Y*Y % P
    S = 4*X*Y2 % P
    M = 3*X*X % P
    X3 = (M*M - 2*S) % P
    Y3 = (M*(S-X3) - 8*Y2*Y2) % P
    Z3 = 2*Y*Z % P
    return X3, Y3, Z3

def jadd(A, B):
    if A is None: return B
    if B is None: return A
    X1,Y1,Z1 = A; X2,Y2,Z2 = B
    Z1sq, Z2sq = Z1*Z1%P, Z2*Z2%P
    U1, U2 = X1*Z2sq%P, X2*Z1sq%P
    S1, S2 = Y1*Z2sq%P*Z2%P, Y2*Z1sq%P*Z1%P
    if U1 == U2:
        if S1 != S2: return None
        return jdouble(A)
    H = (U2-U1)%P; R = (S2-S1)%P
    H2, H3 = H*H%P, H*H*H%P
    U1H2 = U1*H2%P
    X3 = (R*R - H3 - 2*U1H2)%P
    Y3 = (R*(U1H2-X3) - S1*H3)%P
    Z3 = H*Z1%P*Z2%P
    return X3, Y3, Z3

def jmul(k, Pt):
    R = None
    while k:
        if k & 1: R = jadd(R, Pt)
        Pt = jdouble(Pt)
        k >>= 1
    return R

def affine(Pt):
    X,Y,Z = Pt
    zi = inv(Z)
    return X*zi%P*zi%P, Y*zi%P*zi%P*zi%P

G = (Gx, Gy, 1)

def sha256(b):
    return hashlib.sha256(b).digest()

def hash160(b):
    return hashlib.new("ripemd160", sha256(b)).digest()

def dsha(b):
    return sha256(sha256(b))

def b58check(payload):
    data = payload + dsha(payload)[:4]
    n = int.from_bytes(data, "big")
    out = b""
    while n:
        n, r = divmod(n, 58)
        out = bytes([B58[r]]) + out
    pad = 0
    for c in data:
        if c == 0: pad += 1
        else: break
    return (b"1"*pad + out).decode()

def push(data):
    if len(data) < 0x4c:
        return bytes([len(data)]) + data
    raise ValueError("too long")

def script_p2pkh(h160):
    return bytes.fromhex("76a914") + h160 + bytes.fromhex("88ac")

def ser_u32(n):
    return n.to_bytes(4, "little")

def ser_u64(n):
    return n.to_bytes(8, "little")

def der_int(x):
    b = x.to_bytes((x.bit_length()+7)//8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([2, len(b)]) + b

def sign(priv, digest):
    z = int.from_bytes(digest, "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % N
        if k == 0: continue
        R, Ry = affine(jmul(k, G))
        r = R % N
        if r == 0: continue
        s = (pow(k, -1, N) * (z + r * priv)) % N
        if s == 0: continue
        if s > N // 2:
            s = N - s
        sig = bytes([0x30, 0]) + der_int(r) + der_int(s)
        sig = bytes([0x30, len(sig)-2]) + sig[2:]
        return sig + bytes([1]), r, s

def verify(pub, digest, r, s):
    z = int.from_bytes(digest, "big")
    w = pow(s, -1, N)
    u1, u2 = (z*w) % N, (r*w) % N
    X, _ = affine(jadd(jmul(u1, G), jmul(u2, pub)))
    return X % N == r

# throwaway keys, no coins
priv = int.from_bytes(hashlib.sha256(b"kangaroo-demo-spend").digest(), "big") % N
dest = int.from_bytes(hashlib.sha256(b"kangaroo-demo-dest").digest(), "big") % N
pub = jmul(priv, G)
Px, Py = affine(pub)
pub_c = bytes([2 + (Py & 1)]) + Px.to_bytes(32, "big")
Dx, Dy = affine(jmul(dest, G))
dest_c = bytes([2 + (Dy & 1)]) + Dx.to_bytes(32, "big")
spk_in = script_p2pkh(hash160(pub_c))
spk_out = script_p2pkh(hash160(dest_c))

prev = bytes(range(32))  # fake txid, not a real UTXO
vout = 0
value_in = 100_000
value_out = 90_000
seq = 0xFFFFFFFF
locktime = 0
version = 1

def raw(script_sig, extra_type=False):
    parts = [
        ser_u32(version),
        bytes([1]),
        prev,
        ser_u32(vout),
        bytes([len(script_sig)]),
        script_sig,
        ser_u32(seq),
        bytes([1]),
        ser_u64(value_out),
        bytes([len(spk_out)]),
        spk_out,
        ser_u32(locktime),
    ]
    if extra_type:
        parts.append(ser_u32(1))
    return b"".join(parts)

preimage = raw(spk_in, extra_type=True)
digest = dsha(preimage)
sig, r, s = sign(priv, digest)
assert verify(pub, digest, r, s)
script_sig = push(sig) + push(pub_c)
tx = raw(script_sig)

print("from_address", b58check(b"\x00" + hash160(pub_c)))
print("to_address", b58check(b"\x00" + hash160(dest_c)))
print("priv_demo", format(priv, "064x"))
print("pubkey", pub_c.hex())
print("scriptpubkey_in", spk_in.hex())
print("scriptpubkey_out", spk_out.hex())
print("sighash", digest.hex())
print("signature", sig.hex())
print("raw_tx", tx.hex())
print("bytes", len(tx))
print("fee_sats", value_in - value_out)
print("verified", True)