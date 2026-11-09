P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def inv_mod_p(a):
    return pow(a % P, P - 2, P)

def jdouble(pt):
    if pt is None:
        return None
    x, y, z = pt
    if y == 0 or z == 0:
        return None
    y2 = y * y % P
    s = 4 * x * y2 % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * y2 * y2) % P
    z3 = 2 * y * z % P
    return x3, y3, z3

def jadd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1sq, z2sq = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2sq % P, x2 * z1sq % P
    s1 = y1 * z2sq % P * z2 % P
    s2 = y2 * z1sq % P * z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return jdouble(a)
    h = (u2 - u1) % P
    rr = (s2 - s1) % P
    h2, h3 = h * h % P, h * h * h % P
    u1h2 = u1 * h2 % P
    x3 = (rr * rr - h3 - 2 * u1h2) % P
    y3 = (rr * (u1h2 - x3) - s1 * h3) % P
    z3 = h * z1 % P * z2 % P
    return x3, y3, z3

def jmul(k, pt):
    result = None
    while k:
        if k & 1:
            result = jadd(result, pt)
        pt = jdouble(pt)
        k >>= 1
    return result

def affine_x(pt):
    x, _, z = pt
    zi = inv_mod_p(z)
    return x * zi % P * zi % P

def pubkey_point(compressed):
    x = int.from_bytes(compressed[1:], "big")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (compressed[0] & 1):
        y = P - y
    return x, y, 1

pub = bytes.fromhex("039a95675c1f7dd3f04977136bc79c266e63f702e7306d6a4fe44273187c4d88c3")
r = 0x6e29063494abb6f32460b9ad3d7fd99e191f9dcf36d2609d5e626c01804c9bbc
s = 0x1d34b91cebd45a44633ec449d4690c192ff28b7303a9cdb5cb1f965246248d44
z = 0x265e1fc1cd4190470b953d95fcbc012917c6a3af734a63ed5a58fdb93703d69b

w = pow(s, -1, N)
u1 = z * w % N
u2 = r * w % N
point = jadd(jmul(u1, (Gx, Gy, 1)), jmul(u2, pubkey_point(pub)))
print(point)
x = affine_x(point) % N

print(format(u1, "064x"))
print(format(u2, "064x"))
print(format(x, "064x"))
print(x == r)