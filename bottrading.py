# def bcdechex(dec):
#     dec = int(dec)
#     hex_str = ""

#     while dec > 0:
#         last = dec % 16
#         hex_str = format(last, 'x') + hex_str
#         dec = (dec - last) // 16

#     return hex_str or "0"


# def bchexdec(hex_str):
#     dec = 0
#     length = len(hex_str)

#     for i in range(length):
#         digit = int(hex_str[i], 16)
#         power = 16 ** (length - i - 1)
#         dec += digit * power

#     return dec

# def main():

#     k1 = int("1405924699393950650705035035648194463064496908512739764938914210840487641599")

#     s1 = int("123456789")
#     r1 = int("987654321")
#     e1 = int("111111111")

#     j = 0
#     limit = 11111111

#     print("Starting...")
#     print("Initial k1:", k1)
#     print()

#     for i in range(1, limit + 1):

#         k1 += 1

#         print("k1 =", k1)

#         # Integer arithmetic version
#         p = ((s1 * k1) // r1) + (e1 // r1)

#         print("p =", p)

#         # PHP:
#         # bcdechex($p)

#         p_hex = format(p, 'x')

#         print("hex =", p_hex)

#         hex_len = len(p_hex)

#         print("hex length =", hex_len)

#         j += 1

#         print("j =", j)
#         print("-" * 60)

#         # PHP:
#         # if(strlen(bcdechex($p))==64)

#         if hex_len == 64:
#             print()
#             print("FOUND!")
#             print("k1 =", k1)
#             print("p =", p)
#             print("hex =", p_hex)
#             break

