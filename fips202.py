
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf


rho = {(0, 0): 0}

x, y = 1, 0
for t in range(24):
    rho[(x, y)] = (t + 1) * (t + 2) // 2


pi = {}

for y in range(5):
    for x in range(5):
        xp, yp = (x + 3*y) % 5, x
        pi[(x, y)] = ((xp, yp, rho[xp, yp])


def rc(t):
    if not t % 255:
        return 1
    R = 1
    for i in range(1, (t % 255) + 1):
        R <<= 1
        R ^= 0b1110001 * ((R >> 8) & 1)
        R &= 0xff
    return R & 1

iota800, iota1600 = {}, {}

for i in range(24):
    for y in range(5):
        for x in range(5):
            RC = 0
            for j in range(7):
                RC |= rc(j + 7*i) << (2**j - 1)
            if i < 22:
                iota800[i] = RC & 0xffffffff
            iota1600[i] = RC
