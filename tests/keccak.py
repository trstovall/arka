
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
# https://keccak.team/keccak_specs_summary.html


rho = [
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14
]


iota = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
]


ROTL32 = lambda x, n: ((x << n) ^ (x >> (32 - n))) % 2**32
ROTL64 = lambda x, n: ((x << n) ^ (x >> (64 - n))) % 2**64

load32 = lambda x: int.from_bytes(x if len(x) <= 4 else x[:4], 'little')
store32 = lambda x: int(x).to_bytes(4, 'little')

load64 = lambda x: int.from_bytes(x if len(x) <= 8 else x[:8], 'little')
store64 = lambda x: int(x).to_bytes(8, 'little')


def keccak_800(msg, outlen=32):

    def round(A, RC):
        # theta
        B, C, D = {}, {}, {}
        for x in range(5):
            C[x] = A[(x, 0)] ^ A[(x, 1)] ^ A[(x, 2)] ^ A[(x, 3)] ^ A[(x, 4)]
        for x in range(5):
            D[x] = C[4 if x == 0 else (x - 1)] ^ ROTL32(C[(x + 1) % 5], 1)
        for y in range(5):
            for x in range(5):
                A[(x, y)] ^= D[x]
        # rho and pi
        for y in range(5):
            for x in range(5):
                B[(y, (2*x + 3*y) % 5)] = ROTL32(A[(x, y)], rho[x + 5*y] % 32)
        # chi
        for y in range(5):
            for x in range(5):
                A[(x, y)] = B[(x, y)] ^ ((~B[((x + 1) % 5, y)]) & B[((x + 2) % 5, y)])
        # iota
        A[(0, 0)] ^= RC
        return A

    def f_perm(A):
        for i in range(22):
            A = round(A, iota[i] & 0xffffffff)
        return A

    # Initialize A
    A = {(x, y): 0 for x in range(5) for y in range(5)}
    # Ingest msg
    pos = 0
    while pos <= len(msg):
        if pos + 36 <= len(msg):
            for y in range(2):
                for x in range(5):
                    i = x + 5*y
                    if i < 9:
                        A[(x, y)] ^= load32(msg[pos + 4*i:pos + 4*i + 4])
        else:
            buffer = msg[pos:]
            buffer += b'\x81' if len(buffer) == 35 else (b'\x01' + bytes(34 - len(buffer)) + b'\x80')
            for y in range(2):
                for x in range(5):
                    i = x + 5*y
                    if i < 9:
                        A[(x, y)] ^= load32(buffer[4*i:4*i + 4])
        A = f_perm(A)
        pos += 36
    # Squeeze output
    output = b''
    while len(output) + 36 <= outlen:
        for y in range(2):
            for x in range(5):
                if x + 5*y < 9:
                    output += store32(A[(x, y)])
        if len(output) < outlen:
            A = f_perm(A)
    if len(output) < outlen:
        buffer = b''
        for y in range(2):
            for x in range(5):
                if x + 5*y < 9:
                    buffer += store32(A[(x, y)])
        output += buffer[:outlen%36]
    # Return output
    return output


def keccak_1600(msg, outlen=32):

    def round(A, RC):
        # theta
        B, C, D = {}, {}, {}
        for x in range(5):
            C[x] = A[(x, 0)] ^ A[(x, 1)] ^ A[(x, 2)] ^ A[(x, 3)] ^ A[(x, 4)]
        for x in range(5):
            D[x] = C[4 if x == 0 else (x - 1)] ^ ROTL64(C[(x + 1) % 5], 1)
        for y in range(5):
            for x in range(5):
                A[(x, y)] ^= D[x]
        # rho and pi
        for y in range(5):
            for x in range(5):
                B[(y, (2*x + 3*y) % 5)] = ROTL64(A[(x, y)], rho[x + 5*y])
        # chi
        for y in range(5):
            for x in range(5):
                A[(x, y)] = B[(x, y)] ^ ((~B[((x + 1) % 5, y)]) & B[((x + 2) % 5, y)])
        # iota
        A[(0, 0)] ^= RC
        return A

    def f_perm(A):
        for i in range(24):
            A = round(A, iota[i])
        return A

    A = {(x,y): 0 for x in range(5) for y in range(5)}
    pos = 0
    while pos <= len(msg):
        if pos + 136 <= len(msg):
            for y in range(4):
                for x in range(5):
                    i = x + 5*y
                    if i < 17:
                        A[(x, y)] ^= load64(msg[pos + 8*i:pos + 8*i + 8])
        else:
            buffer = msg[pos:]
            buffer += b'\x81' if len(buffer) == 135 else (b'\x01' + ((134 - len(buffer)) * b'\x00') + b'\x80')
            for y in range(4):
                for x in range(5):
                    i = x + 5*y
                    if i < 17:
                        A[(x, y)] ^= load64(buffer[8*i:8*i + 8])
        A = f_perm(A)
        pos += 136
    # Squeeze output
    output = b''
    while len(output) + 136 <= outlen:
        for y in range(4):
            for x in range(5):
                if x + 5*y < 17:
                    output += store64(A[(x, y)])
        if len(output) < outlen:
            A = f_perm(A)
    if len(output) < outlen:
        buffer = b''
        for y in range(4):
            for x in range(5):
                if x + 5*y < 17:
                    buffer += store64(A[(x, y)])
        output += buffer[:outlen%136]
    # Return output
    return output
