
#include "stdio.h"
#include "stdint.h"
#include "string.h"

#define ROTL64(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define ROTL32(a, offset) ((a << offset) ^ (a >> (32-offset)))
#define MIN(A, B) (((A) < (B)) ? (A) : (B))

uint64_t load64(const unsigned char *x)
{
    unsigned long long r = 0, i;

    for (i = 0; i < 8; ++i) {
        r |= (unsigned long long)x[i] << 8 * i;
    }
    return r;
}

uint32_t load32(const unsigned char *x)
{
    uint32_t r = 0, i;

    for (i = 0; i < 4; i++) {
        r |= (uint32_t)x[i] << 8 * i;
    }
    return r;
}

void store64(uint8_t *x, uint64_t u)
{
    unsigned int i;

    for (i = 0; i < 8; ++i) {
        x[i] = u;
        u >>= 8;
    }
}

void store32(uint8_t *x, uint32_t u)
{
    uint32_t i;

    for (i = 0; i < 4; ++i) {
        x[i] = u;
        u >>= 8;
    }
}


static const uint8_t rho[25] = {
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14
};


static const uint64_t iota[24] = 
{
    (uint64_t)0x0000000000000001ULL,
    (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL,
    (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL,
    (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL,
    (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL,
    (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL,
    (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL,
    (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL,
    (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL,
    (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008008ULL
};


void round800(uint32_t * A, uint32_t RC) {

    /*

    Round[b](A,RC) {
    # θ step
    C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
    D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
    A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)

    # ρ and π steps
    B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)

    # χ step
    A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)

    # ι step
    A[0,0] = A[0,0] xor RC

    return A
    }

    */

    uint32_t B[25], C[5], D[5];

    // theta step

    for (int x=0; x < 5; x++) {
        C[x] = A[x + 5*0] ^ A[x + 5*1] ^ A[x + 5*2] ^ A[x + 5*3] ^ A[x + 5*4];
    }
    for (int x=0; x < 5; x++) {
        D[x] = C[(x - 1) % 5] ^ ROTL32(C[(x + 1) % 5], 1);
    }
    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            A[x + 5 * y] ^= D[x];
        }
    }

    // rho and pi steps

    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            B[y  + ((2*x + 3*y) % 5) * 5] = ROTL32(A[x + 5*y], (rho[x + 5*y] % 32));
        }
    }

    // chi step

    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            A[x + y * 5] = B[x + y*5] ^ ((~B[((x+1) % 5) + y * 5]) & B[((x+2) % 5) + y * 5]);
        }
    }

    // iota step

    A[0] ^= RC;
}


void keccak_f800(uint32_t * A) {
    for (int i=0; i < 22; i++) {
        round800(A, (uint32_t) iota[i]);
        printf("A: %u\n", A[0]);
    }
}


void round1600(uint64_t * A, uint64_t RC) {

    /*

    Round[b](A,RC) {
    # θ step
    C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
    D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
    A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)

    # ρ and π steps
    B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)

    # χ step
    A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)

    # ι step
    A[0,0] = A[0,0] xor RC

    return A
    }

    */

    uint64_t B[25], C[5], D[5];

    // theta step

    for (int x=0; x < 5; x++) {
        C[x] = A[x + 5*0] ^ A[x + 5*1] ^ A[x + 5*2] ^ A[x + 5*3] ^ A[x + 5*4];
    }
    for (int x=0; x < 5; x++) {
        D[x] = C[(x - 1) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
    }
    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            A[x + 5 * y] ^= D[x];
        }
    }

    // rho and pi steps

    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            B[y  + ((2*x + 3*y) % 5) * 5] = ROTL64(A[x + 5*y], rho[x + 5*y]);
        }
    }

    // chi step

    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            A[x + y * 5] = B[x + y*5] ^ ((~B[((x+1) % 5) + y * 5]) & B[((x+2) % 5) + y * 5]);
        }
    }

    // iota step

    A[0] ^= RC;
}


void keccak_f1600(uint64_t * A) {
    for (int i=0; i < 24; i++) {
        round1600(A, iota[i]);
    }
}


void keccak800 (uint8_t * output, uint32_t outlen, const uint8_t * input, const uint32_t inlen) {
    uint32_t A[25] = {0};
    uint8_t buffer[36] = {0};
    uint32_t pos = 0;
    while (pos <= inlen) {
        if (pos + 36 <= inlen) {
            #pragma unroll
            for (int i=0; i < 9; i++) {
                A[i] ^= load32(input + pos + (4 * i));
            }
        }
        else {
            strncpy((char *)buffer, (char *)input + pos, inlen-pos);
            buffer[pos % 36] |= 0x01;
            buffer[35] |= 0x80;
            #pragma unroll
            for (int i=0; i < 9; i++) {
                A[i] ^= load32(buffer + 4 * i);
            }
        }
        keccak_f800(A);
        pos += 36;
    }
    pos = 0;
    while (pos <= outlen) {
        if (pos + 36 <= outlen) {
            for (int i=0; i < 9; i++) {
                store32(output + pos + 4*i, A[i]);
            }
        }
        else {
            for (int i=0; i < ((outlen % 36) + 3) / 4; i++) {
                store32(buffer + 4*i, A[i]);
            }
            strncpy((char *)output, (char *)buffer, outlen % 36);
        }
        pos += 36;
        if (pos < outlen)
            keccak_f800(A);
    };
}


void keccak1600 (uint8_t * output, uint64_t outlen, const uint8_t * input, const uint64_t inlen) {
    uint64_t A[25] = {0};
    uint64_t pos = 0;
    uint8_t buffer[200];
    while (inlen > pos) {
        if ((inlen - pos) < 200) {
            strncpy((char *)buffer, (char *)input + pos, inlen-pos);
            pos = inlen;
            memset(buffer + pos, 0, 200 - (pos % 200));
            buffer[pos % 200] = 1;
            buffer[199] = 0x80;
        }
        else {
            strncpy((char *)buffer, (char *)input + pos, 200);
        }
        pos += 200;
        for (int i=0; i < 25; i++) {
            A[i] = load64(buffer + 8*i);
        }
        keccak_f1600(A);
    }
    pos = 0;
    while (outlen > pos) {
        for (int i=0; i < ((int) MIN(outlen - pos, 136))/8; i++) {
            store64(output + pos + 8*i, A[i]);
        }
        pos += ((int) MIN(outlen - pos, 136))/8;
        if (pos < outlen)
            keccak_f1600(A);
    }
}

