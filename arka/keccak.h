
#include "stdio.h"
#include "stdint.h"
#include "string.h"

#define ROTL64(X, N) ((X << N) | (X >> ((64-N) & 63)))
#define ROTL32(X, N) ((X << N) | (X >> ((32-N) & 31)))
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


static const uint8_t rho_1600[25] = {
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14
};


static const uint8_t rho_800[25] = {
    0, 1, 30, 28, 27,
    4, 12, 6, 23, 20,
    3, 10, 11, 25, 7,
    9, 13, 15, 21, 8,
    18, 2, 29, 24, 14
};


static const uint64_t iota_1600[24] = 
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


static const uint32_t iota_800[22] = 
{
    (uint32_t)0x00000001UL,
    (uint32_t)0x00008082UL,
    (uint32_t)0x0000808aUL,
    (uint32_t)0x80008000UL,
    (uint32_t)0x0000808bUL,
    (uint32_t)0x80000001UL,
    (uint32_t)0x80008081UL,
    (uint32_t)0x00008009UL,
    (uint32_t)0x0000008aUL,
    (uint32_t)0x00000088UL,
    (uint32_t)0x80008009UL,
    (uint32_t)0x8000000aUL,
    (uint32_t)0x8000808bUL,
    (uint32_t)0x0000008bUL,
    (uint32_t)0x00008089UL,
    (uint32_t)0x00008003UL,
    (uint32_t)0x00008002UL,
    (uint32_t)0x00000080UL,
    (uint32_t)0x0000800aUL,
    (uint32_t)0x8000000aUL,
    (uint32_t)0x80008081UL,
    (uint32_t)0x00008080UL,
};


void round800(uint32_t * A, uint32_t RC) {

    uint32_t B[25], C[5], D[5];

    // theta step

    for (int x=0; x < 5; x++) {
        C[x] = A[x + 5*0] ^ A[x + 5*1] ^ A[x + 5*2] ^ A[x + 5*3] ^ A[x + 5*4];
    }
    for (int x=0; x < 5; x++) {
        D[x] = C[(x == 0) ? 4 : (x - 1)] ^ ROTL32(C[(x + 1) % 5], 1);
    }
    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            A[x + 5 * y] ^= D[x];
        }
    }

    // rho and pi steps

    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            B[y  + ((2*x + 3*y) % 5) * 5] = ROTL32(A[x + 5*y], rho_800[x + 5*y]);
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
        round800(A, iota_800[i]);
    }
}


void round1600(uint64_t * A, uint64_t RC) {

    uint64_t B[25], C[5], D[5];

    // theta step

    for (int x=0; x < 5; x++) {
        C[x] = A[x + 5*0] ^ A[x + 5*1] ^ A[x + 5*2] ^ A[x + 5*3] ^ A[x + 5*4];
    }
    for (int x=0; x < 5; x++) {
        D[x] = C[(x == 0) ? 4 : (x - 1)] ^ ROTL64(C[(x + 1) % 5], 1);
    }
    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            A[x + 5 * y] ^= D[x];
        }
    }

    // rho and pi steps

    for (int y=0; y < 5; y++) {
        for (int x=0; x < 5; x++) {
            B[y  + ((2*x + 3*y) % 5) * 5] = ROTL64(A[x + 5*y], rho_1600[x + 5*y]);
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
        round1600(A, iota_1600[i]);
    }
}


void keccak800 (uint8_t * output, uint64_t outlen, const uint8_t * input, const uint64_t inlen) {
    uint32_t A[25] = {0};
    uint8_t buffer[36] = {0};
    uint64_t pos = 0;
    while (pos <= inlen) {
        if (pos + 36 <= inlen) {
            #pragma unroll
            for (int i=0; i < 9; i++) {
                A[i] ^= load32(input + pos + (4 * i));
            }
        }
        else {
            memcpy((char *)buffer, (char *)input + pos, inlen-pos);
            buffer[inlen % 36] |= 0x01;
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
    while (pos + 36 <= outlen) {
        for (int i=0; i < 9; i++) {
            store32(output + pos + 4*i, A[i]);
        }
        pos += 36;
        if (pos < outlen) {
            keccak_f800(A);
        }
    }
    if (pos < outlen) {
        for (int i=0; i < 9; i++) {
            store32(buffer + 4*i, A[i]);
        }
        memcpy((char *)output + pos, (char *)buffer, outlen % 36);
    }
}


void keccak1600 (uint8_t * output, uint64_t outlen, const uint8_t * input, const uint64_t inlen) {
    uint64_t A[25] = {0};
    uint8_t buffer[136] = {0};
    uint64_t pos = 0;
    while (pos <= inlen) {
        if (pos + 136 <= inlen) {
            #pragma unroll
            for (int i=0; i < 17; i++) {
                A[i] ^= load64(input + pos + (8 * i));
            }
        }
        else {
            memcpy((char *)buffer, (char *)input + pos, inlen-pos);
            buffer[inlen % 136] |= 0x01;
            buffer[135] |= 0x80;
            #pragma unroll
            for (int i=0; i < 17; i++) {
                A[i] ^= load64(buffer + 8 * i);
            }
        }
        keccak_f1600(A);
        pos += 136;
    }
    pos = 0;
    while (pos + 136 <= outlen) {
        for (int i=0; i < 17; i++) {
            store64(output + pos + 8*i, A[i]);
        }
        pos += 136;
        keccak_f1600(A);
    }
    if (pos < outlen) {
        for (int i=0; i < ((outlen % 136) + 7) / 8; i++) {
            store64(buffer + 8*i, A[i]);
        }
        memcpy(output + pos, buffer, outlen % 136);
    }
}


// void mint_midstate (uint32_t * midstate, const uint8_t * key, const uint8_t * diff, const uint8_t * nonce) {
//     uint32_t A[25] = {0};
//     uint8_t buffer[36] = {0};
//     #pragma unroll
//     for (int i=0; i < 8; i++) {
//         A[i] ^= load32(key + (4 * i));
//     }
//     memcpy(buffer, diff, 2);
//     memcpy(buffer + 2, nonce, 2);
//     A[9] ^= load32(buffer);
//     keccak_f800(A);
//     memcpy(buffer, nonce + 2, 30);
//     buffer[30] ^= 1;
//     buffer[35] ^= 0x80;
//     #pragma unroll
//     for (int i=0; i < 9; i++) {
//         A[i] ^= load32(buffer + (4 * i));
//     }
//     memcpy(midstate, A, 4*25);
// }


// int mint_iterate(uint64_t * offset, const uint32_t * midstate, const uint8_t *diff, uint64_t limit) {

//     uint32_t A[25];
//     uint8_t buffer[32];
//     uint8_t exp, j;

//     for (uint64_t i=0; i < limit; i++) {
//         memcpy(A, midstate, 4*25);
//         A[0] ^= i & 0xffffffff;
//         A[1] ^= (i >> 32) & 0xffffffff;
//         keccak_f800(A);
//         if ((A[0] & 0xff) >= diff[0]) {
//             for (j=0; j<8; j++)
//                 store32(buffer + 4*j, A[j]);
//             exp = diff[1];
//             j = 1;
//             while (exp >= 8 && !buffer[j]){
//                 j += 1;
//                 exp -= 8;
//             }
//             if (exp < 8) {
//                 if (buffer[j] & ((1 << exp) - 1) == 0) {
//                     *offset = i;
//                     return 1;
//                 }
//             }
//         }
//     }
//     *offset = limit;
//     return 0;
// }
