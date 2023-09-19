#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define rot64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static inline void mix(
    const uint64_t *data,
    uint64_t *s0, uint64_t *s1, uint64_t *s2,  uint64_t *s3,
    uint64_t *s4, uint64_t *s5, uint64_t *s6,  uint64_t *s7,
    uint64_t *s8, uint64_t *s9, uint64_t *s10, uint64_t *s11
) {
    *s0 += data[0];    *s2 ^= *s10;    *s11 ^= *s0;    *s0 = rot64(*s0, 11);    *s11 += *s1;
    *s1 += data[1];    *s3 ^= *s11;    *s0 ^= *s1;    *s1 = rot64(*s1, 32);    *s0 += *s2;
    *s2 += data[2];    *s4 ^= *s0;    *s1 ^= *s2;    *s2 = rot64(*s2, 43);    *s1 += *s3;
    *s3 += data[3];    *s5 ^= *s1;    *s2 ^= *s3;    *s3 = rot64(*s3, 31);    *s2 += *s4;
    *s4 += data[4];    *s6 ^= *s2;    *s3 ^= *s4;    *s4 = rot64(*s4, 17);    *s3 += *s5;
    *s5 += data[5];    *s7 ^= *s3;    *s4 ^= *s5;    *s5 = rot64(*s5, 28);    *s4 += *s6;
    *s6 += data[6];    *s8 ^= *s4;    *s5 ^= *s6;    *s6 = rot64(*s6, 39);    *s5 += *s7;
    *s7 += data[7];    *s9 ^= *s5;    *s6 ^= *s7;    *s7 = rot64(*s7, 57);    *s6 += *s8;
    *s8 += data[8];    *s10 ^= *s6;    *s7 ^= *s8;    *s8 = rot64(*s8, 55);    *s7 += *s9;
    *s9 += data[9];    *s11 ^= *s7;    *s8 ^= *s9;    *s9 = rot64(*s9, 54);    *s8 += *s10;
    *s10 += data[10];    *s0 ^= *s8;    *s9 ^= *s10;    *s10 = rot64(*s10, 22);    *s9 += *s11;
    *s11 += data[11];    *s1 ^= *s9;    *s10 ^= *s11;    *s11 = rot64(*s11, 46);    *s10 += *s0;
}

uint64_t custom_hash(const char *str) {
    uint64_t s0 = 0x0123456789ABCDEF;
    uint64_t s1 = 0xFEDCBA9876543210;
    uint64_t s2 = 0x02468ACE13579BDF;
    uint64_t s3 = 0xBDF13579ACE02468;
    uint64_t s4 = 0x13579BDF02468ACE;
    uint64_t s5 = 0x9BDF02468ACE1357;
    uint64_t s6 = 0x2468ACE13579BDF0;
    uint64_t s7 = 0x3579BDF02468ACE1;
    uint64_t s8 = 0xE13579BDF02468AC;
    uint64_t s9 = 0x68ACE13579BDF024;
    uint64_t s10 = 0x79BDF02468ACE135;
    uint64_t s11 = 0xACE13579BDF02468;

    uint64_t chunk;
    for (int j = 0; j < 8; j++) {
        chunk = (chunk << 8) | (str[j] & 0xFF);
        printf("chunk = %lx\n", chunk);
    }
    mix(&chunk, &s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, &s8, &s9, &s10, &s11);


    return s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 + s9 + s10 + s11;
}

int SECRET(const char *input, unsigned long input_2) {
    uint64_t hash = custom_hash(input);

    // Incorporate input_2 into the hash in a complex way
    uint64_t temp = (input_2 << 32) | (input_2 >> 32);  // Bitwise rotation
    hash ^= (temp & 0xFFFFFFFF) ^ (temp >> 32);

    // Modify the reference value based on input_2
    uint64_t reference_value = 0x123456789abcdef;
    reference_value ^= input_2;
    reference_value ^= (input_2 << 16) | (input_2 >> 48);  // More bitwise rotation

    printf("hash = %lx\n", hash);

    return hash == reference_value;
}


int main(int argc, char **argv){
   if (argc < 2) {
        printf("Call this program with 1 arguments\n");
        return 1;
    }

    char input_1[100];
    printf("Entrez la chaîne de caractères : ");
    scanf("%s", input_1);

    unsigned long input_2 = strtoul(argv[1], 0, 10);



    if (SECRET(input_1, input_2)) {
        printf("La vérification a réussi !\n");
    } else {
        printf("La vérification a échoué.\n");
    }

    return 0;
}
