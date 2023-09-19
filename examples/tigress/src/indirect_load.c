#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Example of indirect load
// If you encounter this, i suggest to implement the addrof primitive
// That will take data from the address evaluated by the expression

int indirect_array[10] = {5, 4, 3, 5, 4, 1, 2, 4, 5, 3};

uint64_t SECRET(unsigned long input) {
    int a = indirect_array[input];
    int b = a + 4;
    return indirect_array[b];
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Call this program with 1 argument\n");
        return 1;
    }

    unsigned long input = strtoul(argv[1], 0, 10);
    uint64_t output = SECRET(input);

    printf("%llu\n", output);

    return 0;
}
