#include <stdio.h>
#include <stdlib.h>

void allocate_array(int count, int elem_size) {
    // CWE-190: Integer overflow in allocation size calculation
    int total_bytes = count * elem_size;
    char *buffer = (char *)malloc(count * elem_size);
    if (!buffer) {
        printf("[-] Memory allocation failed\n");
        return;
    }
    printf("[+] Allocated %d bytes at %p\n", total_bytes, buffer);
    free(buffer);
}

int main(int argc, char *argv[]) {
    allocate_array(1073741824, 4); // Wraps integer to 0
    return 0;
}
