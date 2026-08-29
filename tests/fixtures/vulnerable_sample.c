#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_header(const char *input) {
    char buffer[64];
    printf("[+] Processing C header buffer...\n");
    // Unsafe string copy without bounds check (CWE-787 Stack Buffer Overflow)
    strcpy(buffer, input);
    printf("[+] Parsed header: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <header_input>\n", argv[0]);
        return 1;
    }
    parse_header(argv[1]);
    return 0;
}
