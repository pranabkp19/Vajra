#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr = (char *)malloc(64);
    if (!ptr) return 1;
    strcpy(ptr, "VAJRA Use After Free Test");
    printf("[+] Allocated data: %s\n", ptr);
    
    // Free the pointer
    free(ptr);
    
    // CWE-416: Use After Free - Dereferencing freed pointer
    printf("[!] Use after free access: %s\n", ptr);
    return 0;
}
