/*
 * VAJRA Target Benchmark: Stack Buffer Overflow & Format String Vulnerability
 * File: CWE787_Buffer_Overflow_Demo.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_process_user_input(const char *user_input) {
    char stack_buffer[64];
    
    // CWE-787 / CWE-120: Unbounded string copy into 64-byte stack buffer
    printf("[!] Copying user input into stack buffer...\n");
    strcpy(stack_buffer, user_input);
    
    // CWE-134: Non-literal format string vulnerability
    printf("[!] Echoing user buffer: ");
    printf(stack_buffer);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    
    vulnerable_process_user_input(argv[1]);
    return 0;
}
