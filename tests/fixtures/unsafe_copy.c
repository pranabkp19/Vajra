#include <stdio.h>
#include <stdlib.h>

void process_user_input(void) {
    char buf[64];
    printf("[+] Enter input: ");
    // CWE-120: Unsafe gets call without buffer bounds check
    gets(buf);
    printf("[+] Received: %s\n", buf);
}

int main(void) {
    process_user_input();
    return 0;
}
