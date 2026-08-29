#include <stdio.h>

void print_user_msg(const char *user_msg) {
    // CWE-134: Uncontrolled format string vulnerability
    printf(user_msg);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_user_msg("%s%s%s%s");
    } else {
        print_user_msg(argv[1]);
    }
    return 0;
}
