#include <stdint.h>

const int n = 2;

int a() {
    uint64_t rd;
    asm volatile (
        "li %0, 4194304\n"
        "ld	%0, 8(%0)\n"
        : "=r"(rd)
    );

    return n;
}

int b() {
    return a() + n;
}

int c() {
    return b() + a();
}

int main() {
    return c() + b() - 10;
}
