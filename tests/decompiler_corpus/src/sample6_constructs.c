#include <stdint.h>
#include <stddef.h>

/* Broad construct coverage for detection testing:
 *  - switch over dense cases  -> jump-table recovery
 *  - recursion                -> self-call detection
 *  - function pointers        -> indirect-call typing
 *  - do/while + nested loops  -> loop structuring
 *  - bitwise flag masks       -> flag-condition readability
 *  - float arithmetic         -> XMM / SSE lifting
 */

int32_t classify(int32_t op, int32_t a, int32_t b) {
    switch (op) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return b ? a / b : 0;
        case 4: return a & b;
        case 5: return a | b;
        case 6: return a ^ b;
        case 7: return a << (b & 31);
        default: return -1;
    }
}

uint64_t factorial(uint32_t n) {
    if (n <= 1) return 1;
    return (uint64_t)n * factorial(n - 1);
}

typedef int32_t (*binop)(int32_t, int32_t);
static int32_t add_fn(int32_t x, int32_t y) { return x + y; }
static int32_t mul_fn(int32_t x, int32_t y) { return x * y; }

int32_t apply(int use_mul, int32_t x, int32_t y) {
    binop f = use_mul ? mul_fn : add_fn;
    return f(x, y);
}

#define FLAG_A 0x01u
#define FLAG_B 0x02u
#define FLAG_C 0x04u

uint32_t count_set_flags(const uint32_t *flags, size_t n) {
    uint32_t total = 0;
    size_t i = 0;
    do {
        uint32_t v = flags[i];
        if (v & FLAG_A) total++;
        if (v & FLAG_B) total++;
        if (v & FLAG_C) total++;
        i++;
    } while (i < n);
    return total;
}

double dot(const double *u, const double *v, size_t n) {
    double acc = 0.0;
    for (size_t i = 0; i < n; i++) {
        acc += u[i] * v[i];
    }
    return acc;
}

int main(void) {
    int32_t c = classify(2, 6, 7);
    uint64_t f = factorial(5);
    int32_t ap = apply(1, 3, 4);
    uint32_t fl[2] = {FLAG_A | FLAG_C, FLAG_B};
    uint32_t cnt = count_set_flags(fl, 2);
    double u[3] = {1.0, 2.0, 3.0}, w[3] = {4.0, 5.0, 6.0};
    double d = dot(u, w, 3);
    return (int)(c + (int)f + ap + (int)cnt + (int)d);
}
