#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>

/* Broad C feature coverage for decompiler RE testing:
 *  - union + type-punning, bitfields
 *  - varargs (va_list)
 *  - function-pointer dispatch table
 *  - enum, goto, nested loops, string ops (memcpy/strlen-like)
 */

enum Tag { TAG_INT, TAG_FLT, TAG_PTR };

union Value {
    int64_t i;
    double  f;
    void   *p;
};

struct Packed {
    uint32_t flag_a : 1;
    uint32_t flag_b : 1;
    uint32_t width  : 6;
    uint32_t height : 8;
    uint32_t rest   : 16;
};

int64_t sum_varargs(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int64_t acc = 0;
    for (int i = 0; i < count; i++) {
        acc += va_arg(ap, int64_t);
    }
    va_end(ap);
    return acc;
}

static int64_t op_add(int64_t a, int64_t b) { return a + b; }
static int64_t op_sub(int64_t a, int64_t b) { return a - b; }
static int64_t op_mul(int64_t a, int64_t b) { return a * b; }
static int64_t op_xor(int64_t a, int64_t b) { return a ^ b; }

typedef int64_t (*binop)(int64_t, int64_t);

int64_t dispatch(int idx, int64_t a, int64_t b) {
    static const binop table[4] = { op_add, op_sub, op_mul, op_xor };
    if (idx < 0 || idx >= 4) return 0;
    return table[idx](a, b);           /* indirect call through table */
}

int64_t punned_bits(double d) {
    union Value v;
    v.f = d;                            /* type-pun double → bits */
    return v.i;
}

uint32_t pack_fields(int a, int b, int w, int h) {
    struct Packed p;
    p.flag_a = a & 1;
    p.flag_b = b & 1;
    p.width  = (uint32_t)w & 0x3F;
    p.height = (uint32_t)h & 0xFF;
    p.rest   = 0;
    uint32_t out;
    memcpy(&out, &p, sizeof(out));      /* read the packed bits back */
    return out;
}

size_t my_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;                     /* pointer-walk loop */
    return (size_t)(p - s);
}

int64_t matrix_trace(const int64_t *m, int n) {
    int64_t tr = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {   /* nested loops */
            if (i == j) {
                tr += m[i * n + j];
                goto next_row;          /* goto */
            }
        }
    next_row:;
    }
    return tr;
}

int main(void) {
    int64_t s = sum_varargs(3, (int64_t)10, (int64_t)20, (int64_t)30);
    int64_t d = dispatch(2, 6, 7) + dispatch(3, 12, 10);
    int64_t b = punned_bits(3.14);
    uint32_t f = pack_fields(1, 0, 40, 30);
    size_t l = my_strlen("hello, world");
    int64_t mat[9] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int64_t tr = matrix_trace(mat, 3);
    return (int)(s + d + (b & 0xFF) + f + (int64_t)l + tr);
}
