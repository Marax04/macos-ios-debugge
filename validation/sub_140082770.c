// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_140082770(struct Struct_1_t *a1, size_t a2, int a3, int *a4) {
    __int64 result;
    __int64 v6;
    __int64 v5;
    __int64 *src;
    __int64 v4;
    int v2;

    result = a1->field_8;
    v6 = ((__int64 *)a1)[2];
    v5 = 1;
    a3 = 2;
    if (v6 < result) {
        src = a1->field_0;
        a4 = *(src + v6);
        a2 = v6 + 1;
        ((__int64 *)a1)[2] = (__int64)(a2);
        if (a2 < result) {
            a2 = *(src + v6 + 1);
            v4 = v6 + 2;
            ((__int64 *)a1)[2] = (__int64)(v4);
            if (v4 < result) {
                result = *(src + v6 + 2);
                v6 += 3;
                ((__int64 *)a1)[2] = (__int64)(v6);
                a3 = 5;
                if ((a2 & 4) != 0) {
                    v2 = a2;
                    v2 >>= 3;
                    a3 = v2;
                    a3 = ~a3;
                    a3 &= 15;
                    a1 = (struct Struct_1_t *)a4;
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 3);
                    a2 &= 3;
                    v5 = result;
                    v5 >>= 5;
                    v5 &= 3;
                    v6 = result;
                    v6 &= 7;
                    src = (__int64 *)a4;
                    src = (__int64 *)(~(__int64)src);
                    src = (__int64 *)((__int64)(__int64)src >> 7);
                    v4 = (__int64)a4;
                    v4 >>= 5;
                    v4 &= 2;
                    v4 |= (__int64)src;
                    src = (__int64 *)a4;
                    src = (__int64 *)((__int64)(__int64)src >> 3);
                    src = (__int64 *)((__int64)(__int64)src & 4);
                    src = (__int64 *)((__int64)(__int64)src | v4);
                    a4 = (int *)((__int64)(__int64)a4 >> 1);
                    a4 = (int *)((__int64)(__int64)a4 & 8);
                    a4 = (int *)((__int64)(__int64)a4 | (__int64)src);
                    v2 &= 16;
                    v2 |= (__int64)a4;
                    a4 =  + result*4;
                    a4 = (int *)((__int64)(__int64)a4 & 32);
                    a4 = (int *)((__int64)(__int64)a4 | v2);
                    v2 = result;
                    v2 >>= 1;
                    v2 &= 64;
                    v2 |= (__int64)a4;
                    result <<= 3;
                    result &= 128;
                    result |= v2;
                    result ^= 46;
                    a4 = (int *)v6;
                    a4 = (int *)((__int64)(__int64)a4 << 40);
                    v5 <<= 32;
                    v5 |= (__int64)a4;
                    a2 <<= 24;
                    a2 |= v5;
                    a3 <<= 16;
                    a3 |= a2;
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 8);
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 | a3);
                    a3 = result;
                    a3 |= (__int64)a1;
                    v5 = 0;
                }
            }
        }
    }
    a3 <<= 8;
    result = v5;
    result |= a3;
    return result;
}