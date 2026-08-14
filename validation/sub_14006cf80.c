// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_14006CF80(struct Struct_1_t *a1, int a2) {
    __int64 __rdx_rax;
    __int64 v5;
    __int64 v8;
    __int64 result;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v10;
    __int64 v6;
    __int64 v9;

    if (a2 == 0) {
        a2 = 0;
    } else {
        v5 = a2;
        v8 = a1->field_8;
        result = v8 + v8*4;
        result = __ROL8__(result, 7);
        v3 = a1->field_0;
        result += result*8;
        a2 = v8;
        a2 <<= 17;
        v4 = ((__int64 *)a1)[2];
        v4 ^= v3;
        v2 = v4;
        v2 ^= v8;
        v8 ^= *((__int64 *)a1 + 3);
        a1->field_8 = v2;
        v3 ^= v8;
        *(__int64 *)a1 = (__int64)(v3);
        v4 ^= a2;
        v8 = __ROL8__(v8, 45);
        ((__int64 *)a1)[2] = (__int64)(v4);
        result *= v5; /* unsigned; high half in a2 */;
        ((__int64 *)a1)[3] = (__int64)(v8);
        if (v5 > result) {
            v7 = result;
            v10 = a2;
            result = v5;
            result = -result;
            a2 = result;
            a2 |= v5;
            a2 >>= 32;
            if ((a2 == 0)) {
                a2 = 0;
                result = __rdx_rax / v5; a2 = __rdx_rax % v5; /* unsigned */;
                v6 = a2;
                a2 = v10;
                if (v6 > v7) {
                    do {
                        result = v2 + v2*4;
                        result = __ROL8__(result, 7);
                        result += result*8;
                        v9 = v2;
                        v9 <<= 17;
                        v4 ^= v3;
                        v8 ^= v2;
                        v3 ^= v8;
                        v8 = __ROL8__(v8, 45);
                        v2 ^= v4;
                        result *= v5; /* unsigned; high half in a2 */;
                        v4 ^= v9;
                    } while (v6 > result);
                    ((__int64 *)a1)[2] = (__int64)(v4);
                    ((__int64 *)a1)[3] = (__int64)(v8);
                    a1->field_8 = v2;
                    *(__int64 *)a1 = (__int64)(v3);
                }
            } else {
                a2 = 0;
                result = __rdx_rax / v5; a2 = __rdx_rax % v5; /* unsigned */;
                v6 = a2;
                a2 = v10;
                if (v6 > v7) {
                    return a2;
                } else {
                }
            }
        }
    }
    result = a2;
    return result;
}