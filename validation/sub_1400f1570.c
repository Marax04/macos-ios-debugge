// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F37A0();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F2808();
extern __int64 off_1401101D0;
extern __int64 off_140110210;

__int64 __fastcall sub_1400F1570(int *a1, __int64 a2, size_t a3) {
    __int64 rsp;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 i;
    __int64 v5;
    __int64 v4;
    __int64 v8;
    __m128i xmm0;
    __int64 v7;
    __int64 v2;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    if (a3 >= 15) {
        result = a3;
        result >>= 61;
        if (!((result != 0))) {
            a3 <<= 3;
            a1 = 0x2492492492492493;
            result = a3;
            result *= (__int64)a1; /* unsigned; high half in a2 */;
            a3 -= a2;
            a3 >>= 1;
            a3 += a2;
            a3 >>= 2;
            --a3;
            a1 = 63 - __builtin_clzll(a3);
            a1 = (int *)(~(__int64)a1);
            i = -1;
            i >>= (__int64)a1;
            ++i;
            result = v5;
            v5 *= i; /* unsigned; high half in a2 */;
            if (!((0 /* overflow check on (i + 1) */))) {
                if (result <= -16) {
                    result += 15;
                    result &= -16;
                    v4 = i + 16;
                    v8 = v4;
                    v8 += result;
                    a1 = (v8 < 0) ? 1 : 0;
                    a2 = 0x7FFFFFFFFFFFFFF0;
                    a2 = (v8 > a2) ? 1 : 0;
                    a2 |= (__int64)a1;
                    if (!((a2 == 0))) {
                        result = &off_1401101D0;
                        v_28 = result;
                        v_30 = 1;
                        v_38 = 8;
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)&v_40, xmm0);
                        a2 = &off_140110210;
                        a1 = rsp + 40;
                        sub_1400F37A0(a1, a2, a3, a2);
                    }
                    if (v8 != 0) {
                        v7 = result;
                        sub_14002EDF0(0, v8);
                        v2 = result;
                        result = v7;
                        if (v2 == 0) {
                            sub_1400F3340(16, v8);
                            v2 = 16;
                        }
                        v2 += result;
                        v6 = i - 1;
                        result = i;
                        result >>= 3;
                        i &= -8;
                        i -= result;
                        if (v6 < 8) i = v6;
                        sub_1400F2808(v2, 255, v4);
                        *(__int64 *)ptr = (__int64)(v2);
                        ptr->field_8 = v6;
                        ptr->field_10 = i;
                        ptr->field_18 = 0;
                        return i;
                    }
                    return i;
                }
            }
        }
    } else {
        result = a3;
        result &= 8;
        result += 8;
        i = 4;
        if (a3 >= 4) i = result;
        return i;
    }
    return result;
}