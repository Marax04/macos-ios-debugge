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
extern __int64 off_14011D5E0;
extern __int64 off_14011D5D0;
extern __int64 off_1401101D0;
extern __int64 off_140110210;

__int64 __fastcall sub_14007BF40(int *a1, __int64 a2, size_t a3, __int64 a4) {
    __int64 rsp;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __int64 result;
    __int64 i;
    __int64 v4;
    __int64 v7;
    __int64 v6;
    __int64 v2;
    __int64 v5;

    ptr = (struct Struct_1_t *)a1;
    if (a3 == 0) {
        xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
        _mm_storeu_si128((__m128i *)(ptr + 16), xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
        _mm_storeu_si128((__m128i *)ptr, xmm0);
    } else {
        if (a3 >= 15) {
            result = a3;
            result >>= 61;
            if (!((result != 0))) {
                a3 <<= 3;
                result = a3;
                a1 = (int *)a2;
                result *= a4; /* unsigned; high half in a2 */;
                result = a2;
                a2 = (__int64)a1;
                a3 -= result;
                a3 >>= 1;
                a3 += result;
                a3 >>= 2;
                --a3;
                a1 = 63 - __builtin_clzll(a3);
                a1 = (int *)(~(__int64)a1);
                i = -1;
                i >>= (__int64)a1;
                ++i;
                result = a2;
                a2 *= i; /* unsigned; high half in a2 */;
                if (!((0 /* overflow check on (i + 1) */))) {
                    if (result <= -16) {
                        result += 15;
                        result &= -16;
                        v4 = i + 16;
                        v7 = v4;
                        v7 += result;
                        a1 = (v7 < 0) ? 1 : 0;
                        a2 = 0x7FFFFFFFFFFFFFF0;
                        a2 = (v7 > a2) ? 1 : 0;
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
                            sub_1400F37A0(a1, a2, a3, 0x2492492492492493);
                        }
                        if (v7 != 0) {
                            v6 = result;
                            sub_14002EDF0(0, v7);
                            v2 = result;
                            result = v6;
                            if (v2 == 0) {
                                sub_1400F3340(16, v7);
                                v2 = 16;
                            }
                            v2 += result;
                            v5 = i - 1;
                            result = i;
                            result >>= 3;
                            i &= -8;
                            i -= result;
                            if (v5 < 8) i = v5;
                            sub_1400F2808(v2, 255, v4);
                            *(__int64 *)ptr = (__int64)(v2);
                            ptr->field_8 = v5;
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
        return i;
    }
    return result;
}