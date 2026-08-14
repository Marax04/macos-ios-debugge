__int64 sub_14001C340();

__int64 __fastcall sub_14001C250(int *a1, __int64 a2, size_t *a3, int a4) {
    __int64 result;
    __int64 v4;
    __m128i xmm1;
    __m128i xmm0;
    __int64 v5;
    __int64 v6;
    __int64 v3;

    if (v3 < a3) {
        result = (__int64)a3;
        result -= v3;
        if (result >= 32) {
            sub_14001C340(a1, v3, a1, a4);
            v4 = v3;
            return v4;
        } else {
            if (result > 15) {
                xmm1 = _mm_loadu_si128((__m128i *)(a3 - 16));
                xmm0 = _mm_load_si128((__m128i *)(a1 + 64));
                xmm1 = _mm_cmpeq_epi8(xmm1, xmm0);
                result = _mm_movemask_epi8(xmm1);
                if (result == 0) {
                    a3 = (size_t *)((__int64)(__int64)a3 & -16);
                    result = v3 + 16;
                    while (a3 >= result) {
                        xmm1 = _mm_loadu_si128((__m128i *)(a3 - 16));
                        a3 -= 16;
                        xmm1 = _mm_cmpeq_epi8(xmm1, xmm0);
                        a1 = _mm_movemask_epi8(xmm1);
                        result = (__int64)a1;
                        a1 = 31 - __builtin_clz(result);
                        a1 = (int *)((__int64)a1 + (__int64)a3);
                        result = 1;
                        v5 = (__int64)a1;
                        return v5;
                    }
                    if (a3 <= v3) {
                        result = 0;
                        a2 = (__int64)a1;
                        return a2;
                    } else {
                        xmm1 = _mm_loadu_si128((__m128i *)v3);
                        xmm0 = _mm_cmpeq_epi8(xmm0, xmm1);
                        a1 = _mm_movemask_epi8(xmm0);
                        result = 0;
                        result = (a1 != 0) ? 1 : 0;
                        a1 = 31 - __builtin_clz(a1);
                        a1 += v3;
                        v6 = (__int64)a1;
                        return v6;
                    }
                } else {
                    a3 -= 16;
                }
                return (__int64)a3;
            } else {
                a4 = a1[10];
                result = 0;
                while (a3 > v3) {
                    a1 = a3 - 1;
                    return (__int64)a1;
                }
                return (__int64)a1;
            }
            return (__int64)a1;
        }
    }
    return result;
}