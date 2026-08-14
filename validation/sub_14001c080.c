__int64 sub_14001C21A();
__int64 sub_14001C221();

__int64 __fastcall sub_14001C080(size_t a1, __int64 a2, size_t *a3) {
    __int64 rsp;
    __int64 v5;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;
    int v6;
    __m128i xmm2;
    __m128i xmm3;
    __m128i xmm4;
    __m128i xmm5;
    __m128i xmm6;
    __int64 v2;
    __int64 v4;
    __int64 v3;

    _mm_store_si128((__m128i *)&*(__int64 *)rsp, xmm6);
    if (v3 < a3) {
        v5 = (__int64)a3;
        v5 -= v3;
        if (v5 > 15) {
            result = a1;
            xmm0 = _mm_cvtsi32_si128(result);
            xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
            xmm0 = _mm_shufflelo_epi16(xmm0, 0);
            xmm0 = _mm_shuffle_epi32(xmm0, 68);
            xmm1 = _mm_loadu_si128((__m128i *)(a3 - 16));
            xmm1 = _mm_cmpeq_epi8(xmm1, xmm0);
            result = _mm_movemask_epi8(xmm1);
            if (result == 0) {
                result = (__int64)a3;
                result &= -16;
                v5 = (v5 >= 64) ? 1 : 0;
                a1 = v3 + 64;
                v6 = (result >= a1) ? 1 : 0;
                v6 &= v5;
                if (v6 == 1) {
                    result = (__int64)a3;
                    result &= 15;
                    a3 -= result;
                    a3 -= 64;
                    do {
                        xmm1 = _mm_load_si128((__m128i *)a3);
                        xmm1 = _mm_cmpeq_epi8(xmm1, xmm0);
                        xmm2 = _mm_load_si128((__m128i *)(a3 + 16));
                        xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                        xmm3 = _mm_load_si128((__m128i *)(a3 + 32));
                        xmm3 = _mm_cmpeq_epi8(xmm3, xmm0);
                        xmm4 = _mm_load_si128((__m128i *)(a3 + 48));
                        xmm4 = _mm_cmpeq_epi8(xmm4, xmm0);
                        xmm5 = xmm1;
                        xmm5 = _mm_or_si128(xmm5, xmm2);
                        xmm6 = xmm3;
                        xmm6 = _mm_or_si128(xmm6, xmm4);
                        xmm6 = _mm_or_si128(xmm6, xmm5);
                        result = _mm_movemask_epi8(xmm6);
                        if (result != 0) JUMPOUT(0x14001c1eb);
                        result = a3 - 64;
                        a3 = (size_t *)result;
                    } while ((a3 >= a1));
                    result += 64;
                }
                v2 = v3 + 16;
                while (result >= v2) {
                    xmm1 = _mm_loadu_si128((__m128i *)(result - 16));
                    result -= 16;
                    xmm1 = _mm_cmpeq_epi8(xmm1, xmm0);
                    a3 = _mm_movemask_epi8(xmm1);
                    a1 = (size_t)a3;
                    return sub_14001C21A();
                }
                if (result <= v3) {
                    result = 0;
                } else {
                    xmm1 = _mm_loadu_si128((__m128i *)v3);
                    xmm0 = _mm_cmpeq_epi8(xmm0, xmm1);
                    a1 = _mm_movemask_epi8(xmm0);
                    result = 0;
                    result = (a1 != 0) ? 1 : 0;
                    v5 = 31 - __builtin_clz(a1);
                    v5 += v3;
                    v4 = v5;
                    xmm6 = _mm_load_si128((__m128i *)&*(__int64 *)rsp);
                    return _mm_cvtsi128_si64(xmm6);
                }
            } else {
                a3 -= 16;
                v5 = 31 - __builtin_clz(result);
                v5 += (__int64)a3;
                return sub_14001C221();
            }
        } else {
            result = 0;
            while (a3 > v3) {
                v5 = a3 - 1;
                a3 = (size_t *)v5;
                return sub_14001C221();
            }
        }
        a2 = v5;
        xmm6 = _mm_load_si128((__m128i *)&*(__int64 *)rsp);
        return _mm_cvtsi128_si64(xmm6);
    }
    return result;
}