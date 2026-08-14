__int64 sub_1400F37D0();
__int64 sub_1400F2808();
__int64 sub_1400F3869();
__int64 sub_140013E77();
extern __int64 off_14010B4F0;
extern __int64 off_14010B4D8;
extern __int64 off_14010EE10;

__int64 __fastcall sub_140013B30(size_t *a1, size_t *a2) {
    __int64 v5;
    __int64 *dst;
    __int64 v2;
    __int64 *result;
    __int64 i;
    __int64 v4;
    __int64 v9;
    __int64 v7;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v8;
    __int64 v10;
    __int64 v11;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm4;
    __m128i xmm5;

    if (a2 >= 0x500) {
        a1 = &off_14010B4F0;
        v5 = &off_14010B4D8;
        sub_1400F37D0(a1, 29, v5, i);
    } else {
        dst = (__int64 *)a1;
        v2 = (__int64)a2;
        v2 >>= 5;
        v5 = a1[20];
        if (v5 != 0) {
            a1 = (size_t *)v5;
            --a1;
            while (v5 < 41) {
                result = a1 + v2;
                if (result < 40) {
                    i = *(dst + (__int64)(__int64)a1*4);
                    *(dst + (__int64)(__int64)result*4) = i;
                    v4 = (__int64)a2;
                    v4 &= 31;
                    if (a2 >= 32) {
                        v5 =  + v2*4;
                        sub_1400F2808(dst, 0, v5, i);
                    }
                    i = *(dst + 160);
                    result = i + v2;
                    if (v4 == 0) {
                        v5 = (__int64)result;
                    } else {
                        a1 = result - 1;
                        if (a1 > 39) {
                            v5 = &off_14010B4D8;
                            sub_1400F3869(a1, 40, v5);
                        } else {
                            a2 = *(dst + (__int64)(__int64)result*4 - 4);
                            a1 = (size_t *)v4;
                            a1 = (size_t *)(-(__int64)a1);
                            a2 = (size_t *)((__int64)(__int64)a2 >> (__int64)a1);
                            v5 = (__int64)result;
                            if (a2 != 0) {
                                if (result > 39) {
                                    v5 = &off_14010B4D8;
                                    sub_1400F3869(result, 40, v5);
                                    v4 = (__int64)a2;
                                    dst = result;
                                    if (a2 >= 8) JUMPOUT(0x140013d9a);
                                    a2 = *(dst + 160);
                                    if (a2 >= 41) JUMPOUT(0x14001417a);
                                    if (a2 == 0) JUMPOUT(0x140013e00);
                                    result = &off_14010EE10;
                                    result = *(result + v4*4);
                                    v5 =  + (__int64)(__int64)a2*4;
                                    v5 -= 4;
                                    i = v5;
                                    i >>= 2;
                                    ++i;
                                    a1 = (size_t *)i;
                                    a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                    if (v5 >= 12) JUMPOUT(0x140013e0e);
                                    v5 = 0;
                                    v9 = (__int64)dst;
                                    return sub_140013E77();
                                } else {
                                    *(dst + (__int64)(__int64)result*4) = a2;
                                    v5 = result + 1;
                                }
                            }
                            v7 = v2 + 1;
                            if (v7 < result) {
                                a2 = 32;
                                a2 -= v4;
                                --i;
                                if (i >= 8) {
                                    a1 = (size_t *)i;
                                    a1 = (size_t *)((__int64)(__int64)a1 & -8);
                                    xmm2 = _mm_cvtsi32_si128(v4);
                                    xmm3 = _mm_cvtsi32_si128(a2);
                                    v8 = dst + (__int64)(__int64)result*4;
                                    v8 -= 16;
                                    result = (__int64 *)((__int64)result - (__int64)a1);
                                    v10 = (__int64)a1;
                                    v10 = -v10;
                                    v11 = 0;
                                    xmm0 = _mm_setzero_si128();
                                    xmm1 = _mm_setzero_si128();
                                    xmm1 = xmm3;
                                    xmm0 = xmm2;
                                    do {
                                        xmm2 = _mm_loadu_si128((__m128i *)(v8 + v11*4 - 20));
                                        xmm3 = _mm_loadu_si128((__m128i *)(v8 + v11*4 - 16));
                                        xmm4 = _mm_loadu_si128((__m128i *)(v8 + v11*4 - 4));
                                        xmm5 = _mm_loadu_si128((__m128i *)(v8 + v11*4));
                                        xmm4 = _mm_srl_epi32(xmm4, xmm1);
                                        xmm5 = _mm_sll_epi32(xmm5, xmm0);
                                        xmm5 = _mm_or_si128(xmm5, xmm4);
                                        _mm_storeu_si128((__m128i *)(v8 + v11*4), xmm5);
                                        xmm2 = _mm_srl_epi32(xmm2, xmm1);
                                        xmm3 = _mm_sll_epi32(xmm3, xmm0);
                                        xmm3 = _mm_or_si128(xmm3, xmm2);
                                        _mm_storeu_si128((__m128i *)(v8 + v11*4 - 16), xmm3);
                                        v11 -= 8;
                                    } while (v10 != v11);
                                    if (i != a1) {
                                        do {
                                            i = *(dst + (__int64)(__int64)result*4 - 8);
                                            v8 = *(dst + (__int64)(__int64)result*4 - 4);
                                            a1 = (size_t *)v4;
                                            v8 <<= (__int64)a1;
                                            a1 = a2;
                                            i >>= (__int64)a1;
                                            i |= v8;
                                            *(dst + (__int64)(__int64)result*4 - 4) = i;
                                            --result;
                                        } while (v7 < result);
                                    }
                                    a1 = (size_t *)v4;
                                    *(dst + v2*4) = *(dst + v2*4) << (__int64)a1;
                                    *(dst + 160) = v5;
                                    result = dst;
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            return (__int64)result;
                        }
                        return (__int64)result;
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}