__int64 sub_1400F27FC();
__int64 sub_14002C1BE();
__int64 sub_1400F6A10();
__int64 sub_14001A580();
__int64 sub_14002C091();

__int64 __fastcall sub_14002BC60(__int64 *a1, __int64 a2, int *a3, int *a4) {
    int arg_10;
    int arg_18;
    __int64 arg_20;
    __int64 arg_28;
    int arg_30;
    int arg_40;
    int arg_50;
    int arg_60;
    int arg_70;
    int arg_8;
    int arg_80;
    int arg_90;
    int arg_a0;
    int v_10;
    int v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    char *src;
    __int64 i;
    __int64 v2;
    __int64 *i2;
    __int64 *src2;
    __int64 result;
    __m128i xmm0;
    __m128i xmm6;
    __m128i xmm7;
    __int64 v10;
    __int64 v8;
    __int64 v7;
    __m128i xmm12;
    __m128i xmm10;
    __m128i xmm8;
    __m128i xmm1;
    __m128i xmm13;
    __m128i xmm11;
    __m128i xmm9;
    __int64 v6;
    __int64 *src3;

    _mm_store_si128((__m128i *)&arg_a0, xmm13);
    _mm_store_si128((__m128i *)&arg_90, xmm12);
    _mm_store_si128((__m128i *)&arg_80, xmm11);
    _mm_store_si128((__m128i *)&arg_70, xmm10);
    _mm_store_si128((__m128i *)&arg_60, xmm9);
    _mm_store_si128((__m128i *)&arg_50, xmm8);
    _mm_store_si128((__m128i *)&arg_40, xmm7);
    _mm_store_si128((__m128i *)&arg_30, xmm6);
    i = (__int64)a3;
    v2 = a2;
    i2 = a1;
    if (a2 >= a4) {
        if (!((0 /* unresolved: flags != */))) {
            sub_1400F27FC(i2, i, v2, a4);
            i2 = (result == 0) ? 1 : 0;
            return sub_14002C1BE();
        }
    } else {
        src2 = (__int64 *)a4;
        result = *i2;
        a2 = v2 - 1;
        a1 = *(i2 + v2 - 1);
        a3 = (int *)a2;
        if (a1 == result) {
            a1 = *(i2 + v2 - 2);
            if (a1 != result) {
                a3 = v2 - 2;
            } else {
                a1 = *(i2 + v2 - 3);
                if (a1 != result) {
                    a3 = v2 - 3;
                    a4 = v2 + 15;
                    if (src2 >= a4) {
                        v_50 = (int)a4;
                        xmm0 = _mm_cvtsi32_si128(result);
                        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                        xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                        xmm6 = _mm_shuffle_epi32(xmm0, 68);
                        result = (__int64)a1;
                        xmm0 = _mm_cvtsi32_si128(result);
                        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                        xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                        xmm7 = _mm_shuffle_epi32(xmm0, 68);
                        ++i2;
                        v_48 = i;
                        v_40 = (__int64)src2;
                        v_38 = (__int64)i2;
                        arg_20 = a2;
                        v_30 = a2;
                        result = v2 + 63;
                        arg_28 = (__int64)a3;
                        if (result >= src2) {
                            i2 = 0;
                            v10 = 0;
                        } else {
                            v8 = v2 + 127;
                            v7 = a3 + i;
                            v7 += 48;
                            v10 = 0;
                            do {
                                xmm0 = _mm_loadu_si128((__m128i *)(i + v10));
                                xmm12 = _mm_loadu_si128((__m128i *)(i + v10 + 16));
                                xmm10 = _mm_loadu_si128((__m128i *)(i + v10 + 32));
                                xmm8 = _mm_loadu_si128((__m128i *)(i + v10 + 48));
                                xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                                xmm1 = _mm_loadu_si128((__m128i *)(v7 + v10 - 48));
                                xmm13 = _mm_loadu_si128((__m128i *)(v7 + v10 - 32));
                                xmm11 = _mm_loadu_si128((__m128i *)(v7 + v10 - 16));
                                xmm9 = _mm_loadu_si128((__m128i *)(v7 + v10));
                                xmm1 = _mm_cmpeq_epi8(xmm1, xmm7);
                                xmm1 = _mm_and_si128(xmm1, xmm0);
                                a3 = _mm_movemask_epi8(xmm1);
                                a1 = src - 72;
                                sub_1400F6A10(a1, v10, a3, 0);
                                i2 = (__int64 *)result;
                                xmm12 = _mm_cmpeq_epi8(xmm12, xmm6);
                                xmm13 = _mm_cmpeq_epi8(xmm13, xmm7);
                                xmm13 = _mm_and_si128(xmm13, xmm12);
                                a3 = _mm_movemask_epi8(xmm13);
                                if (a3 != 0) {
                                    a2 = v10 + 16;
                                    a1 = src - 72;
                                    sub_1400F6A10(a1, a2, a3, i2);
                                    result |= (__int64)i2;
                                    i2 = (__int64 *)result;
                                }
                                xmm10 = _mm_cmpeq_epi8(xmm10, xmm6);
                                xmm11 = _mm_cmpeq_epi8(xmm11, xmm7);
                                xmm11 = _mm_and_si128(xmm11, xmm10);
                                a3 = _mm_movemask_epi8(xmm11);
                                if (a3 != 0) {
                                    a2 = v10 + 32;
                                    a1 = src - 72;
                                    sub_1400F6A10(a1, a2, a3, i2);
                                    result |= (__int64)i2;
                                    i2 = (__int64 *)result;
                                }
                                xmm8 = _mm_cmpeq_epi8(xmm8, xmm6);
                                xmm9 = _mm_cmpeq_epi8(xmm9, xmm7);
                                xmm9 = _mm_and_si128(xmm9, xmm8);
                                a3 = _mm_movemask_epi8(xmm9);
                                if (a3 != 0) {
                                    a2 = v10 + 48;
                                    a1 = src - 72;
                                    sub_1400F6A10(a1, a2, a3, i2);
                                    result |= (__int64)i2;
                                    i2 = (__int64 *)result;
                                    result = v10 + v8;
                                    v10 += 64;
                                    if (result < src2) {
                                        result = v_50;
                                        result += v10;
                                        if (result < src2) {
                                            if (i2 == 0) {
                                                v2 += 31;
                                                result = arg_28;
                                                v7 = i + result;
                                                v8 = src - 72;
                                                do {
                                                    xmm0 = _mm_loadu_si128((__m128i *)(i + v10));
                                                    xmm1 = _mm_loadu_si128((__m128i *)(v7 + v10));
                                                    xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                                                    xmm1 = _mm_cmpeq_epi8(xmm1, xmm7);
                                                    xmm1 = _mm_and_si128(xmm1, xmm0);
                                                    a3 = _mm_movemask_epi8(xmm1);
                                                    sub_1400F6A10(v8, v10, a3, 0);
                                                    i2 = (__int64 *)result;
                                                    result = v2 + v10;
                                                    if (result < src2) {
                                                        v10 += 16;
                                                    }
                                                    src2 -= arg_20;
                                                    result = i + src2;
                                                    result -= 16;
                                                    xmm0 = _mm_loadu_si128((__m128i *)(i + src2 - 16));
                                                    a1 = (__int64 *)arg_28;
                                                    xmm1 = _mm_loadu_si128((__m128i *)(a1 + result));
                                                    xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                                                    xmm1 = _mm_cmpeq_epi8(xmm1, xmm7);
                                                    xmm1 = _mm_and_si128(xmm1, xmm0);
                                                    a3 = _mm_movemask_epi8(xmm1);
                                                    if (a3 == 0) JUMPOUT(0x14002c1be);
                                                    src2 -= 16;
                                                    a1 = src - 72;
                                                    sub_1400F6A10(a1, src2, a3, i2);
                                                    result |= (__int64)i2;
                                                    i2 = (__int64 *)result;
                                                    return sub_14002C1BE();
                                                } while (i2 == 0);
                                                return (__int64)i2;
                                            }
                                        }
                                        return (__int64)i2;
                                    }
                                    return (__int64)i2;
                                }
                                result = v10 + v8;
                                v10 += 64;
                                if (result < src2) {
                                    return v10;
                                }
                                return v10;
                            } while (i2 == 0);
                            return v10;
                        }
                        return v10;
                    }
                } else {
                    a3 = v2 - 4;
                    a1 = *(i2 + v2 - 4);
                    if (a1 != result) {
                        a4 = v2 + 15;
                        if (src2 < a4) {
                            do {
                                sub_1400F27FC(i, i2, v2, a4);
                                if (result == 0) JUMPOUT(0x14002c1bb);
                                ++i;
                                --src2;
                            } while (v2 <= src2);
                            i2 = 0;
                            return sub_14002C1BE();
                        }
                    } else {
                        if (a3 >= a3) {
                            v_20 = v2;
                            a1 = src - 72;
                            sub_14001A580(a1, i, src2, i2);
                            if (v_48 != 1) JUMPOUT(0x14002c0de);
                            i = v_10;
                            a3 = *src;
                            result = arg_18;
                            v6 = result - 1;
                            a2 = arg_8;
                            src2 = (__int64 *)arg_10;
                            if (i == -1) JUMPOUT(0x14002c11a);
                            a1 = (__int64 *)v_20;
                            a4 = a1 + v6;
                            if (a4 < a2) {
                                v2 = v_28;
                                v7 = v_40;
                                src3 = (__int64 *)v_30;
                                i2 = (__int64 *)result;
                                arg_28 = (__int64)src3;
                                i2 = (__int64 *)((__int64)i2 - (__int64)src3);
                                arg_20 = (__int64)i2;
                                a4 = *(__int64 *)((__int64)a3 + (__int64)a4);
                                if ((i2 >= 0)) JUMPOUT(0x14002c08e);
                                v10 = v7;
                                if (i > v7) v7 = i;
                                src3 = (__int64)a3 + (__int64)a1;
                                a4 = (int *)v7;
                                do {
                                    if (a4 >= result) JUMPOUT(0x14002c0a4);
                                    i2 = (__int64 *)a4;
                                    a4 = (int *)((__int64)a4 + (__int64)a1);
                                    if (a4 >= a2) JUMPOUT(0x14002c300);
                                    a4 = i2 + 1;
                                    v8 = *(__int64 *)((__int64)src2 + (__int64)i2);
                                } while (v8 == *(__int64 *)((__int64)src3 + (__int64)i2));
                                a1 -= v7;
                                a1 = (__int64 *)((__int64)a1 + (__int64)i2);
                                ++a1;
                                return sub_14002C091();
                            }
                        } else {
                            a3 = v2 - 5;
                            a1 = *(i2 + v2 - 5);
                            a4 = v2 + 15;
                            if (src2 < a4) {
                                return (__int64)a4;
                            } else {
                                return (__int64)a4;
                            }
                        }
                        return (__int64)a4;
                    }
                    return (__int64)a4;
                }
                return (__int64)a4;
            }
        }
        return (__int64)a4;
    }
    return result;
}