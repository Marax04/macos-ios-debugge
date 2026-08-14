// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
__int64 sub_140027750();
__int64 sub_1400F5C90();
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;
extern __int64 off_140108450;
extern __int64 off_140108460;
extern __int64 off_140108470;
extern __int64 off_1401110E8;
extern __int64 off_140108480;

__int64 __fastcall sub_140001560(__int64 *a1,struct Struct_1_t *a2, __int64 a3, size_t a4) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    int v_28;
    int v_90;
    __int64 *result;
    __int64 i;
    __int64 v6;
    __int64 *i2;
    __int64 *src;
    __int64 *src2;
    __int64 *dst;
    __int64 v9;
    __int64 v8;
    __m128i xmm1;
    __m128i xmm0;
    __int64 xmm2;
    __int64 *v7;

    result = a2 + 24;
    i = a2->field_20;
    v6 = a2->field_28;
    i2 = v6 + 1;
    a2->field_28 = i2;
    src = 1;
    if (i2 < i) {
        src = *result;
        src2 = *(__int64 *)((__int64)src + (__int64)i2);
        src = 1;
        if (src2 != 43) {
            if (src2 == 45) {
                src = 0;
                v6 += 2;
                a2->field_28 = v6;
                i2 = (__int64 *)v6;
            }
            if (i2 >= i) {
                v_28 = 5;
                if ((0 /* unresolved: flags > */)) JUMPOUT(0x140001855);
                dst = a1;
                src2 = *result;
                a3 = (__int64)src2 + (__int64)i2;
                result = off_14012D020;
                ((__int64 (*)())result)(10, src2, a3, a4);
                if (((__int64)result & 1) != 0) {
                    a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)src2);
                    v9 = a2 + 1;
                    if (a2 >= i) {
                        a4 = &off_140111F70;
                        sub_1400F3600(0, v9, i, a4);
                        v9 = 0;
                    }
                    a3 = src2 + v9;
                    result = off_14012D018;
                    ((__int64 (*)())result)(10, src2, a3);
                    a2 = result + 1;
                    i2 -= v9;
                    a1 = rsp + 40;
                    sub_1400F5F40(a1, a2, i2);
                    *(dst + 8) = result;
                    *dst = 1;
                    return (__int64)a1;
                }
                return (__int64)a1;
            } else {
                src2 = a2->field_18;
                v6 = *(__int64 *)((__int64)src2 + (__int64)i2);
                v8 = i2 + 1;
                a2->field_28 = v8;
                v6 += 208;
                if (v6 >= 10) {
                    v_28 = 13;
                    i2 = a1;
                    sub_140027750(result);
                    a1 = rsp + 40;
                    sub_1400F5F40(a1, result, a2);
                    *(i2 + 8) = result;
                    *i2 = 1;
                } else {
                    if (v8 < i) {
                        v9 = 1;
                        v8 -= i;
                        i2 += 2;
                        i = *(__int64 *)((__int64)src2 + (__int64)i2 - 1);
                        i += 208;
                        while (i < 10) {
                            a2->field_28 = i2;
                            if (v6 <= 0xCCCCCCB) {
                                v6 += v6*4;
                                v6 = i + v6*2;
                                i = v8 + i2;
                                ++i;
                                ++i2;
                                a2 = (struct Struct_1_t *)v_90;
                                if (src == 0) {
                                    src = 0;
                                    src = ((a2 - v6) >= 0) ? 1 : 0;
                                    src += 0x7FFFFFFF;
                                    a2 -= v6;
                                } else {
                                    src = a2 + v6;
                                    src = (__int64 *)((__int64)(__int64)src >> 31);
                                    src += 0x80000000;
                                    a2 += v6;
                                }
                                if (0 /* overflow check on (a2 - v6) */) a2 = src;
                                xmm1 = _mm_cvtsi64_si128(a4);
                                xmm1 = _mm_unpacklo_epi32(xmm1, _mm_load_si128((__m128i *)&off_140108450));
                                /* subpd off_140108460, %xmm1 */;
                                xmm0 = xmm1;
                                /* unpckhpd %xmm1, %xmm0 */;
                                /* addsd %xmm1, %xmm0 */;
                                a4 = (size_t)a2;
                                a4 = -a4;
                                if (a4 < 0) a4 = a2;
                                if (a4 >= 309) {
                                    xmm1 = _mm_setzero_pd();
                                    xmm2 = off_140108470;
                                    do {
                                        if (a2 < 0) {
                                            /* divsd %xmm2, %xmm0 */;
                                            a2 += 308;
                                            a4 = (size_t)a2;
                                            a4 = -a4;
                                            if (a4 < 0) a4 = a2;
                                            v7 = &off_1401110E8;
                                            xmm1 = v7[a4];
                                            if (a2 < 0) {
                                                /* divsd %xmm1, %xmm0 */;
                                                if (a3 == 0) {
                                                    xmm0 = _mm_xor_si128(xmm0, _mm_load_si128((__m128i *)&off_140108480));
                                                } else {
                                                }
                                                arg_8 = _mm_cvtsi128_si64(xmm0);
                                                result = 0;
                                                *a1 = result;
                                                return (__int64)result;
                                            } else {
                                                /* mulsd %xmm1, %xmm0 */;
                                                a2 = _mm_cvtsi128_si64(xmm0);
                                                a4 = 0x7FFFFFFFFFFFFFFF;
                                                a4 &= (__int64)a2;
                                                a2 = 0x7FF0000000000000;
                                                if (a4 == a2) {
                                                    v_28 = 14;
                                                    i2 = a1;
                                                    sub_140027750(result);
                                                    a1 = rsp + 40;
                                                    sub_1400F5F40(a1, result, a2);
                                                    a1 = i2;
                                                    *(i2 + 8) = result;
                                                    result = 1;
                                                } else {
                                                    if (a3 == 0) {
                                                        return (__int64)result;
                                                    }
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    } while (a4 >= 309);
                                }
                                return (__int64)result;
                            }
                            if (v6 == 0xCCCCCCC) {
                                if (i <= 7) {
                                    return (__int64)result;
                                }
                            }
                            a4 = (a4 == 0) ? 1 : 0;
                            v_20 = (__int64)src;
                            sub_1400F5C90(a1, a2, a3, a4);
                            return v_20;
                        }
                    }
                    return v_20;
                }
            }
            return v_20;
        }
        return v_20;
    }
    return (__int64)result;
}