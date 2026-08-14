// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F5BF0();
__int64 sub_1400F5C90();
extern __int64 off_140108450;
extern __int64 off_140108460;
extern __int64 off_140108470;
extern __int64 off_1401110E8;
extern __int64 off_140108480;

__int64 __fastcall sub_140026DF0(__int64 *a1,struct Struct_1_t *a2, __int64 a3, __int64 a4) {
    __int64 rsp;
    __int64 v_20;
    int v_28;
    int v_80;
    __int64 *i;
    __int64 v6;
    __int64 i2;
    __int64 *result;
    __int64 *src;
    __int64 v2;
    __m128i xmm1;
    __m128i xmm0;
    __int64 xmm2;
    __int64 *v7;
    __int64 v9;
    __int64 v8;

    i = a2->field_20;
    v6 = a2->field_28;
    i2 = v6 + 1;
    a2->field_28 = i2;
    result = 1;
    if (i2 < i) {
        result = a2->field_18;
        src = *(result + i2);
        result = 1;
        if (src != 43) {
            if (src == 45) {
                v6 += 2;
                a2->field_28 = v6;
                i2 = v6;
            }
            if (i2 >= i) {
                v_28 = 5;
            } else {
                src = a2->field_18;
                v6 = *(src + i2);
                v2 = i2 + 1;
                a2->field_28 = v2;
                v6 += 208;
                if (v6 >= 10) {
                    v_28 = 13;
                    result = rsp + 40;
                    i = a1;
                    sub_1400F5BF0(a2, result, a3, a4);
                    *(i + 8) = result;
                    *i = 1;
                } else {
                    if (v2 < i) {
                        v2 = 1;
                        v2 -= (__int64)i;
                        i2 += 2;
                        i = *(src + i2 - 1);
                        i += 208;
                        while (i < 10) {
                            a2->field_28 = i2;
                            if (v6 <= 0xCCCCCCB) {
                                v6 += v6*4;
                                v6 = i + v6*2;
                                i = v2 + i2;
                                ++i;
                                ++i2;
                                i2 = v_80;
                                if (result == 0) {
                                    result = 0;
                                    result = ((i2 - v6) >= 0) ? 1 : 0;
                                    result += 0x7FFFFFFF;
                                    i2 -= v6;
                                } else {
                                    result = i2 + v6;
                                    result = (__int64 *)((__int64)(__int64)result >> 31);
                                    result += 0x80000000;
                                    i2 += v6;
                                }
                                if (0 /* overflow check on (i2 - v6) */) i2 = result;
                                xmm1 = _mm_cvtsi64_si128(a4);
                                xmm1 = _mm_unpacklo_epi32(xmm1, _mm_load_si128((__m128i *)&off_140108450));
                                /* subpd off_140108460, %xmm1 */;
                                xmm0 = xmm1;
                                /* unpckhpd %xmm1, %xmm0 */;
                                /* addsd %xmm1, %xmm0 */;
                                result = (__int64 *)i2;
                                result = (__int64 *)(-(__int64)result);
                                if (result < 0) result = i2;
                                if (result >= 309) {
                                    xmm1 = _mm_setzero_pd();
                                    xmm2 = off_140108470;
                                    do {
                                        if (i2 < 0) {
                                            /* divsd %xmm2, %xmm0 */;
                                            i2 += 308;
                                            result = (__int64 *)i2;
                                            result = (__int64 *)(-(__int64)result);
                                            if (result < 0) result = i2;
                                            v7 = &off_1401110E8;
                                            xmm1 = v7[(__int64)result];
                                            if (i2 < 0) {
                                                /* divsd %xmm1, %xmm0 */;
                                                if (a3 == 0) {
                                                    xmm0 = _mm_xor_si128(xmm0, _mm_load_si128((__m128i *)&off_140108480));
                                                } else {
                                                }
                                                *(a1 + 8) = _mm_cvtsi128_si64(xmm0);
                                                result = 0;
                                                *a1 = result;
                                                return (__int64)result;
                                            } else {
                                                /* mulsd %xmm1, %xmm0 */;
                                                v9 = _mm_cvtsi128_si64(xmm0);
                                                v8 = 0x7FFFFFFFFFFFFFFF;
                                                v8 &= v9;
                                                result = 0x7FF0000000000000;
                                                if (v8 == result) {
                                                    v_28 = 14;
                                                    result = rsp + 40;
                                                    i = a1;
                                                    sub_1400F5BF0(a2, result);
                                                    a1 = i;
                                                    *(i + 8) = result;
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
                                    } while (result >= 309);
                                }
                                return (__int64)result;
                            }
                            if (v6 == 0xCCCCCCC) {
                                if (i <= 7) {
                                    return (__int64)result;
                                }
                            }
                            a4 = (a4 == 0) ? 1 : 0;
                            v_20 = (__int64)result;
                            sub_1400F5C90(0, a1, a2, a3, a4);
                            return v_20;
                        }
                    }
                    return v_20;
                }
                return v_20;
            }
            return v_20;
        }
        return v_20;
    }
    return (__int64)result;
}