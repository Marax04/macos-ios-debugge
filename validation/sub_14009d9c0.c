__int64 sub_14009E080();
__int64 sub_1400F9B90();
__int64 sub_1400FB0B0();
__int64 sub_14009E170();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14009D9C0(__int64 *a1, size_t *a2) {
    __int64 rsp;
    int arg_14;
    int arg_24;
    int arg_28;
    int arg_2c;
    int arg_8;
    int v_28;
    __int64 v_2e;
    int v_30;
    int v_38;
    __int64 v_3c;
    int v_40;
    int v_48;
    int v_50;
    __int64 v_58;
    int v_64;
    int v_68;
    int v_70;
    int v_78;
    __int64 v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_a0;
    __int64 v_a8;
    __int64 v_b0;
    __int64 v_b8;
    int v_c0;
    __int64 *v_0;
    __int64 *v_14;
    __int64 *v_18;
    __int64 *v_1a;
    __int64 *v_1c;
    __int64 *v_20;
    __int64 *v_24;
    __int64 *v_8;
    __int64 *v_c;
    int v13;
    __int64 *result;
    __int64 v9;
    __int64 *src;
    __int64 i;
    __int64 v12;
    __int64 v11;
    __int64 v6;
    __int64 v8;
    __int64 *src2;
    __int64 v7;
    __int64 *src3;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_c0, xmm6);
    if (a2[28] >= 2) {
        v13 = a2[11];
        result = a2[11];
        result = (__int64 *)((__int64)(__int64)result | v13);
        if ((result == 0)) {
            *a1 = 0;
            arg_8 = 8;
            a1[2] = 0;
        } else {
            v_68 = 0;
            v_70 = 8;
            v_78 = 0;
            v9 = a2[4];
            result = a2[5];
            src = *(a2 + 8);
            i = a2[2];
            v9 -= 28;
            a2 = result + (__int64)(__int64)result*8;
            v12 = a2 + (__int64)(__int64)a2*2;
            v12 += (__int64)result;
            v11 = 0x8000000000000000;
            do {
                a2 = (size_t *)v12;
                result = (__int64 *)v9;
                while (a2 != 0) {
                    v6 = arg_24;
                    v8 = arg_28;
                    src2 = (__int64 *)arg_2c;
                    if (src2 > v6) v6 = src2;
                    v6 += v8;
                    if (!((v6 < 0))) {
                        result += 28;
                        a2 -= 28;
                        v7 = v13;
                        v7 -= v8;
                        if (v7 < src2) {
                            result = (__int64 *)arg_14;
                            a2 = (size_t *)v7;
                            a2 = (size_t *)((__int64)a2 + (__int64)result);
                            if (a2 < i) {
                                result = a2 + 20;
                                if (i >= result) {
                                    src3 = *(__int64 *)((__int64)src + (__int64)a2);
                                    result = *(__int64 *)((__int64)src + (__int64)a2 + 12);
                                    src2 = *(__int64 *)((__int64)src + (__int64)a2 + 16);
                                    a2 = (size_t *)result;
                                    a2 = (size_t *)((__int64)(__int64)a2 | (__int64)src3);
                                    a2 = (size_t *)((__int64)(__int64)a2 | (__int64)src2);
                                    if (!((a2 == 0))) {
                                        if (result != 0) {
                                            if (src2 != 0) {
                                                v_3c = (__int64)src2;
                                                v_20 = (__int64 *)i;
                                                src2 = (__int64 *)v12;
                                                a2 = (size_t *)v9;
                                                while (src2 != 0) {
                                                    v7 = a2[4];
                                                    i = a2[5];
                                                    v6 = a2[5];
                                                    if (v6 > v7) v7 = v6;
                                                    v7 += i;
                                                    if (!((v7 < 0))) {
                                                        a2 += 28;
                                                        src2 -= 28;
                                                        v8 = (__int64)result;
                                                        v8 -= i;
                                                        if (v8 < v6) {
                                                            result = a2[2];
                                                            v6 = v8;
                                                            v6 += (__int64)result;
                                                            if (v6 < v_20) {
                                                                v_30 = (int)a1;
                                                                a1 = rsp + 144;
                                                                src2 = v_20;
                                                                sub_14009E080(a1, src, src2, v6);
                                                                a1 = (__int64 *)v_30;
                                                                a2 = (size_t *)v_90;
                                                                result = (__int64 *)a2;
                                                                result = (__int64 *)(-(__int64)result);
                                                                if (!((0 /* overflow check on (-result) */))) {
                                                                    v_88 = (int)a2;
                                                                    v_58 = (__int64)src;
                                                                    result = (__int64 *)v_98;
                                                                    v_80 = (__int64)result;
                                                                    if (src3 == 0) src3 = v_3c;
                                                                    result = (__int64 *)v_a0;
                                                                    v_b8 = (__int64)result;
                                                                    v_40 = 0;
                                                                    v_48 = 8;
                                                                    v_50 = 0;
                                                                    i = 0;
                                                                    result = 8;
                                                                    v_28 = 0;
                                                                    v7 = 0;
                                                                    v6 = v2;
                                                                    v6 &= 0xFFFF0000;
                                                                    v_64 = v7;
                                                                    v2 = v7;
                                                                    src2 = (__int64 *)v12;
                                                                    a2 = (size_t *)v9;
                                                                    v2 += (__int64)src3;
                                                                    if (v2 < 0) v2 = v6;
                                                                    while (!((v2 < 0))) {
                                                                        while (src2 != 0) {
                                                                            v7 = a2[4];
                                                                            src = a2[5];
                                                                            v6 = a2[5];
                                                                            if (v6 > v7) v7 = v6;
                                                                            v7 += (__int64)src;
                                                                            if (!((v7 < 0))) {
                                                                                a2 += 28;
                                                                                src2 -= 28;
                                                                                v8 = v2;
                                                                                v8 -= (__int64)src;
                                                                                if (v8 < v6) {
                                                                                    src2 = a2[2];
                                                                                    a2 = (size_t *)v8;
                                                                                    a2 = (size_t *)((__int64)a2 + (__int64)src2);
                                                                                    if (a2 < v_20) {
                                                                                        src2 = a2 + 8;
                                                                                        if (v_20 >= src2) {
                                                                                            src2 = (__int64 *)v_58;
                                                                                            src = *(__int64 *)((__int64)src2 + (__int64)a2);
                                                                                            if (src == 0) {
                                                                                                i = v_78;
                                                                                                result = rsp + 104;
                                                                                                if (i == v_68) {
                                                                                                    sub_1400F9B90(result, a2, src2);
                                                                                                    a1 = (__int64 *)v_30;
                                                                                                }
                                                                                                result = (__int64 *)v_70;
                                                                                                a2 = i + i*2;
                                                                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                                src2 = (__int64 *)v_88;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = src2;
                                                                                                src2 = (__int64 *)v_80;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 8) = src2;
                                                                                                src2 = (__int64 *)v_b8;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 16) = src2;
                                                                                                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                                                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 24), xmm0);
                                                                                                src2 = (__int64 *)v_50;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 40) = src2;
                                                                                                ++i;
                                                                                                v_78 = i;
                                                                                                src = (__int64 *)v_58;
                                                                                                if (v13 > 0xFFFFFFEB) JUMPOUT(0x14009e06f);
                                                                                                v13 += 20;
                                                                                                i = (__int64)v_20;
                                                                                            }
                                                                                            a2 = (size_t *)v_38;
                                                                                            a2 = (size_t *)((__int64)(__int64)a2 & 0xFFFF0000);
                                                                                            v11 = v_28;
                                                                                            v11 += v_3c;
                                                                                            if (v11 >= 0) a2 = v11;
                                                                                            if (!((v11 < 0))) {
                                                                                                v_38 = (int)a2;
                                                                                                if (src < 0) {
                                                                                                    if (i == v_40) {
                                                                                                        a1 = rsp + 64;
                                                                                                        sub_1400FB0B0(a1, a2, src2, v6);
                                                                                                        a1 = (__int64 *)v_30;
                                                                                                        result = (__int64 *)v_48;
                                                                                                    }
                                                                                                    a2 = i + i*4;
                                                                                                    src2 = 0x8000000000000000;
                                                                                                    v_0[(__int64)a2] = src2;
                                                                                                    v_18[(__int64)a2] = 1;
                                                                                                    v_1a[(__int64)a2] = src;
                                                                                                    v_1c[(__int64)a2] = v11;
                                                                                                    v_20[(__int64)a2] = 0;
                                                                                                    v_24[(__int64)a2] = 0;
                                                                                                    a2 = (size_t *)i;
                                                                                                    ++a2;
                                                                                                    v_50 = (int)a2;
                                                                                                    src2 =  + (__int64)(__int64)a2*8;
                                                                                                    v7 = v_64;
                                                                                                    v7 &= 0xFFFF0000;
                                                                                                    v6 = v_28;
                                                                                                    v6 &= 0xFFFF0000;
                                                                                                    if (i < 0x1FFFFFFF) v7 = src2;
                                                                                                    if (i < 0x1FFFFFFF) v6 = src2;
                                                                                                    v_28 = v6;
                                                                                                    i = (__int64)a2;
                                                                                                    v11 = 0x8000000000000000;
                                                                                                    arg_8 = 8;
                                                                                                    *a1 = v11;
                                                                                                    i = 0x20000000;
                                                                                                    v2 = v_48;
                                                                                                    src3 = v2 + 8;
                                                                                                    v12 = off_140108030;
                                                                                                    v7 = off_140108038;
                                                                                                    do {
                                                                                                        result = *(src3 - 8);
                                                                                                        result = (__int64 *)((__int64)(__int64)result << 1);
                                                                                                        src3 += 40;
                                                                                                        --i;
                                                                                                    } while (!((i == 0)));
                                                                                                    if (v_40 != 0) {
                                                                                                        ((__int64 (*)())off_140108030)();
                                                                                                        ((__int64 (*)())off_140108038)(result, 0, v2);
                                                                                                    }
                                                                                                    if (v_88 != 0) {
                                                                                                        ((__int64 (*)())off_140108030)();
                                                                                                        src2 = (__int64 *)v_80;
                                                                                                        ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                    }
                                                                                                    a1 = rsp + 104;
                                                                                                    sub_14009E170(a1);
                                                                                                    xmm6 = _mm_load_si128((__m128i *)&v_c0);
                                                                                                    return _mm_cvtsi128_si64(xmm6);
                                                                                                }
                                                                                                src = (__int64 *)((__int64)(__int64)src & 0x7FFFFFFF);
                                                                                                a2 = (size_t *)v12;
                                                                                                result = (__int64 *)v9;
                                                                                                v11 = 0x8000000000000000;
                                                                                                while (a2 != 0) {
                                                                                                    v6 = arg_24;
                                                                                                    v8 = arg_28;
                                                                                                    src2 = (__int64 *)arg_2c;
                                                                                                    if (src2 > v6) v6 = src2;
                                                                                                    v6 += v8;
                                                                                                    if (!((v6 < 0))) {
                                                                                                        result += 28;
                                                                                                        a2 -= 28;
                                                                                                        v7 = (__int64)src;
                                                                                                        v7 -= v8;
                                                                                                        if (v7 < src2) {
                                                                                                            a2 = (size_t *)arg_14;
                                                                                                            result = (__int64 *)v7;
                                                                                                            result = (__int64 *)((__int64)result + (__int64)a2);
                                                                                                            if (result < v_20) {
                                                                                                                v6 = result + 2;
                                                                                                                src2 = v_20;
                                                                                                                if (src2 >= v6) {
                                                                                                                    a2 = (size_t *)v_58;
                                                                                                                    result = *(__int64 *)((__int64)a2 + (__int64)result);
                                                                                                                    v_2e = (__int64)result;
                                                                                                                    a1 = rsp + 144;
                                                                                                                    sub_14009E080(a1, a2, src2, v6);
                                                                                                                    v8 = v_90;
                                                                                                                    result = (__int64 *)v8;
                                                                                                                    result = (__int64 *)(-(__int64)result);
                                                                                                                    if (!((0 /* overflow check on (-result) */))) {
                                                                                                                        xmm6 = _mm_cvtsi64_si128((__int64)(v_98));
                                                                                                                        a1 = rsp + 156;
                                                                                                                        result = (__int64 *)arg_8;
                                                                                                                        v_b0 = (__int64)result;
                                                                                                                        result = *a1;
                                                                                                                        v_a8 = (__int64)result;
                                                                                                                        a1 = (__int64 *)v_30;
                                                                                                                        if (i == v_40) {
                                                                                                                            a1 = rsp + 64;
                                                                                                                            sub_1400FB0B0(a1);
                                                                                                                            a1 = (__int64 *)v_30;
                                                                                                                        }
                                                                                                                        src += 2;
                                                                                                                        result = (__int64 *)v_48;
                                                                                                                        a2 = i + i*4;
                                                                                                                        v_0[(__int64)a2] = v8;
                                                                                                                        v_8[(__int64)a2] = _mm_cvtsi128_si64(xmm6);
                                                                                                                        src2 = (__int64 *)v_a8;
                                                                                                                        v_c[(__int64)a2] = src2;
                                                                                                                        src2 = (__int64 *)v_b0;
                                                                                                                        v_14[(__int64)a2] = src2;
                                                                                                                        v_18[(__int64)a2] = 0;
                                                                                                                        src2 = (__int64 *)v_38;
                                                                                                                        v_1c[(__int64)a2] = src2;
                                                                                                                        v_20[(__int64)a2] = src;
                                                                                                                        src2 = (__int64 *)v_2e;
                                                                                                                        v_24[(__int64)a2] = src2;
                                                                                                                        return (__int64)src2;
                                                                                                                    }
                                                                                                                    a1 = (__int64 *)v_30;
                                                                                                                    arg_8 = 8;
                                                                                                                    v11 = 0x8000000000000000;
                                                                                                                    *a1 = v11;
                                                                                                                    v2 = v_48;
                                                                                                                    if (i != 0) {
                                                                                                                        return v2;
                                                                                                                    }
                                                                                                                    return v2;
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                                arg_8 = 8;
                                                                                                return arg_8;
                                                                                            }
                                                                                            arg_8 = 8;
                                                                                            return arg_8;
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        return arg_8;
                                                                    }
                                                                    arg_8 = 8;
                                                                    return arg_8;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        arg_8 = 8;
                                        *a1 = v11;
                                        return arg_8;
                                    }
                                    result = (__int64 *)v_78;
                                    a1[2] = result;
                                    xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                                    _mm_storeu_si128((__m128i *)a1, xmm0);
                                    return _mm_cvtsi128_si64(xmm0);
                                }
                            }
                        }
                    }
                }
                return _mm_cvtsi128_si64(xmm0);
            } while (true);
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}