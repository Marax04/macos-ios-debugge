__int64 sub_14002D9A0();
extern __int64 off_1401214B4;

__int64 __fastcall sub_14002D630(size_t *a1, __int64 *a2, int a3, size_t a4) {
    int arg_10;
    int arg_18;
    int arg_19;
    int arg_28;
    int arg_29;
    int arg_38;
    int arg_40;
    int arg_41;
    int arg_42;
    __int64 arg_8;
    int v_10;
    int v_18;
    int v_41;
    int v_50;
    int v_58;
    int v_60;
    int str;
    char *dst;
    __int64 *i;
    __int64 v3;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v10;
    __int64 v7;
    __int64 v8;
    __int64 v5;
    __int64 v2;
    __int64 v6;
    __int64 v9;

    i = *a1;
    v3 = arg_8;
    result = a1[2];
    if (result != 6) {
        a2 = a1[6];
        v_41 = (int)a2;
        xmm0 = _mm_loadu_si128((__m128i *)(a1 + 17));
        xmm1 = _mm_loadu_si128((__m128i *)(a1 + 33));
        _mm_store_si128((__m128i *)&v_50, xmm1);
        _mm_store_si128((__m128i *)&v_60, xmm0);
    }
    a2 = a1[7];
    v10 = a1[7];
    a3 = a1[7];
    arg_8 = (__int64)i;
    arg_10 = v3;
    arg_18 = result;
    xmm0 = _mm_load_si128((__m128i *)&v_60);
    xmm1 = _mm_load_si128((__m128i *)&v_50);
    _mm_storeu_si128((__m128i *)&arg_19, xmm0);
    _mm_storeu_si128((__m128i *)&arg_29, xmm1);
    a1 = (size_t *)v_41;
    arg_38 = (int)a1;
    arg_42 = (int)a2;
    arg_40 = v10;
    arg_41 = a3;
    if (v10 == 2) {
        if (v3 == 0) {
            v3 = 0;
            if (a3 == 2) {
                v7 = (result == 6) ? 1 : 0;
                v8 = (result < 5) ? 1 : 0;
                a3 = (v10 != 0) ? 1 : 0;
                v7 = arg_38;
                a1 = v7 + 1;
                if (v7 == 0) a1 = v7;
                if (v10 > 1) {
                    if (v3 != 0) {
                        v10 = dst - 96;
                        v5 = dst + 8;
                        sub_14002D9A0(v10, v5);
                        while (v_58 == 10) {
                            a2 = (__int64 *)v3;
                            a2 -= v_60;
                            if ((a2 < 0)) JUMPOUT(0x14002d95d);
                            arg_10 = (int)a2;
                            v3 = (__int64)a2;
                            v3 = 0;
                        }
                        result = (__int64)i;
                        a2 = (__int64 *)v3;
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                } else {
                    v2 = (__int64)a2;
                    v8 |= (__int64)a2;
                    v7 |= a3;
                    a2 = (__int64 *)arg_28;
                    a3 = a2 + 4;
                    v_10 = a3;
                    v6 = (__int64)a2 + (__int64)a1;
                    v6 += 2;
                    str = v6;
                    a1 = (__int64)a2 + (__int64)a1 + 8;
                    *dst = a1;
                    v_18 = v8;
                    v9 = dst + 8;
                    if (v8 != 0) {
                        do {
                            result = 0;
                            do {
                                a1 = (size_t *)v_18;
                                a2 = &off_1401214B4;
                                a1 = *(a2 + (__int64)(__int64)a1*4);
                                a1 = (size_t *)((__int64)a1 + (__int64)a2);
                                JUMPOUT(a1);
                                a1 = (size_t *)v_10;
                                a1 += v2;
                                v8 += (__int64)a1;
                                while (v3 > v8) {
                                    a1 = dst - 96;
                                    sub_14002D9A0(a1, v9, v6, v7);
                                    if (v_58 == 10) {
                                        a2 = (__int64 *)v3;
                                        a2 -= v_60;
                                        if ((a2 < 0)) JUMPOUT(0x14002d95d);
                                        arg_10 = (int)a2;
                                        v3 = (__int64)a2;
                                        if (v8 == 0) {
                                            if (v7 == 0) {
                                                a1 = 2;
                                                if (v3 < 2) JUMPOUT(0x14002d980);
                                                a2 = 0;
                                                result = (a1 != v3) ? 1 : 0;
                                                a1 = (size_t *)((__int64)a1 + (__int64)i);
                                                a2 = (__int64 *)result;
                                                a2 = (__int64 *)((__int64)a2 + (__int64)a1);
                                                v8 = i + v3;
                                                result = (a2 == v8) ? 1 : 0;
                                                a1 = *a1;
                                                a3 = (a1 != 46) ? 1 : 0;
                                                a3 |= result;
                                                if ((a3 == 0)) {
                                                    result = *a2;
                                                    a1 = (result == 92) ? 1 : 0;
                                                    result = (result == 47) ? 1 : 0;
                                                    result |= (__int64)a1;
                                                    if (v10 != 0) {
                                                        a1 = 0;
                                                    }
                                                }
                                                a1 = (a1 == 46) ? 1 : 0;
                                                result &= (__int64)a1;
                                                if (v10 != 0) {
                                                    return result;
                                                }
                                            }
                                            a1 = 0;
                                            return (__int64)a1;
                                        }
                                    }
                                }
                                return (__int64)a1;
                            } while (true);
                        } while (a1 == v3);
                    }
                    return (__int64)a1;
                }
            }
            return (__int64)a1;
        } else {
            if (result >= 3) {
                do {
                    a4 = 0;
                    a1 = *(i + a4);
                    while (a1 != 47) {
                        if (a1 == 92) {
                            a1 = 1;
                            if (a4 == 0) {
                                a1 += a4;
                                if (v3 < a1) JUMPOUT(0x14002d96e);
                                i = (__int64 *)((__int64)i + (__int64)a1);
                                v3 -= (__int64)a1;
                                v3 = 0;
                                arg_8 = (__int64)i;
                                arg_10 = v3;
                                if (a3 == 2) {
                                    return arg_10;
                                }
                                return arg_10;
                            }
                            if (a4 == 1) {
                                if (*i == 46) {
                                    return arg_10;
                                }
                            }
                            return arg_10;
                        }
                        ++a4;
                        a4 = v3;
                        a1 = 0;
                        if (v3 != 0) {
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                } while ((v3 != 0));
                return (__int64)a1;
            } else {
                a1 = i + v3;
                do {
                    a4 = 0;
                    while (*(i + a4) != 92) {
                        ++a4;
                        return a4;
                    }
                    if (a4 == 0) {
                        ++i;
                        --v3;
                        i = (__int64 *)a1;
                        return (__int64)i;
                    }
                    return (__int64)i;
                } while ((v3 != 0));
                return (__int64)i;
            }
            return (__int64)i;
        }
        return (__int64)i;
    }
    return result;
}