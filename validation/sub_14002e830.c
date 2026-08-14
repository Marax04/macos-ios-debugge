// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14002EA90();
__int64 sub_1400F68D0();
__int64 off_140108030();
extern __int64 off_140113110;
extern __int64 off_140108038;

__int64 __fastcall sub_14002E830(int *a1, __int64 a2, __int64 a3) {
    int arg_2;
    int arg_4;
    int arg_6;
    int arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_8;
    char *dst;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 *dst2;
    __int64 result;
    __int64 v8;
    __int64 v9;
    __int64 i2;
    __int64 v5;
    __m128i xmm0;
    __int64 v6;

    *dst = -2;
    ptr = (struct Struct_1_t *)a1;
    i = a3;
    ++i;
    dst2 = a3 + a3 + 2;
    result = (i >= 0) ? 1 : 0;
    a1 = 0x7FFFFFFFFFFFFFFF;
    a1 = (dst2 < a1) ? 1 : 0;
    if ((result & (__int64)a1) == 0) {
        sub_1400F3360(a1);
    }
    if (dst2 != 0) {
        v8 = a2;
        v9 = a3;
        sub_14002EDF0(0, dst2);
        a2 = v8;
        if (v6 == 0) {
            sub_1400F3326(2, dst2, v9);
            result = 2;
            i = 0;
        }
        v_18 = i;
        v_10 = v6;
        v_8 = 0;
        a3 += a2;
        v_30 = a2;
        v_28 = a3;
        v_20 = 0;
        a1 = dst - 24;
        a2 = dst - 48;
        sub_14002EA90(a1, a2, a3);
        dst2 = (__int64 *)v_10;
        i2 = v_8;
        result = i2;
        a1 = (int *)dst2;
        if (i2 >= 8) {
            a1 = (int *)dst2;
            result = i2;
            while (*a1 != 0) {
                if (arg_2 != 0) {
                    if (arg_4 != 0) {
                        if (arg_6 != 0) {
                            if (arg_8 != 0) {
                                if (a1[1] != 0) {
                                    if (a1[1] != 0) {
                                        if (a1[1] != 0) {
                                            result -= 8;
                                            a1 += 16;
                                            if (result != 0) {
                                                if (*a1 != 0) {
                                                    if (result != 1) {
                                                        if (arg_2 != 0) {
                                                            if (result != 2) {
                                                                if (arg_4 != 0) {
                                                                    if (result != 3) {
                                                                        if (arg_6 != 0) {
                                                                            if (result != 4) {
                                                                                if (arg_8 != 0) {
                                                                                    if (result != 5) {
                                                                                        if (a1[1] != 0) {
                                                                                            if (result != 6) {
                                                                                                a1 = (a1[1] != 0) ? 1 : 0;
                                                                                                result = (result == 7) ? 1 : 0;
                                                                                                if (((__int64)a1 & result) == 0) {
                                                                                                    result = &off_140113110;
                                                                                                    ptr->field_8 = result;
                                                                                                    *(__int64 *)ptr = (__int64)(result);
                                                                                                    if (v_18 != 0) {
                                                                                                        off_140108030(0x8000000000000000);
                                                                                                        a1 = (int *)result;
                                                                                                        a2 = 0;
                                                                                                        v5 = (__int64)dst2;
                                                                                                        JUMPOUT(off_140108038);
                                                                                                    }
                                                                                                } else {
                                                                                                    if (i2 == v_18) {
                                                                                                        a1 = dst - 24;
                                                                                                        sub_1400F68D0(a1);
                                                                                                        dst2 = (__int64 *)v_10;
                                                                                                    }
                                                                                                    *(dst2 + i2*2) = 0;
                                                                                                    ++i2;
                                                                                                    v_8 = i2;
                                                                                                    ptr->field_10 = i2;
                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_18);
                                                                                                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                                                                                                }
                                                                                                return _mm_cvtsi128_si64(xmm0);
                                                                                            }
                                                                                            return _mm_cvtsi128_si64(xmm0);
                                                                                        }
                                                                                        return _mm_cvtsi128_si64(xmm0);
                                                                                    }
                                                                                    return _mm_cvtsi128_si64(xmm0);
                                                                                }
                                                                                return _mm_cvtsi128_si64(xmm0);
                                                                            }
                                                                            return _mm_cvtsi128_si64(xmm0);
                                                                        }
                                                                        return _mm_cvtsi128_si64(xmm0);
                                                                    }
                                                                    return _mm_cvtsi128_si64(xmm0);
                                                                }
                                                                return _mm_cvtsi128_si64(xmm0);
                                                            }
                                                            return _mm_cvtsi128_si64(xmm0);
                                                        }
                                                        return _mm_cvtsi128_si64(xmm0);
                                                    }
                                                    return _mm_cvtsi128_si64(xmm0);
                                                }
                                                return _mm_cvtsi128_si64(xmm0);
                                            }
                                            return _mm_cvtsi128_si64(xmm0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return result;
}