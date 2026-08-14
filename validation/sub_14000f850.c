__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F33A0();
__int64 sub_1400F27F0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14000F850(size_t a1, int *a2, int a3) {
    __int64 rsp;
    int v_1;
    int v_10;
    int v_18;
    int v_2;
    __int64 v_20;
    int v_28;
    int v_3;
    int v_30;
    int v_4;
    __int64 *dst;
    __int64 *src;
    __int64 *dst2;
    __int64 v2;
    __int64 v3;
    __int64 v10;
    int v9;
    __int64 v8;
    __int64 result;
    __int64 v6;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;

    dst = rsp + 80;
    *dst = -2;
    if (a3 < 0) {
        sub_1400F3360();
    }
    src = (__int64 *)a2;
    v_30 = a1;
    if ((0 /* unresolved: flags == */)) {
        dst2 = 1;
    } else {
        v2 = a3;
        sub_14002EDF0(0, a3);
        if (result == 0) {
            sub_1400F3326(1, v2);
            v_10 = v2;
            dst = v2 + 80;
            if (v_28 != 0) {
                v3 = v_20;
                off_140108030();
                off_140108038(result, 0, v3);
            }
            return v3;
        } else {
            dst2 = (__int64 *)result;
            a3 = v2;
        }
    }
    v_28 = a3;
    v_20 = (__int64)dst2;
    v_18 = 0;
    v_10 = 1;
    v2 = src + a3*2;
    v10 = 0;
    v9 = 0;
    do {
        if (src != v2) {
            v8 = *src;
            src += 2;
            a1 = v8;
            a1 &= 0xF800;
            result = v8;
            if (a1 != 0xD800) {
                v_4 = 0;
                if (result >= 128) {
                    a1 = result;
                    a1 <<= 16;
                    result &= 63;
                    result |= 128;
                    a2 = (int *)a1;
                    a2 = (int *)((__int64)(__int64)a2 >> 22);
                    if (a1 >= 0x8000000) {
                        a2 = (int *)((__int64)(__int64)a2 & 63);
                        a2 = (int *)((__int64)(__int64)a2 | 128);
                        v6 = a1;
                        v6 >>= 28;
                        v5 = a1;
                        v5 >>= 32;
                        if ((v5 != 0)) {
                            a3 &= 63;
                            a3 |= 128;
                            a1 >>= 34;
                            a1 |= 240;
                            v_4 = a1;
                            v_3 = a3;
                            v_2 = (int)a2;
                            v_1 = result;
                            v8 = 4;
                            result = v_28;
                            result -= v10;
                            if (v8 > result) {
                                a1 = dst - 40;
                                sub_1400F33A0(a1, v10, v8);
                                dst2 = (__int64 *)v_20;
                                v10 = v_18;
                            }
                            a1 = dst2 + v10;
                            a2 = dst - 4;
                            sub_1400F27F0(a1, a2, v8, v5);
                            v10 += v8;
                            v_18 = v10;
                            v9 = 0;
                        }
                        a3 |= 224;
                        v_4 = a3;
                        v_3 = (int)a2;
                        v_2 = result;
                        v8 = 3;
                        return v8;
                    }
                    a2 = (int *)((__int64)(__int64)a2 | 192);
                    v_4 = (int)a2;
                    v_3 = result;
                    v8 = 2;
                    return v8;
                }
                v_4 = v8;
                v8 = 1;
                return v8;
            }
            if (result > 0xDBFF) {
                v9 = 0;
                v_10 = 0;
                result = v_28;
                result -= v10;
                if (result <= 2) {
                    a1 = dst - 40;
                    sub_1400F33A0(a1, v10, 3);
                    v10 = v_18;
                }
                result = v8;
                result &= 63;
                result |= 128;
                v8 >>= 6;
                v8 &= 63;
                v8 |= 128;
                dst2 = (__int64 *)v_20;
                *(dst2 + v10) = 237;
                *(dst2 + v10 + 1) = v8;
                *(dst2 + v10 + 2) = result;
                v10 += 3;
                v_18 = v10;
            }
            if (src == v2) {
                v9 = 0;
                src = (__int64 *)v2;
                return (__int64)src;
            }
            result = *src;
            src += 2;
            a1 = result;
            a1 += 0x2000;
            if (a1 < 0xFC00) {
                v9 = 1;
                v3 = result;
                return v3;
            }
            a1 = result;
            v8 &= 1023;
            a1 &= 1023;
            v8 <<= 26;
            a1 <<= 16;
            a1 |= v8;
            result = 0x100000000;
            a1 += result;
            result = a1;
            result >>= 16;
            v_4 = 0;
            return v_4;
        }
        xmm0 = _mm_loadu_si128((__m128i *)&v_28);
        xmm1 = _mm_loadu_si128((__m128i *)&v_18);
        result = v_30;
        _mm_storeu_si128((__m128i *)(result + 16), xmm1);
        _mm_storeu_si128((__m128i *)result, xmm0);
        return result;
    } while (true);
}