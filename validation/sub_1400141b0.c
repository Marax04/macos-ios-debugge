__int64 sub_1400F3600();
__int64 sub_1400F3869();
__int64 sub_140011760();
__int64 sub_1400F27F0();
extern __int64 off_14010B4D8;

__int64 __fastcall sub_1400141B0(size_t *a1, int *a2, int *a3) {
    int arg_10;
    int arg_20;
    int arg_30;
    int arg_48;
    int arg_50;
    int arg_8;
    int v_10;
    int v_20;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    char *dst;
    __int64 *dst2;
    __m128i xmm0;
    __int64 result;
    __int64 v5;
    __int64 *i;
    __int64 v4;
    __int64 i2;
    __int64 v10;
    __int64 v8;
    __int64 v11;
    __int64 v9;
    __int64 v6;

    dst2 = (__int64 *)a1;
    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&arg_30, xmm0);
    _mm_store_si128((__m128i *)&arg_20, xmm0);
    _mm_store_si128((__m128i *)&arg_10, xmm0);
    _mm_store_si128((__m128i *)&*dst, xmm0);
    _mm_store_si128((__m128i *)&v_10, xmm0);
    _mm_store_si128((__m128i *)&v_20, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm0);
    _mm_store_si128((__m128i *)&v_40, xmm0);
    _mm_store_si128((__m128i *)&v_50, xmm0);
    _mm_store_si128((__m128i *)&v_60, xmm0);
    result = a1[20];
    if (result >= a3) {
        if (result >= 41) {
            v5 = &off_14010B4D8;
            sub_1400F3600(0, result, 40, v5);
        } else {
            a3 = a2 + (__int64)(__int64)a3*4;
            v5 =  + result*4;
            a1 = result + 1;
            arg_50 = (int)a1;
            i = 0;
            v4 = 0;
            while (a2 != a3) {
                i2 = (__int64)i;
                ++i;
                v10 = *a2;
                a2 += 4;
                v8 = 0;
                a1 = (size_t *)i2;
                v11 = 0;
                while (a1 < 40) {
                    v9 = *(dst2 + v8);
                    v6 = *(dst + (__int64)(__int64)a1*4 - 96);
                    v11 += v6;
                    v9 *= v10;
                    v9 += v11;
                    v11 = v9;
                    v11 >>= 32;
                    *(dst + (__int64)(__int64)a1*4 - 96) = v9;
                    ++a1;
                    v8 += 4;
                    a1 = (size_t *)result;
                    if (v11 == 0) {
                        a1 += i2;
                        if (v4 <= a1) v4 = a1;
                    }
                    a1 = i2 + result;
                    if (a1 < 40) {
                        *(dst + (__int64)(__int64)a1*4 - 96) = v11;
                        a1 = (size_t *)arg_50;
                        return (__int64)a1;
                    }
                }
                a3 = &off_14010B4D8;
                sub_1400F3869(a1, 40, a3);
                a3 = (int *)a1;
                a1 = *a2;
                a2 = (int *)arg_8;
                return sub_140011760();
            }
            a2 = dst - 96;
            sub_1400F27F0(dst2, a2, 160, v5);
            *(dst2 + 160) = v4;
            result = (__int64)dst2;
            return result;
        }
    } else {
        result = dst2 + result*4;
        v5 =  + (__int64)(__int64)a3*4;
        a1 = a3 + 1;
        arg_48 = (int)a1;
        i2 = 0;
        i = dst2;
        v4 = 0;
        while (i != result) {
            v10 = i2;
            ++i2;
            v11 = *i;
            i += 4;
            arg_50 = v4;
            v9 = 0;
            a1 = (size_t *)v10;
            v8 = 0;
            while (a1 < 40) {
                v6 = *(a2 + v9);
                v4 = *(dst + (__int64)(__int64)a1*4 - 96);
                v8 += v4;
                v6 *= v11;
                v6 += v8;
                v8 = v6;
                v8 >>= 32;
                *(dst + (__int64)(__int64)a1*4 - 96) = v6;
                ++a1;
                v9 += 4;
                a1 = (size_t *)a3;
                v4 = arg_50;
                if (v8 == 0) {
                    a1 += v10;
                    if (v4 <= a1) v4 = a1;
                }
                a1 = v10 + a3;
                if (a1 < 40) {
                    *(dst + (__int64)(__int64)a1*4 - 96) = v8;
                    a1 = (size_t *)arg_48;
                    return (__int64)a1;
                }
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return result;
}