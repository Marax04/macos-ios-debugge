__int64 sub_140058580();
__int64 sub_1400F8440();

__int64 __fastcall sub_14004F500(__int64 *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int v_28;
    __int64 v_38;
    int v_40;
    int v_50;
    int v_60;
    __int64 *v_10;
    char *str;
    __int64 *i;
    __int64 *dst;
    __int64 result;
    __int64 v7;
    __int64 v2;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __int64 i2;
    __int64 i3;

    i = (__int64 *)a2;
    dst = a1;
    sub_140058580(a1, a3);
    result = *a1;
    if (result != 3) {
        v7 = 2;
        if (result != 1) v7 = result;
        result = *(dst + 8);
        v2 = dst + 16;
        if (v7 != 0) {
            src = i + 24;
            if (v7 != 1) {
                v_28 = result;
                xmm0 = _mm_loadu_si128((__m128i *)v2);
                xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
                _mm_storeu_si128((__m128i *)&str, xmm0);
                _mm_storeu_si128((__m128i *)&v_40, xmm1);
                i2 = v_38;
                if (i2 == result) JUMPOUT(0x14004f6e8);
                a1 = (__int64 *)str;
                a2 =  + i2*2;
                a2 += i2;
                a3 = *(i + 16);
                v_10[a2] = a3;
                xmm0 = _mm_loadu_si128((__m128i *)i);
                _mm_storeu_si128((__m128i *)(a1 + a2*8), xmm0);
                ++i2;
                v_38 = i2;
                xmm0 = _mm_loadu_si128((__m128i *)str);
                xmm1 = _mm_loadu_si128((__m128i *)(str + 16));
                _mm_store_si128((__m128i *)&v_50, xmm0);
                _mm_store_si128((__m128i *)&v_60, xmm1);
                *dst = 2;
            } else {
                v_28 = result;
                xmm0 = _mm_loadu_si128((__m128i *)v2);
                xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
                _mm_storeu_si128((__m128i *)&str, xmm0);
                _mm_storeu_si128((__m128i *)&v_40, xmm1);
                i3 = v_38;
                if (i3 == result) {
                    a1 = rsp + 40;
                    sub_1400F8440(a1);
                    result = v_28;
                }
                a1 = (__int64 *)str;
                a2 =  + i3*2;
                a2 += i3;
                a3 = *(i + 16);
                v_10[a2] = a3;
                xmm0 = _mm_loadu_si128((__m128i *)i);
                _mm_storeu_si128((__m128i *)(a1 + a2*8), xmm0);
                ++i3;
                v_38 = i3;
                xmm0 = _mm_loadu_si128((__m128i *)str);
                xmm1 = _mm_loadu_si128((__m128i *)(str + 16));
                _mm_store_si128((__m128i *)&v_50, xmm0);
                _mm_store_si128((__m128i *)&v_60, xmm1);
                *dst = 1;
            }
            *(dst + 8) = result;
            xmm0 = _mm_load_si128((__m128i *)&v_50);
            xmm1 = _mm_load_si128((__m128i *)&v_60);
            _mm_storeu_si128((__m128i *)(v2 + 16), xmm1);
            _mm_storeu_si128((__m128i *)v2, xmm0);
            v_28 = result;
            xmm0 = _mm_loadu_si128((__m128i *)v2);
            xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
            _mm_storeu_si128((__m128i *)&str, xmm0);
            _mm_storeu_si128((__m128i *)&v_40, xmm1);
            i = (__int64 *)v_38;
            if (i == result) {
                a1 = rsp + 40;
                sub_1400F8440(a1, a2, a3);
                result = v_28;
            }
            a1 = (__int64 *)str;
            a2 = i + (__int64)(__int64)i*2;
            a3 = *(src + 16);
            v_10[a2] = a3;
            xmm0 = _mm_loadu_si128((__m128i *)src);
            _mm_storeu_si128((__m128i *)(a1 + a2*8), xmm0);
            ++i;
            v_38 = (__int64)i;
            xmm0 = _mm_loadu_si128((__m128i *)str);
            xmm1 = _mm_loadu_si128((__m128i *)(str + 16));
            _mm_store_si128((__m128i *)&v_50, xmm0);
            _mm_store_si128((__m128i *)&v_60, xmm1);
        }
        *dst = v7;
        *(dst + 8) = result;
        xmm0 = _mm_load_si128((__m128i *)&v_50);
        xmm1 = _mm_load_si128((__m128i *)&v_60);
        _mm_storeu_si128((__m128i *)(v2 + 16), xmm1);
        _mm_storeu_si128((__m128i *)v2, xmm0);
    }
    return result;
}