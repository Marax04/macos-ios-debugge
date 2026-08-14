__int64 sub_140011760();
extern __int64 off_140113FD8;
extern __int64 off_140114EE0;

__int64 __fastcall sub_14002F239() {
    int v_10;
    int v_18;
    int v_30;
    int v_40;
    int v_48;
    int v_50;
    int v_8;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v6;
    __int64 v9;
    __int64 v3;
    __int64 v7;
    __int64 v8;
    __int64 v4;
    __int64 result;
    __int64 v10;
    __int64 *dst;

    v_10 = 1;
    v_8 = 0;
    src = *src;
    xmm0 = _mm_loadu_si128((__m128i *)src);
    xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(src + 32));
    _mm_store_si128((__m128i *)&v_50, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm2);
    _mm_store_si128((__m128i *)&v_40, xmm1);
    v6 = v_48;
    if (v6 != 1) {
    }
    v9 = &off_140113FD8;
    v3 = v10 - 24;
    v7 = v10 - 80;
    sub_140011760(v3, v9, v7);
    xmm0 = _mm_loadu_si128((__m128i *)&v_18);
    _mm_store_si128((__m128i *)&v_50, xmm0);
    v8 = v_8;
    v_40 = v8;
    *(dst + 16) = v8;
    _mm_storeu_si128((__m128i *)dst, xmm0);
    v4 = &off_140114EE0;
    result = (__int64)dst;
    return result;
}