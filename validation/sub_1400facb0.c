__int64 sub_140020E30();
__int64 sub_140020C60();
__int64 sub_1400F37D0();
__int64 sub_1400F2C50();
__int64 sub_1400F4640();
extern __int64 off_14008C220;
extern __int64 off_14011B42B;
extern __int64 off_140117360;

__int64 __fastcall sub_1400FACB0(__int64 *a1, int a2, __int64 *a3, __int64 *a4) {
    __int64 rsp;
    int arg_8;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    int v_90;
    int v_98;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    char *str;
    __int64 v3;
    __int64 v6;
    __int64 *dst;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v7;
    __int64 v8;
    __int64 v4;
    __int64 v9;
    __int64 result;

    v3 = (__int64)a3;
    v6 = a2;
    dst = a1;
    a1 = a3 + 272;
    a2 = a3[32];
    v_d0 = (int)a1;
    v_d8 = 0;
    v_e0 = a2;
    v_e8 = 1;
    xmm0 = _mm_loadu_si128((__m128i *)a4);
    xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a4 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(a4 + 48));
    _mm_store_si128((__m128i *)&str, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm1);
    _mm_store_si128((__m128i *)&v_40, xmm2);
    _mm_store_si128((__m128i *)&v_50, xmm3);
    xmm0 = _mm_loadu_si128((__m128i *)(a4 + 64));
    _mm_store_si128((__m128i *)&v_60, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(a4 + 80));
    _mm_store_si128((__m128i *)&v_70, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(a4 + 96));
    _mm_store_si128((__m128i *)&v_80, xmm0);
    a1 = a4[14];
    v_90 = (int)a1;
    v_98 = 0;
    a2 = &off_14008C220;
    sub_140020E30(v6, a2, str);
    v7 = v_d8;
    if (v7 == 3) {
        v8 = v_98;
        xmm0 = _mm_load_si128((__m128i *)&v_a0);
        if (v8 != 1) {
            if (v8 == 2) {
                a1 = _mm_cvtsi128_si64(xmm0);
                xmm0 = _mm_shuffle_epi32(xmm0, 238);
                a2 = _mm_cvtsi128_si64(xmm0);
                sub_140020C60(a1, a2);
            }
            a1 = &off_14011B42B;
            v4 = &off_140117360;
            sub_1400F37D0(a1, 40, v4);
            dst = a1;
            a2 = *a1;
            v9 = a2 + a2;
            v3 = 8;
            if (v9 >= 9) v3 = v9;
            v_28 = 1;
            str = 1;
            a1 = rsp + 48;
            sub_1400F2C50(a1, a2, arg_8, v3);
            if (v_30 == 1) JUMPOUT(0x1400fae6a);
            result = v_38;
            *(dst + 8) = result;
            *dst = v3;
            return result;
        }
        _mm_storeu_si128((__m128i *)dst, xmm0);
        xmm0 = _mm_load_si128((__m128i *)&v_b0);
        xmm1 = _mm_load_si128((__m128i *)&v_c0);
        _mm_storeu_si128((__m128i *)(dst + 16), xmm0);
        _mm_storeu_si128((__m128i *)(dst + 32), xmm1);
        return _mm_cvtsi128_si64(xmm1);
    }
    a2 = rsp + 216;
    sub_1400F4640(v3, a2);
    v8 = v_98;
    xmm0 = _mm_load_si128((__m128i *)&v_a0);
    while (v8 != 1) {
        return _mm_cvtsi128_si64(xmm0);
    }
    return result;
}