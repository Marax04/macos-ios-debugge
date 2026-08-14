__int64 sub_1400F3600();
__int64 sub_1400B1EED();
__int64 sub_14006C3D0();
__int64 sub_14006C500();
extern __int64 off_14011AA30;
extern __int64 off_14011B7A0;
extern __int64 off_14011B7B0;

__int64 __fastcall sub_1400B1D80(__int64 a1, __int64 a2, int a3, __int64 a4) {
    int v_1b0;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    int v_d0;
    int v_d8;
    char *str;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v4;
    __int64 *dst;
    __int64 v3;
    __int64 v1;
    int v6;

    v2 = a1;
    if (a2 == 0) {
        xmm0 = _mm_loadu_si128((__m128i *)a4);
        xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
        _mm_storeu_si128((__m128i *)(v2 + 16), xmm1);
        _mm_storeu_si128((__m128i *)v2, xmm0);
        return _mm_cvtsi128_si64(xmm1);
    } else {
        v4 = a3;
        dst = (__int64 *)v_d0;
        a3 = v_d8;
        v3 = dst + a3;
        if (v3 > v4) {
            v1 = &off_14011AA30;
            sub_1400F3600(dst, v3, v4, v1);
            v6 = v_1b0;
            if (v6 >= 16) JUMPOUT(0x1400b1e6a);
            *dst = 12;
            return sub_1400B1EED();
        } else {
            a2 += (__int64)dst;
            xmm0 = _mm_setzero_si128();
            _mm_store_si128((__m128i *)&v_50, xmm0);
            _mm_store_si128((__m128i *)&v_40, xmm0);
            _mm_store_si128((__m128i *)&v_30, xmm0);
            _mm_store_si128((__m128i *)&str, xmm0);
            xmm1 = _mm_loadu_si128((__m128i *)&off_14011B7A0);
            _mm_store_si128((__m128i *)&v_60, xmm1);
            xmm1 = _mm_loadu_si128((__m128i *)&off_14011B7B0);
            _mm_store_si128((__m128i *)&v_70, xmm1);
            _mm_store_si128((__m128i *)&v_80, xmm0);
            sub_14006C3D0(str, a2, a3);
            sub_14006C500(v2, str);
            return _mm_cvtsi128_si64(xmm1);
        }
    }
}