__int64 sub_14006C3D0();
__int64 sub_14006C500();
extern __int64 off_14011B7A0;
extern __int64 off_14011B7B0;

void __fastcall sub_14006D3C0(__int64 a1) {
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    char *str;
    __int64 v1;
    __m128i xmm0;
    __m128i xmm1;

    v1 = a1;
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
    sub_14006C3D0(str);
    sub_14006C500();
}