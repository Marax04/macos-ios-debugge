__int64 sub_140044F10();
__int64 sub_1400F3050();
extern __int64 off_1401091C8;

__int64 __fastcall sub_1400F2A80(__int64 a1) {
    int v_30;
    int v_38;
    int v_48;
    int v_58;
    int v_68;
    int v_78;
    int v_88;
    char *str;
    char *str2;
    __int64 v2;
    __int64 v1;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    v2 = a1;
    sub_140044F10(str2);
    v1 = &off_1401091C8;
    str = (char *)v1;
    v_30 = 26;
    xmm0 = _mm_loadu_si128((__m128i *)v2);
    xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(v2 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(v2 + 48));
    _mm_storeu_si128((__m128i *)&v_38, xmm0);
    _mm_storeu_si128((__m128i *)&v_48, xmm1);
    _mm_storeu_si128((__m128i *)&v_58, xmm2);
    _mm_storeu_si128((__m128i *)&v_68, xmm3);
    xmm0 = _mm_loadu_si128((__m128i *)(v2 + 64));
    _mm_storeu_si128((__m128i *)&v_78, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(v2 + 80));
    _mm_storeu_si128((__m128i *)&v_88, xmm0);
    return sub_1400F3050(str);
}