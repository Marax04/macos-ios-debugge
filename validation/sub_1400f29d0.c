__int64 sub_140044F10();
__int64 sub_1400F31D0();
extern __int64 off_14010961F;

__int64 __fastcall sub_1400F29D0(__int64 a1) {
    int v_28;
    int v_30;
    int v_40;
    int v_50;
    char *str;
    char *str2;
    __int64 *src;
    __int64 v1;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v2;

    src = (__int64 *)a1;
    sub_140044F10(str2);
    v1 = &off_14010961F;
    str = (char *)v1;
    v_28 = 45;
    xmm0 = _mm_loadu_si128((__m128i *)src);
    xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
    _mm_storeu_si128((__m128i *)&v_30, xmm0);
    _mm_storeu_si128((__m128i *)&v_40, xmm1);
    v2 = *(src + 32);
    v_50 = v2;
    return sub_1400F31D0(str);
}