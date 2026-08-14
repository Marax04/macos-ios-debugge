__int64 sub_140044F10();
__int64 sub_1400F2E20();

__int64 __fastcall sub_1400F2B40(__int64 a1, __int64 a2) {
    int v_30;
    int v_38;
    char *str;
    char *str2;
    __int64 *src;
    __int64 v3;
    __int64 v1;
    __m128i xmm0;

    src = (__int64 *)a2;
    v3 = a1;
    sub_140044F10(str2);
    v1 = *(src + 16);
    v_30 = v1;
    xmm0 = _mm_loadu_si128((__m128i *)src);
    _mm_store_si128((__m128i *)&str, xmm0);
    v_38 = v3;
    return sub_1400F2E20(str);
}