__int64 off_140108098();
extern __int64 off_1401136E0;

int __fastcall sub_140038B40() {
    int v_10;
    int v_20;
    int v_30;
    char *str;
    __m128i xmm0;
    __int64 v2;
    int result;
    __int64 v3;

    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&v_10, xmm0);
    _mm_store_si128((__m128i *)&v_20, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm0);
    v2 = str - 48;
    off_140108098(v2);
    v2 = v_10;
    result = 0;
    result = (v2 == 0) ? 1 : 0;
    v3 = &off_1401136E0;
    if (v2 != 0) v3 = v2;
    return result;
}