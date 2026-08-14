__int64 off_140108370();
__int64 off_140108068();
extern __int64 off_140112D18;

__int64 __fastcall sub_140031510(__int64 a1, int a2, __int64 a3, __int64 a4) {
    int arg_8;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    char *src;
    __int64 v2;
    __m128i xmm0;
    __int64 result;

    v2 = a1;
    xmm0 = _mm_loadu_si128((__m128i *)&off_140112D18);
    _mm_store_si128((__m128i *)&*src, xmm0);
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_38, xmm0);
    v_28 = a2;
    v_20 = (__int64)src;
    v_30 = 32;
    off_140108370(a1, 0, 0, 0);
    if (result == 259) {
        off_140108068(v2, 0xFFFFFFFF);
        result = *src;
    }
    if (result != 0xC0000011) {
        if (result == 259) JUMPOUT(0x1400315cc);
        if (result < 0) JUMPOUT(0x140031598);
        a2 = arg_8;
    } else {
        a2 = 0;
    }
    result = 0;
    return result;
}