__int64 sub_1400F27F6();
extern __int64 off_1401086B0;

__int64 __fastcall sub_1400F9EAA(int a1, int a2, int a3, __int64 a4) {
    int v_20;
    int v_28;
    __m128i xmm0;
    __int64 result;
    __int64 v4;
    __int64 *dst;
    __int64 *v3;
    __int64 v7;
    __int64 v5;
    __int64 v6;

    a2 -= 2;
    if ((a2 != 0)) JUMPOUT(0x1400f9e80);
    if ((result & 1) != 0) {
        xmm0 = _mm_setzero_si128();
        xmm0 = _mm_cmpgt_epi8(xmm0, *(v3 + a1));
        xmm0 = _mm_or_si128(xmm0, _mm_load_si128((__m128i *)&off_1401086B0));
        _mm_store_si128((__m128i *)(v3 + a1), xmm0);
    }
    a1 = v5;
    if (v5 < 16) {
        a1 = 16;
        a3 = v5;
    }
    a1 += (__int64)v3;
    sub_1400F27F6(a1, v3, 16);
    result = v3 - 16;
    v4 = 1;
    a1 = 0;
    a3 = 0;
    do {
        v4 = a3;
        v4 += 0;
    } while (a3 < v5);
    if (v6 < 8) v7 = v6;
    dst = (__int64 *)v_28;
    v3 = (__int64 *)v_20;
    v7 -= (__int64)v3;
    *(dst + 16) = v7;
    result = 0x8000000000000001;
    return result;
}