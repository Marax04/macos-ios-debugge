__int64 sub_140011CD4();
__int64 sub_140011CEA();

__int64 __fastcall sub_140011BE0(__int64 a1, int a2, __int64 a3, __int64 a4) {
    __int64 rsp;
    int v_10;
    int v_20;
    int v_30;
    int v_40;
    int v_50;
    __int64 v2;
    int v1;
    __int64 v3;
    int v4;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;
    __m128i xmm8;
    __m128i xmm7;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_50, xmm11);
    _mm_store_si128((__m128i *)&v_40, xmm10);
    _mm_store_si128((__m128i *)&v_30, xmm9);
    _mm_store_si128((__m128i *)&v_20, xmm8);
    _mm_store_si128((__m128i *)&v_10, xmm7);
    _mm_store_si128((__m128i *)&*(__int64 *)rsp, xmm6);
    a3 = a1 + 7;
    a3 &= -8;
    v2 = a3;
    v2 -= a1;
    a2 -= v2;
    v1 = a2;
    v1 &= 7;
    v3 = a3;
    v3 -= a1;
    if ((v3 != 0)) {
        if (v3 >= 4) JUMPOUT(0x140011c4d);
        v4 = 0;
        a4 = 0;
        return sub_140011CD4();
    } else {
        a4 = 0;
        return sub_140011CEA();
    }
}