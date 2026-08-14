__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_140031B30();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400384F0(int a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 rsp;
    int arg_60;
    int v_10;
    int v_18;
    int v_20;
    int v_8;
    __int64 *dst;
    __int64 v4;
    __int64 v2;
    __int64 v3;
    __int64 v8;
    __int64 v9;
    __int64 v7;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v1;

    dst = rsp + 64;
    *dst = -2;
    if (a3 < 0) {
        sub_1400F3360();
    }
    v4 = a4;
    v2 = a3;
    v3 = a1;
    if ((0 /* unresolved: flags == */)) {
        v8 = 1;
    } else {
        v9 = a2;
        sub_14002EDF0(0, v2);
        if (v1 == 0) {
            sub_1400F3326(1, v2);
            v_10 = v2;
            dst = v2 + 64;
            if (v_20 != 0) {
                v7 = v_18;
                off_140108030();
                off_140108038(v1, 0, v7);
            }
            return v7;
        } else {
            v8 = v1;
        }
    }
    v5 = arg_60;
    sub_1400F27F0(v8, v5, v2);
    v_20 = v2;
    v_18 = v8;
    v_10 = v2;
    v_8 = 0;
    v6 = dst - 32;
    sub_140031B30(v6, v4, v5);
    xmm0 = _mm_loadu_si128((__m128i *)&v_20);
    xmm1 = _mm_loadu_si128((__m128i *)&v_10);
    _mm_storeu_si128((__m128i *)(v3 + 16), xmm1);
    _mm_storeu_si128((__m128i *)v3, xmm0);
    return _mm_cvtsi128_si64(xmm1);
}