__int64 sub_140011760();
__int64 sub_1400F3B80();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14010AD40;
extern __int64 off_14010AC40;
extern __int64 off_140112520;
extern __int64 off_14010AC00;

__int64 __fastcall sub_14000F0EF() {
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    __int64 v4;
    __int64 v3;
    __int64 result;
    __int64 v9;
    __int64 v8;
    __int64 v7;
    __int64 v12;
    __int64 v10;
    __int64 v2;
    __m128i xmm0;
    __int64 v11;
    __int64 v6;
    __int64 *dst;

    if (v11 != 1) {
    }
    v4 = &off_14010AD40;
    v3 = v12 - 40;
    sub_140011760(v3, v4, v6);
    if (result != 0) {
        result = &off_14010AC40;
        v_20 = result;
        v9 = &off_140112520;
        v8 = &off_14010AC00;
        v7 = v12 - 9;
        sub_1400F3B80(v9, 86, v7, v8);
        v_10 = v4;
        v12 = v4 + 80;
        if (v_28 != 0) {
            v10 = v_20;
            off_140108030();
            off_140108038(result, 0, v10);
        }
        return v10;
    } else {
        v2 = v_18;
        *(dst + 16) = v2;
        xmm0 = _mm_loadu_si128((__m128i *)&v_28);
        _mm_storeu_si128((__m128i *)dst, xmm0);
        return result;
    }
}