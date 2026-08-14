__int64 sub_1400F37A0();
__int64 sub_1400F3326();
__int64 sub_1400F3410();
__int64 sub_1400F3493();
extern __int64 off_1401120A8;
extern __int64 off_14010AD28;

__int64 __fastcall sub_1400F3360(int *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_8;
    __int64 v12;
    __int64 v6;
    __m128i xmm0;
    __int64 *dst;
    __int64 v7;
    __int64 v9;
    __int64 v4;
    __int64 v2;
    __int64 v10;
    __int64 v8;
    __int64 v11;
    __int64 result;
    __int64 v5;

    v12 = rsp + 80;
    v6 = &off_1401120A8;
    v_30 = v6;
    v_28 = 1;
    v_20 = 8;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_18, xmm0);
    a2 = &off_14010AD28;
    a1 = v12 - 48;
    sub_1400F37A0(a1, a2);
    v12 = rsp + 64;
    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        dst = (__int64 *)a1;
        v7 = *a1;
        v9 = v7 + v7;
        if (a2 > v9) v9 = a2;
        v4 = 8;
        if (v9 >= 9) v4 = v9;
        v2 = *(dst + 8);
        v10 = v12 - 24;
        sub_1400F3410(v10, v7, v2, v4);
        if (v_18 != 1) {
            v8 = v_10;
            *(dst + 8) = v8;
            *dst = v4;
            return result;
        }
    }
    v11 = v_10;
    a2 = v_8;
    sub_1400F3326(v11, a2);
    v12 = rsp + 32;
    dst = (__int64 *)v11;
    v10 = 1;
    if (v5 >= 0) JUMPOUT(0x1400f3436);
    result = 8;
    v4 = 0;
    return sub_1400F3493();
}