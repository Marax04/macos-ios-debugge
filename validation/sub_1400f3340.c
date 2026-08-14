__int64 sub_14002F4B0();
__int64 sub_1400F37A0();
__int64 sub_1400F3326();
__int64 sub_1400F3410();
__int64 sub_1400F3493();
extern __int64 off_1401120A8;
extern __int64 off_14010AD28;

__int64 __fastcall sub_1400F3340(int *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_8;
    __int64 v11;
    __int64 v7;
    __m128i xmm0;
    __int64 *dst;
    __int64 v8;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    int v10;
    __int64 result;
    __int64 v5;

    sub_14002F4B0(a2, a1);
    v11 = rsp + 80;
    v7 = &off_1401120A8;
    v_30 = v7;
    v_28 = 1;
    v_20 = 8;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_18, xmm0);
    a2 = &off_14010AD28;
    a1 = v11 - 48;
    sub_1400F37A0(a1, a2);
    v11 = rsp + 64;
    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        dst = (__int64 *)a1;
        v8 = *a1;
        a1 = v8 + v8;
        if (a2 > a1) a1 = a2;
        v4 = 8;
        if (a1 >= 9) v4 = a1;
        v2 = *(dst + 8);
        a1 = v11 - 24;
        sub_1400F3410(a1, v8, v2, v4);
        if (v_18 != 1) {
            v9 = v_10;
            *(dst + 8) = v9;
            *dst = v4;
            return result;
        }
    }
    a1 = (int *)v_10;
    a2 = v_8;
    sub_1400F3326(a1, a2);
    v11 = rsp + 32;
    dst = (__int64 *)a1;
    v10 = 1;
    if (v5 >= 0) JUMPOUT(0x1400f3436);
    result = 8;
    v4 = 0;
    return sub_1400F3493();
}