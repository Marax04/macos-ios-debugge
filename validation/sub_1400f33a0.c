__int64 sub_1400F3326();
__int64 sub_1400F3410();
__int64 sub_1400F3493();

__int64 __fastcall sub_1400F33A0(int *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_8;
    __int64 v12;
    __int64 *dst;
    __int64 v6;
    __int64 v8;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    __int64 v7;
    __int64 v10;
    __int64 result;
    __int64 v5;

    v12 = rsp + 64;
    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        dst = (__int64 *)a1;
        v6 = *a1;
        v8 = v6 + v6;
        if (a2 > v8) v8 = a2;
        v4 = 8;
        if (v8 >= 9) v4 = v8;
        v2 = *(dst + 8);
        v9 = v12 - 24;
        sub_1400F3410(v9, v6, v2, v4);
        if (v_18 != 1) {
            v7 = v_10;
            *(dst + 8) = v7;
            *dst = v4;
            return result;
        }
    }
    v10 = v_10;
    sub_1400F3326(v10, v_8);
    v12 = rsp + 32;
    dst = (__int64 *)v10;
    v10 = 1;
    if (v5 >= 0) JUMPOUT(0x1400f3436);
    result = 8;
    v4 = 0;
    return sub_1400F3493();
}