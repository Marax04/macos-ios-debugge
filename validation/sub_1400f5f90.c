__int64 sub_1400F3326();
__int64 sub_1400F2C50();

__int64 __fastcall sub_1400F5F90(int *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    __int64 *dst;
    __int64 v6;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v8;
    __int64 result;

    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        dst = (__int64 *)a1;
        v6 = *a1;
        a1 = v6 + v6;
        if (a2 > a1) a1 = a2;
        v4 = 8;
        if (a1 >= 9) v4 = a1;
        v2 = *(dst + 8);
        v_28 = 1;
        v_20 = 1;
        a1 = rsp + 48;
        sub_1400F2C50(a1, v6, v2, v4);
        if (v_30 != 1) {
            v7 = v_38;
            *(dst + 8) = v7;
            *dst = v4;
            return v7;
        }
    }
    a1 = (int *)v_38;
    a2 = v_40;
    sub_1400F3326(a1, a2);
    dst = (__int64 *)a1;
    a2 = *a1;
    v8 = a2 + a2;
    v4 = 4;
    if (v8 >= 5) v4 = v8;
    v_28 = 32;
    v_20 = 8;
    a1 = rsp + 48;
    sub_1400F2C50(a1, a2, arg_8, v4);
    if (v_30 == 1) JUMPOUT(0x1400f606a);
    result = v_38;
    *(dst + 8) = result;
    *dst = v4;
    return result;
}