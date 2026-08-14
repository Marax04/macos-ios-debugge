__int64 sub_1400F44F0();
__int64 sub_1400F3326();
__int64 sub_1400F2C50();

__int64 __fastcall sub_1400F8700(__int64 *a1, int a2) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    __int64 *dst;
    __int64 v6;
    __int64 v4;
    __int64 v5;
    __int64 v8;
    __int64 result;
    __int64 v7;

    dst = a1;
    ++a2;
    v6 = *a1;
    a1 = v6 + v6;
    if (a2 <= a1) a2 = a1;
    v4 = 4;
    if (a2 >= 5) v4 = a2;
    v5 = *(dst + 8);
    a1 = rsp + 32;
    sub_1400F44F0(a1, v6, v5, v4);
    if (v_20 == 1) {
        a1 = (__int64 *)v_28;
        a2 = v_30;
        sub_1400F3326(a1, a2);
        dst = a1;
        a2 = *a1;
        v8 = a2 + a2;
        v4 = 4;
        if (v8 >= 5) v4 = v8;
        v_28 = 36;
        v_20 = 4;
        a1 = rsp + 48;
        sub_1400F2C50(a1, a2, arg_8, v4);
        if (v_30 == 1) JUMPOUT(0x1400f87ca);
        result = v_38;
        *(dst + 8) = result;
        *dst = v4;
        return result;
    } else {
        v7 = v_28;
        *(dst + 8) = v7;
        *dst = v4;
        return result;
    }
}