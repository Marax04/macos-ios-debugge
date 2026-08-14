__int64 sub_1400F2C50();
__int64 sub_1400F3326();
__int64 sub_1400F44F0();

__int64 __fastcall sub_1400F8690(__int64 *a1) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    __int64 *dst;
    __int64 i;
    __int64 v7;
    __int64 v5;
    __int64 v9;
    __int64 v2;
    __int64 result;
    __int64 v8;

    dst = a1;
    i = *a1;
    v7 = i + i;
    v5 = 4;
    if (v7 >= 5) v5 = v7;
    v_28 = 344;
    v_20 = 8;
    a1 = rsp + 48;
    sub_1400F2C50(a1, i, arg_8, v5);
    if (v_30 == 1) {
        a1 = (__int64 *)v_38;
        i = v_40;
        sub_1400F3326(a1, i);
        dst = a1;
        ++i;
        v9 = *a1;
        a1 = v9 + v9;
        if (i <= a1) i = a1;
        v5 = 4;
        if (i >= 5) v5 = i;
        v2 = *(dst + 8);
        a1 = rsp + 32;
        sub_1400F44F0(a1, v9, v2, v5);
        if (v_20 == 1) JUMPOUT(0x1400f8755);
        result = v_28;
        *(dst + 8) = result;
        *dst = v5;
        return result;
    } else {
        v8 = v_38;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}