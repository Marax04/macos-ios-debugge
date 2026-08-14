__int64 sub_14009BA30();

__int64 __fastcall sub_1400B1E40(__int64 *a1, __int64 a2, int a3, int a4) {
    int v_1a0;
    int v_1a8;
    int v_1b0;
    int v_1b8;
    int v_1c0;
    int v_1c8;
    int v_1d0;
    int v_1d8;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_d8;
    char *str;
    int v10;
    __int64 v4;
    __int64 v3;
    __int64 v9;
    __int64 v7;
    int v2;
    int v6;
    int v8;
    __int64 result;
    __int64 *dst;

    v10 = v_1b0;
    if (v10 >= 16) {
        v_58 = (int)a1;
        v_60 = a3;
        v_50 = a4;
        v4 = v_1d8;
        v3 = v_1d0;
        v9 = v_1c8;
        v7 = v_1c0;
        v2 = v_1b8;
        v6 = v_1a8;
        v8 = v_1a0;
        v_68 = a2;
        sub_14009BA30(str);
        result = (__int64)str;
        result = -result;
        if ((0 /* overflow check on (-result) */)) JUMPOUT(0x1400b1f01);
        result = v_d8;
        dst = (__int64 *)v_58;
        *dst = 8;
        *(dst + 4) = result;
    } else {
        *a1 = 12;
    }
    return result;
}