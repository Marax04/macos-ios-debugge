__int64 sub_1400F3410();
__int64 sub_1400F3326();
__int64 sub_1400FB190();

__int64 __fastcall sub_1400F3510(int *a1) {
    __int64 rsp;
    int arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    char *str;
    __int64 *dst;
    __int64 v3;
    __int64 v7;
    __int64 v5;
    __int64 v6;
    __int64 v9;
    __int64 v2;
    __int64 result;
    __int64 v8;

    dst = (__int64 *)a1;
    v3 = *a1;
    v7 = v3 + v3;
    v5 = 8;
    if (v7 >= 9) v5 = v7;
    v6 = arg_8;
    a1 = str - 24;
    sub_1400F3410(a1, v3, v6, v5);
    if (v_18 == 1) {
        a1 = (int *)v_10;
        v3 = v_8;
        sub_1400F3326(a1, v3);
        v3 += v6;
        if ((v3 < 0)) JUMPOUT(0x1400f35c7);
        dst = (__int64 *)a1;
        v9 = *a1;
        a1 = v9 + v9;
        if (v3 > a1) a1 = v3;
        v5 = 8;
        if (a1 >= 9) v5 = a1;
        v2 = *(dst + 8);
        a1 = rsp + 32;
        sub_1400FB190(a1, v9, v2, v5);
        if (v_20 == 1) JUMPOUT(0x1400f35ce);
        result = v_28;
        *(dst + 8) = result;
        *dst = v5;
        return result;
    } else {
        v8 = v_10;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}