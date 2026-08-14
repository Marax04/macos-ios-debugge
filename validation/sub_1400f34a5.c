__int64 sub_1400F37A0();
__int64 sub_1400F3410();
__int64 sub_1400F3326();
__int64 sub_1400FB190();
extern __int64 off_14010AC80;
extern __int64 off_140018400;

__int64 __fastcall sub_1400F34A5(int *a1, __int64 *a2, __int64 a3) {
    __int64 rsp;
    __int64 arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    __int64 v7;
    __int64 *result;
    __int64 *dst;
    __int64 *dst2;
    __int64 v4;
    __int64 v2;
    __int64 v6;

    v7 = rsp + 128;
    result = v7 - 8;
    *result = a1;
    dst = v7 - 16;
    *dst = a2;
    a2 = v7 - 48;
    *a2 = result;
    result = &off_14010AC80;
    a1 = v7 - 96;
    *a1 = result;
    result = &off_140018400;
    arg_8 = (__int64)result;
    arg_8 = 3;
    a1[4] = a1[4] & 0;
    a2[2] = dst;
    a2[3] = result;
    a1[2] = a2;
    a1[3] = 2;
    sub_1400F37A0(a1, a3, a3, dst);
    v7 = rsp + 64;
    dst2 = (__int64 *)a1;
    a2 = *a1;
    result = (__int64)a2 + (__int64)a2;
    v4 = 8;
    if (result >= 9) v4 = result;
    v2 = arg_8;
    a1 = v7 - 24;
    sub_1400F3410(a1, a2, v2, v4);
    if (v_18 == 1) {
        a1 = (int *)v_10;
        a2 = (__int64 *)v_8;
        sub_1400F3326(a1, a2);
        a2 += v2;
        if ((a2 < 0)) JUMPOUT(0x1400f35c7);
        dst2 = (__int64 *)a1;
        result = *a1;
        a1 = (__int64)result + (__int64)result;
        if (a2 > a1) a1 = a2;
        v4 = 8;
        if (a1 >= 9) v4 = a1;
        v6 = *(dst2 + 8);
        a1 = rsp + 32;
        sub_1400FB190(a1, result, v6, v4);
        if (v_20 == 1) JUMPOUT(0x1400f35ce);
        result = (__int64 *)v_28;
        *(dst2 + 8) = result;
        *dst2 = v4;
        return (__int64)result;
    } else {
        result = (__int64 *)v_10;
        *(dst2 + 8) = result;
        *dst2 = v4;
        return (__int64)result;
    }
}