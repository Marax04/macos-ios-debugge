__int64 sub_1400F6940();
__int64 sub_1400F3326();
__int64 sub_1400F69F2();

__int64 __fastcall sub_1400F68D0(__int64 *a1) {
    __int64 rsp;
    int arg_60;
    int arg_68;
    int arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    __int64 v13;
    __int64 *dst;
    __int64 v3;
    __int64 v2;
    __int64 v5;
    __int64 v12;
    __int64 v9;
    __int64 v10;
    __int64 result;
    int v11;
    __int64 v8;
    __int64 v7;

    v13 = rsp + 80;
    dst = a1;
    v3 = *a1;
    v2 = v3 + v3;
    v5 = 4;
    if (v2 >= 5) v5 = v2;
    v_28 = 2;
    v_20 = 2;
    a1 = v13 - 24;
    sub_1400F6940(a1, v3, arg_8, v5);
    if (v_18 == 1) {
        a1 = (__int64 *)v_10;
        v3 = v_8;
        sub_1400F3326(a1, v3);
        v13 = rsp + 32;
        dst = a1;
        v12 = arg_60;
        v9 = arg_68;
        a1 = v12 + v9;
        --a1;
        v10 = v12;
        v10 = -v10;
        v10 &= (__int64)a1;
        v10 *= v7; /* unsigned; high half in v3 */;
        v5 = v10;
        result = (0 /* overflow check on (v10 & (__int64)a1) */) ? 1 : 0;
        a1 = 0x8000000000000000;
        a1 -= v12;
        a1 = (v5 > a1) ? 1 : 0;
        a1 = (__int64 *)((__int64)(__int64)a1 | result);
        v11 = 1;
        if ((a1 == 0)) JUMPOUT(0x1400f699e);
        result = 8;
        v5 = 0;
        return sub_1400F69F2();
    } else {
        v8 = v_10;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}