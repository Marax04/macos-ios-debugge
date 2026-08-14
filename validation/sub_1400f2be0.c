__int64 sub_1400F2C50();
__int64 sub_1400F3326();
__int64 sub_1400F2CFE();

__int64 __fastcall sub_1400F2BE0(__int64 *a1) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_70;
    int v_78;
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

    dst = a1;
    v3 = *a1;
    v2 = v3 + v3;
    v5 = 4;
    if (v2 >= 5) v5 = v2;
    v_28 = 64;
    v_20 = 8;
    a1 = rsp + 48;
    sub_1400F2C50(a1, v3, arg_8, v5);
    if (v_30 == 1) {
        a1 = (__int64 *)v_38;
        v3 = v_40;
        sub_1400F3326(a1, v3);
        dst = a1;
        v12 = v_70;
        v9 = v_78;
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
        if ((a1 == 0)) JUMPOUT(0x1400f2caa);
        result = 8;
        v5 = 0;
        return sub_1400F2CFE();
    } else {
        v8 = v_38;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}