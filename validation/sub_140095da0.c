__int64 sub_140095EA0();

__int64 __fastcall sub_140095DA0(size_t a1, size_t a2, __int64 a3, __int64 a4) {
    __int64 __rdx_rax;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_60;
    int v_68;
    int v_78;
    __int64 v9;
    __int64 v2;
    __int64 v3;
    __int64 v4;
    int v1;
    __int64 v5;
    int v10;
    __int64 v7;
    int v8;
    __int64 v6;

    v9 = a2;
    v_40 = a1;
    v2 = 0x4000000000000000;
    a2 = 0;
    v3 = __rdx_rax / v9; a2 = __rdx_rax % v9; /* unsigned */;
    v3 += 1;
    v_78 = v3;
    v4 = v9;
    if (v9 >= 0x1001) {
        v4 |= 1;
        a1 = 63 - __builtin_clzll(v4);
        v1 = a1;
        v1 >>= 1;
        a1 &= 1;
        a1 += v1;
        v1 = 1;
        v4 <<= a1;
        a2 = v9;
        a2 >>= a1;
        a2 += v4;
        a2 >>= 1;
        v_48 = a2;
    } else {
        v4 >>= 1;
        a1 = v9;
        a1 -= v4;
        v1 = 64;
        if (a1 < 64) v4 = a1;
        v_48 = v4;
    }
    v5 = v_40;
    a1 = v5 + 32;
    v_60 = a1;
    v5 -= 16;
    v_68 = v5;
    v10 = 1;
    v7 = 0;
    v8 = 0;
    v_38 = a4;
    v_30 = a3;
    v_50 = v9;
    v6 = v9;
    v6 -= v7;
    if ((v6 <= 0)) JUMPOUT(0x140095e87);
    return sub_140095EA0();
}