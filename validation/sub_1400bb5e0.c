__int64 sub_1400BB6F0();

__int64 __fastcall sub_1400BB5E0(size_t a1, size_t a2, __int64 a3, __int64 a4) {
    __int64 __rdx_rax;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_58;
    int v_60;
    int v_68;
    int v_78;
    __int64 v7;
    __int64 v2;
    __int64 v3;
    __int64 v4;
    int v1;
    __int64 v6;
    int v10;
    __int64 v8;
    int v9;
    __int64 v5;

    v7 = a2;
    v_40 = a1;
    v2 = 0x4000000000000000;
    a2 = 0;
    v3 = __rdx_rax / v7; a2 = __rdx_rax % v7; /* unsigned */;
    v3 += 1;
    v_78 = v3;
    v4 = v7;
    if (v7 >= 0x1001) {
        v4 |= 1;
        a1 = 63 - __builtin_clzll(v4);
        v1 = a1;
        v1 >>= 1;
        a1 &= 1;
        a1 += v1;
        v1 = 1;
        v4 <<= a1;
        a2 = v7;
        a2 >>= a1;
        a2 += v4;
        a2 >>= 1;
        v_48 = a2;
    } else {
        v4 >>= 1;
        a1 = v7;
        a1 -= v4;
        v1 = 64;
        if (a1 < 64) v4 = a1;
        v_48 = v4;
    }
    v6 = v_40;
    a1 = v6 + 32;
    v_58 = a1;
    v6 -= 16;
    v_68 = v6;
    v10 = 1;
    v8 = 0;
    v9 = 0;
    v_38 = a4;
    v_30 = a3;
    v_60 = v7;
    v5 = v7;
    v5 -= v8;
    if ((v5 <= 0)) JUMPOUT(0x1400bb6c9);
    return sub_1400BB6F0();
}