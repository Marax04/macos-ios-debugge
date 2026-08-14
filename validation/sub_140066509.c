__int64 sub_1400679E0();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_140066FB9();

__int64 __fastcall sub_140066509(size_t a1, int a2, int a3, int a4) {
    __int64 rsp;
    int v_180;
    int v_28;
    int v_30;
    int v_50;
    int v_58;
    int v_60;
    int v_88;
    int v_a8;
    int v_b0;
    int v_b8;
    __int64 v_c0;
    int v_c8;
    char *str;
    char *str2;
    __int64 *dst;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v4;
    __int64 v3;
    __int64 v2;

    dst = (__int64 *)((__int64)(__int64)dst & 88);
    *dst = *dst + (__int64)dst;
    *dst = *dst + (__int64)dst;
    v_60 = 0;
    str2 = (char *)v2;
    v_a8 = a1;
    v_b0 = 0;
    v_180 = a1;
    v_b8 = a1;
    dst = 0x5F0000005F;
    v_c0 = (__int64)dst;
    v_c8 = 1;
    v5 = 1;
    v6 = 0;
    v7 = 0;
    sub_1400679E0(str, str2);
    while (str == 1) {
        v4 = v_28;
        v3 = v_30;
        v4 -= v7;
        dst = (__int64 *)v_50;
        dst -= v6;
        if (v4 > dst) {
            a1 = rsp + 80;
            sub_1400F5F90(a1, v6, v4);
            v5 = v_58;
            v6 = v_60;
        }
        v7 += v2;
        a1 = v5 + v6;
        sub_1400F27F0(a1, v7, v4);
        v6 += v4;
        v_60 = v6;
        v7 = v3;
    }
    a3 = v_180;
    a3 -= v7;
    dst = (__int64 *)v_50;
    dst -= v6;
    if (a3 > dst) JUMPOUT(0x1400674d9);
    v4 = v_88;
    v2 += v7;
    a1 = v5 + v6;
    v2 = a3;
    sub_1400F27F0(a1, v2, a3);
    v6 += v2;
    a1 = rsp + 288;
    a2 = v5;
    a3 = v6;
    a4 = 8;
    return sub_140066FB9();
}