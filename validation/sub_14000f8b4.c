__int64 sub_14000F995();

__int64 __fastcall sub_14000F8B4(size_t a1, __int64 a2, __int64 a3) {
    int v_10;
    int v_4;
    __int64 v2;
    int v8;
    int v7;
    __int64 v6;
    __int64 *src;
    int v1;
    __int64 v3;
    __int64 v5;

    v_10 = 1;
    v2 = src + a3*2;
    v8 = 0;
    v7 = 0;
    if ((v7 & 1) == 0) {
        if (src == v2) JUMPOUT(0x14000fac5);
        v6 = *src;
        src += 2;
    } else {
        v6 = v3;
    }
    a1 = v6;
    a1 &= 0xF800;
    v1 = v6;
    if (a1 != 0xD800) JUMPOUT(0x14000f970);
    if (v1 > 0xDBFF) JUMPOUT(0x14000fa3b);
    if (src == v2) JUMPOUT(0x14000fa40);
    v1 = *src;
    src += 2;
    a1 = v1;
    a1 += 0x2000;
    if (a1 < 0xFC00) JUMPOUT(0x14000fa48);
    a1 = v1;
    v6 &= 1023;
    a1 &= 1023;
    v6 <<= 26;
    a1 <<= 16;
    a1 |= v6;
    v3 = 0x100000000;
    a1 += v3;
    v5 = a1;
    v5 >>= 16;
    v_4 = 0;
    return sub_14000F995();
}