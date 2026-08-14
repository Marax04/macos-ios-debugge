__int64 sub_14006BD50();
__int64 sub_14006BFD0();
__int64 sub_1400AFD9D();
extern __int64 off_14011A9E8;

__int64 __fastcall sub_1400AFA20(size_t a1, int a2, int a3) {
    int v_20;
    int v_29;
    int v_2a;
    int v_2b;
    int v_2c;
    int v_2d;
    int v_30;
    char *str;
    char *str2;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    __int64 v1;
    int v7;
    __int64 v6;
    int v2;

    v3 = a3;
    v4 = a2;
    str = (char *)a1;
    v_20 = 23;
    v5 = &off_14011A9E8;
    sub_14006BD50(str2, str, 8, v5);
    v_30 = 0;
    str = 0;
    v_20 = 9;
    sub_14006BFD0(str2, v4, v3, str);
    a3 = (int)str;
    v1 = a3 * 205;
    v1 >>= 10;
    a1 = v_29;
    a1 &= 3;
    a2 = v_2a;
    v5 = a2 * 57;
    v5 >>= 9;
    v5 &= 0xFFFFFFFC;
    v5 = str + (__int64)(__int64)str*8;
    v7 = a2;
    v7 -= v5;
    v5 = 97;
    v6 = 22;
    if (v7 < 26) v6 = v5;
    v6 += v7;
    if (v6 <= 96) {
        v5 = a2;
        v5 *= 79;
        v5 >>= 11;
        v6 = str + (__int64)(__int64)str*4;
        v7 = v6 + v6*4;
        v7 += v5;
        v6 = a2;
        v6 -= v7;
        v6 += 97;
    }
    v5 = v1 + v1*4;
    v1 = v6 - 32;
    if (a1 >= 2) {
        if (!((0 /* unresolved: flags == */))) {
            /* test a2 , a2 */;
            a2 = v1;
            v1 = v6;
            if (0 /* unresolved: flags < 0 */) v6 = a2;
        }
    } else {
        v1 = v6;
    }
    v3 = v_2b;
    a2 = v3 * 57;
    a2 >>= 9;
    a2 &= 0xFFFFFFFC;
    a2 = str + (__int64)(__int64)str*8;
    v2 = v3;
    v2 -= a2;
    v7 = 97;
    v6 = 22;
    v4 = 22;
    if (v2 < 26) v4 = v7;
    v4 += v2;
    if (v4 >= 97) {
        if (a1 >= 2) JUMPOUT(0x1400afc50);
    }
    a2 = v4;
    a3 -= v5;
    v3 = v_2c;
    v5 = v3 * 57;
    v5 >>= 9;
    v5 &= 0xFFFFFFFC;
    v5 = str + (__int64)(__int64)str*8;
    v2 = v3;
    v2 -= v5;
    if (v2 < 26) v6 = v7;
    v6 += v2;
    if (v6 >= 97) {
        if (a1 >= 2) JUMPOUT(0x1400afc71);
    }
    v5 = v6;
    if (a3 == 0) JUMPOUT(0x1400afbef);
    a3 += 5;
    v7 = v_2d;
    v6 = v7 * 57;
    v6 >>= 9;
    v6 &= 0xFFFFFFFC;
    v6 += v6*8;
    v2 = v7;
    v2 -= v6;
    v6 = 97;
    v3 = 22;
    if (v2 < 26) v3 = v6;
    v3 += v2;
    if (v3 >= 97) {
        if (a1 >= 2) JUMPOUT(0x1400afc97);
    }
    v6 = v3;
    if (a3 != 6) JUMPOUT(0x1400afbff);
    a3 = 0;
    v3 = 0;
    v7 = 0;
    return sub_1400AFD9D();
}