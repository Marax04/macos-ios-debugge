// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400B1938();

__int64 __fastcall sub_1400B1750(struct Struct_1_t *a1, __int64 a2, __int64 a3, __int64 a4) {
    int v_30;
    __int64 v_38;
    int v_40;
    int v_48;
    int v_50;
    __int64 v2;
    __int64 v9;
    __int64 v4;
    __int64 v6;
    __int64 v8;
    __int64 v7;
    __int64 *dst;
    __int64 v5;
    __int64 v3;

    v2 = a3;
    v9 = a2;
    v4 = (__int64)a1;
    v6 = a3 + a3*2;
    v6 <<= 4;
    v6 += a2;
    v8 = 48;
    if (a3 == 0) v8 = a3;
    v8 += a2;
    v7 = 4;
    if (a3 != 0) {
        dst = (__int64 *)v8;
        v5 = v9;
        do {
            a1 = (struct Struct_1_t *)v5;
            v5 = (__int64)dst;
            dst = a1->field_10;
            v7 += (__int64)dst;
            v7 += 7;
            dst = a1->field_28;
            dst = v5 + 48;
            if (v5 == v6) dst = v5;
        } while (v5 != v6);
        if (v7 < 0) {
            sub_1400F3360(a1, a2, 0xCCCCCCCCCCCCCCCD, 0);
        }
        if ((0 /* unresolved: flags == */)) JUMPOUT(0x1400b1d11);
    }
    sub_14002EDF0(0, v7);
    if (dst == 0) JUMPOUT(0x1400b1d72);
    v_48 = v4;
    v_30 = v7;
    v_38 = (__int64)dst;
    v_40 = 0;
    v3 = 0xFFFFFFFF;
    if (v2 < v3) v3 = v2;
    if (v7 <= 3) JUMPOUT(0x1400b1d3d);
    v_50 = v6;
    a1 = 0;
    v7 = a1 + 4;
    *(__int64 *)((__int64)dst + (__int64)a1) = v3;
    v_40 = v7;
    if (v2 == 0) JUMPOUT(0x1400b1cea);
    v6 = 0xFFFF;
    v3 = 0;
    return sub_1400B1938();
}