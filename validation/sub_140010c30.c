// inferred from 2 accesses on `a3`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011856();

__int64 __fastcall sub_140010C30(int a1, size_t a2,struct Struct_1_t *a3, size_t a4) {
    int v_10;
    int v_18;
    int v_8;
    char *dst;
    __int64 *v1;
    __int64 *src;
    __int64 v7;
    __int64 *src2;
    __int64 *src3;
    __int64 v3;
    int v2;

    v1 = a3->field_8;
    if (v1 != 1) {
    }
    v1 = 0xE0000020;
    *dst = v1;
    v_10 = a1;
    v_8 = a2;
    src = ((__int64 *)a3)[4];
    v_18 = (int)a3;
    if (src == 0) JUMPOUT(0x14001189a);
    v1 = ((__int64 *)a3)[5];
    if (v1 == 0) JUMPOUT(0x14001191b);
    v1 = (__int64 *)((__int64)(__int64)v1 << 4);
    v7 = v1 + (__int64)(__int64)v1*2;
    src2 = a3->field_0;
    src3 = ((__int64 *)a3)[2];
    src2 += 8;
    v3 = 0;
    v2 = 0;
    a3 = *src2;
    if (a3 != 0) {
        a1 = v_10;
        v1 = (__int64 *)v_8;
        a2 = *(src2 - 8);
        ((__int64 (*)())(*(v1 + 24)))();
        if (v1 != 0) JUMPOUT(0x140011917);
    }
    v1 = *(src + v3 + 16);
    if (v1 == 0) JUMPOUT(0x140011820);
    if (v1 != 1) JUMPOUT(0x140011840);
    v1 = *(src + v3 + 24);
    v1 = (__int64 *)((__int64)(__int64)v1 << 4);
    v1 = *(__int64 *)((__int64)src3 + (__int64)v1 + 8);
    a1 = *(src + v3);
    if (a1 == 2) JUMPOUT(0x140011830);
    if (a1 != 1) JUMPOUT(0x140011850);
    a1 = *(src + v3 + 8);
    a1 <<= 4;
    a1 = *(src3 + a1 + 8);
    return sub_140011856();
}