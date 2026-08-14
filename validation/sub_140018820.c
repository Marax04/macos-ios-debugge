// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400188D5();

__int64 __fastcall sub_140018820(struct Struct_1_t *a1, __int64 a2, __int64 a3) {
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    char *dst;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    __int64 v7;
    __int64 v6;
    __int64 v1;
    __int64 v2;
    int v8;

    v3 = ((__int64 *)a1)[2];
    v_20 = v3;
    v4 = a1->field_0;
    v_18 = v4;
    v5 = a1->field_8;
    v_10 = v5;
    *dst = a2;
    v7 = a2 + 8;
    v_28 = v7;
    v3 = 0;
    v6 = 0xF5F5F5F5F5F5F5F5;
    v1 = 0x101010101010101;
    v2 = 0x8080808080808080;
    v7 = 0;
    v8 = 0;
    v_8 = a3;
    return sub_1400188D5();
}