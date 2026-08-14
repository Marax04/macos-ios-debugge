// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[120];
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
};

__int64 sub_140020E90();
extern __int64 off_1401080A0;

__int64 __fastcall sub_140020E30(struct Struct_1_t *a1, __int64 a2, __int64 a3) {
    int v_28;
    int v_30;
    __int64 v2;
    __int64 v4;
    __int64 v1;
    __int64 v3;
    int v6;
    __int64 v5;
    int v7;

    v_30 = a3;
    v_28 = a2;
    v2 = a1->field_0;
    v4 = a1->field_80;
    v4 ^= v2;
    v1 = a1->field_80;
    v3 = a1->field_88;
    v6 = 0;
    v5 = off_1401080A0;
    v7 = 0;
    return sub_140020E90();
}