// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14001118B();

__int64 __fastcall sub_140011050(struct Struct_1_t *a1, __int64 a2, __int64 a3) {
    int v_30;
    int v_3c;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    __int64 v2;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    int v7;
    __int64 v6;
    __int64 v1;

    v2 = a1->field_0;
    v_50 = v2;
    v3 = a1->field_8;
    v_58 = v3;
    v4 = ((__int64 *)a1)[2];
    v_40 = v4;
    v_68 = (int)a1;
    a1 = ((__int64 *)a1)[3];
    v5 = a2 + 8;
    v_60 = v5;
    v7 = 0;
    v6 = 0xF5F5F5F5F5F5F5F5;
    v1 = 0x101010101010101;
    v3 = 0;
    v_30 = 0;
    v_3c = 0;
    v_48 = a2;
    return sub_14001118B();
}