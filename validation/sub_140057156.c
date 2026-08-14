// inferred from 17 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
};

__int64 sub_1400F27F0();

__int64 __fastcall sub_140057156() {
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    __int64 v3;
    __int64 v4;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 v10;
    __int64 *result;
    __int64 v15;
    __int64 v13;
    __int64 v11;
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v12;
    __int64 v14;
    __int64 v2;

    *result = *result + (__int64)result;
    *result = *result + (__int64)result;
    sub_1400F27F0(v15, v13, v11);
    v3 = v15;
    v4 = v_60;
    v7 = v_30;
    v8 = v_28;
    v9 = v_40;
    v10 = v_38;
    *(__int64 *)ptr = (__int64)(v6);
    ptr->field_8 = v12;
    ptr->field_10 = v6;
    ptr->field_18 = v8;
    ptr->field_20 = v7;
    ptr->field_28 = v4;
    ptr->field_30 = v10;
    ptr->field_38 = v9;
    result = (__int64 *)v_58;
    ptr->field_40 = result;
    ptr->field_48 = v14;
    result = (__int64 *)v_70;
    ptr->field_50 = result;
    result = (__int64 *)v_50;
    ptr->field_58 = result;
    ptr->field_60 = v2;
    result = (__int64 *)v_68;
    ptr->field_68 = result;
    result = (__int64 *)v_48;
    ptr->field_70 = result;
    ptr->field_78 = v11;
    ptr->field_80 = v3;
    ptr->field_88 = v11;
    return (__int64)result;
}