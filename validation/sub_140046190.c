// inferred from 11 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[8];
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    char _pad_50[8];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    char _pad_68[8];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140046190(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    __int64 v8;
    __int64 v9;
    __int64 v10;
    __int64 result;
    __int64 v11;
    __int64 v5;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 != 0) {
        v4 = ptr->field_8;
        off_140108030();
        ((__int64 (*)())off_140108038)(v6, 0, v4);
    }
    v7 = ptr->field_18;
    v2 = 0x8000000000000003;
    if (v7 != v2) {
        if (v7 > 0) {
            v4 = ptr->field_20;
            off_140108030();
            ((__int64 (*)())off_140108038)(v7, 0, v4);
        }
    }
    v8 = ptr->field_30;
    if (v8 != v2) {
        if (v8 > 0) {
            v4 = ptr->field_38;
            off_140108030();
            ((__int64 (*)())off_140108038)(v8, 0, v4);
        }
    }
    v9 = ptr->field_48;
    if (v9 != v2) {
        if (v9 > 0) {
            v4 = ptr->field_50;
            off_140108030();
            ((__int64 (*)())off_140108038)(v9, 0, v4);
        }
    }
    v10 = ptr->field_60;
    if (v10 != v2) {
        if (v10 > 0) {
            v4 = ptr->field_68;
            off_140108030();
            ((__int64 (*)())off_140108038)(v10, 0, v4);
        }
    }
    result = ptr->field_78;
    if (result != v2) {
        if (result > 0) {
            ptr = ptr->field_80;
            off_140108030();
            v11 = result;
            a2 = 0;
            v5 = (__int64)ptr;
            JUMPOUT(off_140108038);
        }
    }
    return result;
}