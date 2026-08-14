// inferred from 8 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[40];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    char _pad_48[40];
    __int64 field_78; // offset 120
    char _pad_78[8];
    __int64 field_88; // offset 136
    __int64 field_90; // offset 144
};

__int64 sub_140046040();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14004F700(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v2;
    __int64 v4;
    __int64 v7;
    __int64 v9;
    __int64 result;
    __int64 v10;
    __int64 v11;
    __int64 v8;
    __int64 v5;

    ptr = (struct Struct_1_t *)a1;
    v6 = a1[14];
    v2 = 0x8000000000000003;
    if (v6 != v2) {
        if (v6 > 0) {
            v4 = ptr->field_78;
            off_140108030();
            ((__int64 (*)())off_140108038)(v6, 0, v4);
        }
    }
    v7 = ptr->field_88;
    if (v7 != v2) {
        if (v7 > 0) {
            v9 = ptr->field_90;
            off_140108030();
            ((__int64 (*)())off_140108038)(v7, 0, v9);
        }
    }
    result = ptr->field_48;
    if (result != 0) {
        v10 = ptr->field_40;
        result =  + result*8 + 23;
        result &= -16;
        v10 -= result;
        off_140108030();
        ((__int64 (*)())off_140108038)(result, 0, v10);
    }
    v11 = ptr->field_30;
    a2 = ptr->field_38;
    sub_140046040(v11, a2);
    if (ptr->field_28 != 0) {
        off_140108030();
        v8 = result;
        a2 = 0;
        v5 = v11;
        JUMPOUT(off_140108038);
    }
    return result;
}