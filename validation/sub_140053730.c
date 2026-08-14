// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[48];
    __int64 field_30; // offset 48
    char _pad_30[8];
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    char _pad_48[40];
    __int64 field_78; // offset 120
    char _pad_78[8];
    __int64 field_88; // offset 136
    __int64 field_90; // offset 144
};

__int64 sub_140053810();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140053730(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v2;
    __int64 v4;
    __int64 v7;
    __int64 v10;
    __int64 *v11;
    __int64 result;
    __int64 v8;
    __int64 v9;
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
            v10 = ptr->field_90;
            off_140108030();
            ((__int64 (*)())off_140108038)(v7, 0, v10);
        }
    }
    v11 = ptr + 40;
    result = ptr->field_48;
    if (result != 0) {
        v8 = ptr->field_40;
        result =  + result*8 + 23;
        result &= -16;
        v8 -= result;
        off_140108030();
        ((__int64 (*)())off_140108038)(result, 0, v8);
    }
    sub_140053810(v11);
    if (*v11 != 0) {
        ptr = ptr->field_30;
        off_140108030();
        v9 = result;
        a2 = 0;
        v5 = (__int64)ptr;
        JUMPOUT(off_140108038);
    }
    return result;
}