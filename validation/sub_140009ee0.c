// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[16];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
};

__int64 sub_140009F93();
__int64 sub_140009F79();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140009EE0(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v5;
    __int64 v2;
    __int64 v8;
    __int64 v9;
    __int64 v6;
    __int64 v7;
    __int64 v1;

    ptr = (struct Struct_1_t *)a1;
    if (a1[3] != 0) {
        v4 = ptr->field_20;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(v1, 0, v4);
    }
    v5 = ptr->field_48;
    v5 <<= 1;
    if (v5 != 0) {
        v4 = ptr->field_50;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(v5, 0, v4);
        v4 = ptr->field_38;
        v2 = ptr->field_40;
        if (v2 == 0) JUMPOUT(0x140009f93);
    } else {
        v4 = ptr->field_38;
        v8 = ptr->field_40;
        if (v8 == 0) {
            return sub_140009F93();
        }
    }
    v9 = v4 + 8;
    v6 = off_140108030;
    v7 = off_140108038;
    return sub_140009F79();
}