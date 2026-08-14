// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[112];
    __int64 field_80; // offset 128
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14001EDC0(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 v4;
    __int64 v7;
    __int64 v6;
    __int64 v5;
    __int64 v1;

    ptr = *a1;
    ptr2 = ptr->field_80;
    ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 & -8);
    if (ptr2->field_8 != 0) {
        v4 = ptr2->field_0;
        off_140108030();
        ((__int64 (*)())off_140108038)(v1, 0, v4);
    }
    off_140108030();
    ((__int64 (*)())off_140108038)(v1, 0, ptr2);
    if (ptr != -1) {
        ptr->field_8 = ptr->field_8 - 1;
        if (!((ptr->field_8 != 0))) {
            v7 = *(__int64 *)(ptr - 8);
            off_140108030();
            v6 = v1;
            a2 = 0;
            v5 = v7;
            JUMPOUT(off_140108038);
        }
    }
    return v5;
}