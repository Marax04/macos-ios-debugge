// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140043680(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v6;
    __int64 v2;
    __int64 v5;
    __int64 v1;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 != 0) {
        v4 = ptr->field_8;
        off_140108030();
        ((__int64 (*)())off_140108038)(v1, 0, v4);
    }
    if (ptr->field_20 != 0) {
        v6 = ptr->field_28;
        off_140108030();
        ((__int64 (*)())off_140108038)(v1, 0, v6);
    }
    if (ptr->field_38 != 0) {
        ptr = ptr->field_40;
        off_140108030();
        v2 = v1;
        a2 = 0;
        v5 = (__int64)ptr;
        JUMPOUT(off_140108038);
    }
    return v5;
}