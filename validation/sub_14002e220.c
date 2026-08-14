// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14002E220(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 v2;
    __int64 v5;
    __int64 v1;

    ptr = (struct Struct_1_t *)a1;
    dst = a1[3];
    if (dst != 0) {
        *dst = 0;
        if (!((ptr->field_20 == 0))) {
            off_140108030();
            ((__int64 (*)())off_140108038)(v1, 0, dst);
        }
    }
    if (ptr != -1) {
        ptr->field_8 = ptr->field_8 - 1;
        if (!((ptr->field_8 != 0))) {
            off_140108030();
            v2 = v1;
            a2 = 0;
            v5 = (__int64)ptr;
            JUMPOUT(off_140108038);
        }
    }
    return v5;
}