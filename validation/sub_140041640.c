// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002E220();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140041640(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v2;
    __int64 v4;

    ptr = (struct Struct_1_t *)a1;
    result = a1[2];
    *result = *result - 1;
    if (!((*result != 0))) {
        v2 = ptr->field_10;
        sub_14002E220(v2);
    }
    if (ptr != -1) {
        ptr->field_8 = ptr->field_8 - 1;
        if (!((ptr->field_8 != 0))) {
            off_140108030();
            v4 = (__int64)result;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
    }
    return (__int64)result;
}