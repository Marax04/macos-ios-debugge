// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400127C0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14000ECF0(__int64 a1,struct Struct_1_t *a2) {
    __int64 *src;
    struct Struct_2_t *ptr;
    __int64 v5;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    __int64 v6;
    __int64 v9;
    __int64 v10;
    __int64 v1;

    src = (__int64 *)a1;
    if (a2 >= 17) {
        src = *(src - 8);
    }
    off_140108030();
    ptr = (struct Struct_2_t *)v1;
    a2 = 0;
    v5 = (__int64)src;
    JUMPOUT(off_140108038);
    v4 = ptr->field_8;
    v7 = ptr->field_10;
    v2 = a2->field_0;
    v6 = a2->field_8;
    v9 = v4;
    v10 = v7;
    return sub_1400127C0();
}