// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
};

__int64 sub_1400F2DE0();
__int64 sub_14000EFE0();
__int64 sub_1400F2DB0();

__int64 __fastcall sub_1400F32C0(int *a1) {
    char *str;
    struct Struct_2_t *ptr2;
    __int64 v1;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v5;

    ptr2 = (struct Struct_2_t *)a1;
    a1 = *(a1 + 8);
    v1 = ptr2->field_18;
    if (a1 == 1) {
        if (v1 == 0) {
            ptr = ptr2->field_0;
            v4 = ptr->field_0;
            v5 = ptr->field_8;
            return sub_1400F2DE0();
        }
    } else {
        if (a1 == 0) {
            if (v1 == 0) {
                a1 = 1;
                ptr2 = 0;
                return sub_1400F2DE0();
            }
        }
    }
    sub_14000EFE0(str, ptr2);
    return sub_1400F2DB0(str);
}