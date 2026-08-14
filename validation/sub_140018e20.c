// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

__int64 sub_140018F18();
extern __int64 off_1401109F8;

__int64 __fastcall sub_140018E20(struct Struct_1_t *a1, __int64 a2, int a3, __int64 a4) {
    int arg_70;
    __int64 v9;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 *src;
    __int64 v10;
    __int64 v2;
    __int64 v7;
    __int64 v6;
    __int64 *src2;
    __int64 result;

    v9 = a4;
    ptr = (struct Struct_2_t *)a1;
    v3 = a1->field_0;
    src = a1->field_8;
    v10 = *(src + 24);
    ((__int64 (*)())v10)(v3);
    v2 = 1;
    if (result == 0) {
        v7 = arg_70;
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x140018ea0);
        a2 = &off_1401109F8;
        ((__int64 (*)())v10)(v3, a2, 1);
        if (result == 0) {
            ((__int64 (*)())v7)(v9, ptr);
            if (result == 0) {
                v6 = ptr->field_0;
                src2 = ptr->field_8;
                v2 = *(src2 + 24);
                return sub_140018F18();
            }
        }
    }
    result = v2;
    return result;
}