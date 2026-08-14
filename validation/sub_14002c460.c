// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140017B60();
__int64 sub_14000F850();
__int64 sub_14002C938();
__int64 sub_14002CB50();
__int64 sub_14002CC90();
__int64 sub_14002C5ED();
extern __int64 off_14011220E;
extern __int64 off_1401213E0;

__int64 __fastcall sub_14002C460(__int64 a1, int *a2, int a3, __int64 a4) {
    int arg_100;
    int arg_110;
    __int64 arg_168;
    __int64 arg_180;
    int arg_188;
    int arg_190;
    int arg_e8;
    int arg_f0;
    int arg_f8;
    char *str;
    struct Struct_2_t *ptr2;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 v5;
    __int64 v6;

    arg_190 = -2;
    ptr2 = (struct Struct_2_t *)a4;
    src = (__int64 *)a3;
    ptr = (struct Struct_1_t *)a2;
    v4 = a1;
    a2 = *(a2 + 8);
    a3 = ptr->field_10;
    if (ptr->field_0 != 1) {
        a1 = str + 240;
        sub_140017B60(a1, a2);
        if (arg_f0 == 0) a2 = arg_100;
        ptr = &off_14011220E;
        if (arg_f0 == 0) ptr = arg_f8;
        arg_180 = (__int64)ptr;
        ptr = 0x8000000000000000;
        arg_168 = (__int64)ptr;
        if (src != 0) JUMPOUT(0x14002c938);
    } else {
        a1 = str + 240;
        sub_14000F850(a1, a2, a3);
        ptr = (struct Struct_1_t *)arg_f0;
        arg_168 = (__int64)ptr;
        ptr = (struct Struct_1_t *)arg_f8;
        arg_180 = (__int64)ptr;
        a2 = (int *)arg_100;
        if (src != 0) {
            return sub_14002C938();
        }
    }
    arg_e8 = v4;
    a1 = arg_180;
    arg_188 = (int)a2;
    sub_14002CB50(a1, 9);
    a1 = (ptr2 != 0) ? 1 : 0;
    v4 = arg_e8;
    a2 = (int *)arg_188;
    if ((a1 & (__int64)ptr) == 0) JUMPOUT(0x14002c938);
    v7 = ptr2->field_8;
    ptr2 = ptr2->field_10;
    a1 = str + 240;
    a2 = (int *)arg_180;
    sub_14002CC90(a1, a2, a2);
    v5 = arg_f0;
    a1 = arg_100;
    ptr = (struct Struct_1_t *)arg_110;
    a2 = (int *)v5;
    src = &off_1401213E0;
    v6 = *(src + (__int64)(__int64)a2*4);
    v6 += (__int64)src;
    a2 = (int *)arg_188;
    v5 = arg_180;
    JUMPOUT(v6);
    a1 += 4;
    return sub_14002C5ED();
}