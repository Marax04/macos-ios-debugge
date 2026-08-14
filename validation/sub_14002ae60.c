// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[24];
    __int64 field_20; // offset 32
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
};

__int64 sub_14002B13D();
__int64 sub_14002AFDF();
extern __int64 off_140112208;
extern __int64 off_1401175D8;
extern __int64 off_140028030;
extern __int64 off_140112140;

__int64 __fastcall sub_14002AE60(struct Struct_1_t *a1, __int64 a2, int a3, __int64 a4) {
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_28;
    int v_18;
    int v_20;
    int v_30;
    int v_38;
    int v_40;
    int v_60;
    char *str;
    struct Struct_2_t *ptr;
    __int64 i;
    int v1;
    struct Struct_3_t *ptr2;
    __int64 v6;
    __int64 v5;
    __int64 v7;
    __int64 v8;
    __int64 v9;

    ptr = a1->field_0;
    i = a1->field_8;
    v_60 = a2;
    if (a2 == 0) {
        if (ptr->field_20 == 0) {
            ++i;
            a1->field_8 = i;
            v1 = 0;
            return sub_14002B13D();
        }
    }
    ptr2 = ptr->field_0;
    if (i == 0) JUMPOUT(0x14002af2a);
    v6 = ptr2->field_0;
    ptr2 = ptr2->field_8;
    a2 = &off_140112208;
    a3 = 6;
    ((__int64 (*)())(ptr2->field_18))();
    if (v1 != 0) JUMPOUT(0x14002b13b);
    if (ptr->field_20 != 1) JUMPOUT(0x14002afff);
    v5 = ptr->field_0;
    v7 = &off_1401175D8;
    arg_10 = v7;
    a2 = &off_140028030;
    arg_18 = a2;
    arg_20 = 0;
    arg_28 = 21;
    v_40 = v7;
    v_38 = 1;
    v8 = &off_140112140;
    v_20 = v8;
    v_18 = 1;
    v9 = str + 16;
    v_30 = v9;
    return sub_14002AFDF();
}