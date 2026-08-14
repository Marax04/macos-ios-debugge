// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    char field_10; // offset 16
    __int64 field_11; // offset 17
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[16];
    char field_10; // offset 16
    __int64 field_11; // offset 17
};

// inferred from 2 accesses on `ptr4`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400277DC();
extern __int64 off_140114008;
extern __int64 off_140114040;

__int64 __fastcall sub_14002EE60(__int64 *a1, __int64 a2, int a3, __int64 a4) {
    __int64 rsp;
    int arg_8;
    int v_10;
    __int64 v_18;
    __int64 v_20;
    int v_8;
    __int64 *dst;
    struct Struct_1_t *ptr;
    struct Struct_4_t *ptr4;
    __int64 v2;
    struct Struct_2_t *ptr2;
    __int64 result;
    __int64 v10;
    __int64 v6;
    __int64 v3;
    struct Struct_3_t *ptr3;
    __int64 v8;

    dst = rsp + 80;
    *dst = -2;
    ptr = *a1;
    a3 = ptr->field_8;
    ptr4 = ptr->field_18;
    if (a3 == 1) {
        if (ptr4 == 0) {
            ptr4 = ptr->field_0;
            ptr = ptr4->field_0;
            ptr4 = ptr4->field_8;
            v_20 = (__int64)ptr;
            v_18 = (__int64)ptr4;
            v2 = arg_8;
            ptr2 = a1[2];
            a4 = ptr2->field_10;
            result = ptr2->field_11;
            v_20 = result;
            v10 = &off_140114008;
            a1 = dst - 32;
            sub_1400277DC(a1, v10, v2, a4);
        }
    } else {
        if (a3 == 0) {
            if (ptr4 == 0) {
                result = 1;
                a2 = 0;
                return a2;
            }
        }
    }
    v_8 = (int)a1;
    v6 = 0x8000000000000000;
    v_20 = v6;
    v3 = arg_8;
    ptr3 = a1[2];
    a4 = ptr3->field_10;
    result = ptr3->field_11;
    v_20 = result;
    a2 = &off_140114040;
    v8 = dst - 32;
    sub_1400277DC(v8, a2, v3, a4);
    v_10 = a2;
    dst = a2 + 80;
    result = v_20;
    result <<= 1;
    if (result != 0) JUMPOUT(0x14002ef32);
    return result;
}