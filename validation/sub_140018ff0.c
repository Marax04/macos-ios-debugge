// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    int field_12; // offset 18
    char _pad_12[2];
    __int64 field_18; // offset 24
};

__int64 sub_140018B70();
__int64 sub_140019112();
__int64 sub_140019115();
extern __int64 off_140110A3D;

__int64 __fastcall sub_140018FF0(__int64 *a1, int a2, int a3, __int64 a4) {
    int arg_1;
    int arg_70;
    int arg_78;
    int arg_80;
    int arg_88;
    int arg_90;
    int arg_98;
    int arg_a0;
    int arg_a8;
    int arg_b0;
    int arg_b8;
    int arg_c0;
    int arg_c8;
    int arg_d0;
    int arg_d8;
    int arg_e0;
    __int64 v_20;
    __int64 v_8;
    char *dst;
    __int64 v7;
    __int64 *src;
    __int64 v2;
    __int64 v3;
    __int64 v9;
    __int64 v6;
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 v5;

    v7 = a4;
    src = a1;
    v2 = arg_98;
    v3 = arg_a0;
    v9 = arg_70;
    v6 = arg_78;
    v4 = arg_80;
    a1 = *a1;
    ptr = *(src + 8);
    ((__int64 (*)())(ptr->field_18))();
    v_8 = (__int64)src;
    *dst = ptr;
    arg_1 = 0;
    v_20 = v4;
    v5 = dst - 8;
    sub_140018B70(v5, v7, v9, v6);
    v_20 = v3;
    a2 = arg_88;
    a3 = arg_90;
    sub_140018B70(v5, a2, a3, v2);
    ptr = (struct Struct_1_t *)arg_c0;
    v_20 = (__int64)ptr;
    a2 = arg_a8;
    a3 = arg_b0;
    a4 = arg_b8;
    sub_140018B70(v5, a2, a3, a4);
    ptr = (struct Struct_1_t *)arg_e0;
    v_20 = (__int64)ptr;
    a2 = arg_c8;
    a3 = arg_d0;
    a4 = arg_d8;
    sub_140018B70(v5, a2, a3, a4);
    a1 = *dst;
    ptr = (struct Struct_1_t *)arg_1;
    a2 = (int)ptr;
    a2 = ~a2;
    a2 |= (__int64)a1;
    if ((a2 & 1) == 0) {
        ptr = (struct Struct_1_t *)v_8;
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x1400190fe);
        a1 = ptr->field_0;
        ptr = ptr->field_8;
        a2 = &off_140110A3D;
        a3 = 2;
        return sub_140019112();
    } else {
        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | (__int64)a1);
        return sub_140019115();
    }
}