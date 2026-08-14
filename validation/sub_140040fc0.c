// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[24];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
};

__int64 sub_14002E220();
__int64 sub_1400377D0();
__int64 sub_140037910();
__int64 sub_140037C60();
__int64 sub_140041110();
extern __int64 off_140108048;

__int64 __fastcall sub_140040FC0(struct Struct_1_t *a1) {
    int v_10;
    __int64 v_8;
    char *dst;
    struct Struct_2_t *ptr;
    __int64 *dst2;
    __int64 v3;
    __int64 v4;
    __int64 *dst3;
    __int64 *result;

    *dst = -2;
    ptr = (struct Struct_2_t *)a1;
    dst2 = a1->field_20;
    *dst2 = *dst2 - 1;
    if (!((*dst2 != 0))) {
        a1 = ptr->field_20;
        sub_14002E220(a1);
    }
    a1 = ptr->field_30;
    v3 = ptr->field_38;
    v4 = off_140108048;
    ((__int64 (*)())v4)(a1);
    ((__int64 (*)())v4)(v3);
    v_8 = (__int64)ptr;
    a1 = ptr + 24;
    v_10 = (int)a1;
    sub_1400377D0(a1);
    a1 = (struct Struct_1_t *)v_10;
    dst3 = a1->field_0;
    if (dst3 != 0) {
        *dst3 = *dst3 - 1;
        if (!((*dst3 != 0))) {
            sub_140037910(a1);
        }
    }
    a1 = (struct Struct_1_t *)v_8;
    sub_140037C60(a1);
    a1 = (struct Struct_1_t *)v_8;
    result = a1->field_28;
    *result = *result - 1;
    if ((*result != 0)) {
        return (__int64)result;
    } else {
        a1 = a1->field_28;
        return sub_140041110();
    }
}