// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();

__int64 __fastcall sub_1400E4630(struct Struct_1_t *a1) {
    int v_20;
    __int64 result;
    __int64 v2;
    __int64 *dst;
    struct Struct_2_t *ptr;
    __int64 v5;

    result = a1->field_0;
    v2 = ((__int64 *)a1)[2];
    dst = (__int64 *)result;
    dst -= v2;
    if (dst <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(a1, v2, 3, 1);
        result = ptr->field_0;
        v2 = ptr->field_10;
    }
    dst = a1->field_8;
    *(dst + v2 + 2) = 200;
    *(dst + v2) = 328;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    v5 = result;
    v5 -= v2;
    if (v5 <= 3) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 4, 1);
        v2 = ptr->field_10;
        result = ptr->field_0;
        dst = ptr->field_8;
    }
    *(dst + v2) = 0xDC1C148;
    v2 += 4;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result -= v2;
    if (result <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        dst = ptr->field_8;
        v2 = ptr->field_10;
    }
    *(dst + v2 + 2) = 193;
    *(dst + v2) = 0x3148;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result = a1->field_0;
    dst = (__int64 *)result;
    dst -= v2;
    if (dst <= 3) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 4, 1);
        result = ptr->field_0;
        v2 = ptr->field_10;
    }
    dst = a1->field_8;
    *(dst + v2) = 0x20C0C148;
    v2 += 4;
    ((__int64 *)a1)[2] = (__int64)(v2);
    v5 = result;
    v5 -= v2;
    if (v5 <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        v2 = ptr->field_10;
        result = ptr->field_0;
        dst = ptr->field_8;
    }
    *(dst + v2 + 2) = 218;
    *(dst + v2) = 328;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 4, 1);
        dst = ptr->field_8;
        v2 = ptr->field_10;
    }
    *(dst + v2) = 0x10C3C148;
    v2 += 4;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result = a1->field_0;
    dst = (__int64 *)result;
    dst -= v2;
    if (dst <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        result = ptr->field_0;
        v2 = ptr->field_10;
    }
    dst = a1->field_8;
    *(dst + v2 + 2) = 211;
    *(dst + v2) = 0x3148;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    v5 = result;
    v5 -= v2;
    if (v5 <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        v2 = ptr->field_10;
        result = ptr->field_0;
        dst = ptr->field_8;
    }
    *(dst + v2 + 2) = 216;
    *(dst + v2) = 328;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 4, 1);
        dst = ptr->field_8;
        v2 = ptr->field_10;
    }
    *(dst + v2) = 0x15C3C148;
    v2 += 4;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result = a1->field_0;
    dst = (__int64 *)result;
    dst -= v2;
    if (dst <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        result = ptr->field_0;
        v2 = ptr->field_10;
    }
    dst = a1->field_8;
    *(dst + v2 + 2) = 195;
    *(dst + v2) = 0x3148;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    v5 = result;
    v5 -= v2;
    if (v5 <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        v2 = ptr->field_10;
        result = ptr->field_0;
        dst = ptr->field_8;
    }
    *(dst + v2 + 2) = 202;
    *(dst + v2) = 328;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 4, 1);
        dst = ptr->field_8;
        v2 = ptr->field_10;
    }
    *(dst + v2) = 0x11C1C148;
    v2 += 4;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result = a1->field_0;
    dst = (__int64 *)result;
    dst -= v2;
    if (dst <= 2) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 3, 1);
        result = ptr->field_0;
        v2 = ptr->field_10;
    }
    dst = a1->field_8;
    *(dst + v2 + 2) = 209;
    *(dst + v2) = 0x3148;
    v2 += 3;
    ((__int64 *)a1)[2] = (__int64)(v2);
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        ptr = (struct Struct_2_t *)a1;
        sub_1400F2D20(ptr, v2, 4, 1);
        a1 = (struct Struct_1_t *)ptr;
        dst = ptr->field_8;
        v2 = ptr->field_10;
    }
    *(dst + v2) = 0x20C2C148;
    v2 += 4;
    ((__int64 *)a1)[2] = (__int64)(v2);
    return result;
}