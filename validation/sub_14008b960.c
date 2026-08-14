// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr2`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr3`
struct Struct_6_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr4`
struct Struct_7_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr5`
struct Struct_8_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr6`
struct Struct_9_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3AE0();
__int64 sub_14008BD10();

__int64 __fastcall sub_14008B960(struct Struct_1_t *a1, int *a2,struct Struct_2_t *a3) {
    struct Struct_3_t *result;
    struct Struct_6_t *ptr3;
    __int64 *src;
    struct Struct_7_t *ptr4;
    struct Struct_8_t *ptr5;
    struct Struct_5_t *ptr2;
    struct Struct_4_t *ptr;
    int v11;
    struct Struct_9_t *ptr6;
    __int64 v10;
    __int64 v8;

    result = ((__int64 *)a1)[1];
    ptr3 = ((__int64 *)a1)[4];
    src = 0;
    ptr4 = 0;
    src = (result >= a1->field_0) ? 1 : 0;
    ptr4 = (result < a1->field_0) ? 1 : 0;
    ptr5 = a1 + 36;
    ptr2 = a1 + 24;
    /* cmp ptr3 , a1[3] */;
    ptr = ptr4 + (__int64)(__int64)ptr4*2;
    ptr4 = a1 + (__int64)(__int64)ptr*4;
    src += (__int64)(__int64)src*2;
    ptr3 = (struct Struct_6_t *)ptr2;
    if (src < 0) ptr3 = ptr5;
    result = a1 + (__int64)(__int64)src*4;
    if (src < 0) ptr5 = ptr2;
    ptr2 = ptr3->field_0;
    v11 = ptr5->field_0;
    src = *(__int64 *)(a1 + (__int64)(__int64)src*4);
    ptr6 = (struct Struct_9_t *)result;
    if (v11 < src) ptr6 = ptr3;
    if (ptr2 < *(__int64 *)(a1 + (__int64)(__int64)ptr*4)) ptr6 = ptr4;
    if (ptr2 < *(__int64 *)(a1 + (__int64)(__int64)ptr*4)) ptr4 = ptr3;
    if (ptr2 < *(__int64 *)(a1 + (__int64)(__int64)ptr*4)) ptr3 = result;
    if (v11 >= src) result = ptr5;
    if (v11 < src) ptr3 = ptr5;
    ptr5 = ptr3->field_0;
    ptr5 = (struct Struct_8_t *)ptr6;
    if (ptr5 < ptr6->field_0) ptr5 = ptr3;
    if (0 /* unresolved: flags < */) ptr3 = ptr6;
    src = ptr4->field_8;
    a3->field_8 = src;
    ptr4 = ptr4->field_0;
    *(__int64 *)a3 = (__int64)(ptr4);
    ptr4 = ptr5->field_8;
    ((__int64 *)a3)[2] = (__int64)(ptr4);
    ptr4 = ptr5->field_0;
    ((__int64 *)a3)[1] = (__int64)(ptr4);
    ptr4 = ptr3->field_8;
    ((__int64 *)a3)[4] = (__int64)(ptr4);
    ptr3 = ptr3->field_0;
    ((__int64 *)a3)[3] = (__int64)(ptr3);
    ptr3 = result->field_8;
    ((__int64 *)a3)[5] = (__int64)(ptr3);
    result = result->field_0;
    ((__int64 *)a3)[4] = (__int64)(result);
    result = ((__int64 *)a1)[7];
    ptr3 = ((__int64 *)a1)[10];
    src = 0;
    ptr4 = 0;
    src = (result >= ((__int64 *)a1)[6]) ? 1 : 0;
    ptr4 = (result < ((__int64 *)a1)[6]) ? 1 : 0;
    ptr5 = a1 + 84;
    ptr2 = a1 + 72;
    /* cmp ptr3 , a1[9] */;
    ptr = ptr4 + (__int64)(__int64)ptr4*2;
    ptr4 = a1 + (__int64)(__int64)ptr*4 + 48;
    src += (__int64)(__int64)src*2;
    ptr3 = (struct Struct_6_t *)ptr2;
    if (src < 0) ptr3 = ptr5;
    result = a1 + (__int64)(__int64)src*4 + 48;
    if (src < 0) ptr5 = ptr2;
    ptr2 = ptr3->field_0;
    v11 = ptr5->field_0;
    src = *(__int64 *)(a1 + (__int64)(__int64)src*4 + 48);
    ptr6 = (struct Struct_9_t *)result;
    if (v11 < src) ptr6 = ptr3;
    if (ptr2 < *(__int64 *)(a1 + (__int64)(__int64)ptr*4 + 48)) ptr6 = ptr4;
    if (ptr2 < *(__int64 *)(a1 + (__int64)(__int64)ptr*4 + 48)) ptr4 = ptr3;
    if (ptr2 < *(__int64 *)(a1 + (__int64)(__int64)ptr*4 + 48)) ptr3 = result;
    if (v11 >= src) result = ptr5;
    if (v11 < src) ptr3 = ptr5;
    a1 = ptr3->field_0;
    a1 = (struct Struct_1_t *)ptr6;
    if (a1 < ptr6->field_0) a1 = ptr3;
    if (0 /* unresolved: flags < */) ptr3 = ptr6;
    ptr5 = ptr4->field_8;
    ((__int64 *)a3)[7] = (__int64)(ptr5);
    ptr4 = ptr4->field_0;
    ((__int64 *)a3)[6] = (__int64)(ptr4);
    ptr4 = a1->field_0;
    ((__int64 *)a3)[7] = (__int64)(ptr4);
    a1 = a1->field_8;
    ((__int64 *)a3)[8] = (__int64)(a1);
    a1 = ptr3->field_0;
    ((__int64 *)a3)[9] = (__int64)(a1);
    a1 = ptr3->field_8;
    ((__int64 *)a3)[10] = (__int64)(a1);
    a1 = result->field_0;
    ((__int64 *)a3)[10] = (__int64)(a1);
    result = result->field_8;
    ((__int64 *)a3)[11] = (__int64)(result);
    result = ((__int64 *)a3)[6];
    ptr3 = 0;
    a1 = 0;
    result = a3 + 48;
    ptr3 = (result >= a3->field_0) ? 1 : 0;
    if (0 /* unresolved: flags >= */) result = a3;
    a1 = (0 /* unresolved: flags < */) ? 1 : 0;
    ptr4 = result->field_8;
    *(a2 + 8) = ptr4;
    result = result->field_0;
    *a2 = result;
    ptr4 = ((__int64 *)a3)[10];
    ptr5 = ((__int64 *)a3)[4];
    result = 0;
    /* cmp ptr4 , ptr5 */;
    src = 0;
    src -= 1;
    /* cmp ptr4 , ptr5 */;
    ptr2 = 0;
    ptr2 = 0;
    ptr = a3 + 36;
    ptr6 = a3 + 84;
    /* cmp ptr4 , ptr5 */;
    ptr5 = a1 + (__int64)(__int64)a1*2;
    a1 = a3 + (__int64)(__int64)ptr5*4 + 48;
    ptr3 += (__int64)(__int64)ptr3*2;
    ptr4 = a3 + (__int64)(__int64)ptr3*4;
    if (ptr3 < 0) ptr6 = ptr;
    ptr = ptr6->field_8;
    a2[11] = ptr;
    ptr = ptr6->field_0;
    a2[10] = ptr;
    src += (__int64)(__int64)src*2;
    ptr5 = *(__int64 *)(a3 + (__int64)(__int64)ptr5*4 + 48);
    ptr = 0;
    ptr6 = 0;
    ptr3 = ptr2 + (__int64)(__int64)ptr2*2;
    ptr = (ptr5 >= *(__int64 *)(a3 + (__int64)(__int64)ptr3*4)) ? 1 : 0;
    ptr6 = (0 /* unresolved: flags < */) ? 1 : 0;
    ptr5 = (struct Struct_8_t *)ptr4;
    if (0 /* unresolved: flags < */) ptr5 = a1;
    ptr2 = ptr5->field_8;
    a2[2] = ptr2;
    ptr5 = ptr5->field_0;
    a2[1] = ptr5;
    ptr5 = *(__int64 *)(a3 + (__int64)(__int64)src*4 + 84);
    ptr2 = *(__int64 *)(a3 + (__int64)(__int64)ptr3*4 + 36);
    /* cmp ptr5 , ptr2 */;
    v10 = 0;
    v10 -= 1;
    /* cmp ptr5 , ptr2 */;
    ptr5 = a3 + (__int64)(__int64)src*4 + 84;
    src = a3 + (__int64)(__int64)ptr3*4 + 36;
    ptr2 = ptr6 + (__int64)(__int64)ptr6*2;
    a3 = a1 + (__int64)(__int64)ptr2*4;
    ptr += (__int64)(__int64)ptr*2;
    ptr3 = ptr4 + (__int64)(__int64)ptr*4;
    ptr6 = (struct Struct_9_t *)ptr5;
    if (ptr < 0) ptr6 = src;
    v11 = ptr6->field_8;
    a2[10] = v11;
    ptr6 = ptr6->field_0;
    a2[9] = ptr6;
    ptr6 = v10 + v10*2;
    v10 = 0;
    v10 = 0;
    a1 = *(__int64 *)(a1 + (__int64)(__int64)ptr2*4);
    ptr2 = 0;
    v8 = 0;
    a1 = v10 + v10*2;
    ptr2 = (a1 >= *(__int64 *)(ptr4 + (__int64)(__int64)ptr*4)) ? 1 : 0;
    v8 = (0 /* unresolved: flags < */) ? 1 : 0;
    ptr4 = (struct Struct_7_t *)ptr3;
    if (0 /* unresolved: flags < */) ptr4 = a3;
    ptr = ptr4->field_8;
    a2[4] = ptr;
    ptr4 = ptr4->field_0;
    a2[3] = ptr4;
    ptr4 = *(__int64 *)(ptr5 + (__int64)(__int64)ptr6*4);
    ptr = *(src + (__int64)(__int64)a1*4);
    /* cmp ptr4 , ptr */;
    v10 = 0;
    v10 -= 1;
    /* cmp ptr4 , ptr */;
    ptr4 = ptr5 + (__int64)(__int64)ptr6*4;
    ptr5 = src + (__int64)(__int64)a1*4;
    ptr6 = v8 + v8*2;
    a1 = a3 + (__int64)(__int64)ptr6*4;
    ptr2 += (__int64)(__int64)ptr2*2;
    src = ptr3 + (__int64)(__int64)ptr2*4;
    ptr = (struct Struct_4_t *)ptr4;
    if (ptr2 < 0) ptr = ptr5;
    v11 = ptr->field_8;
    a2[8] = v11;
    ptr = ptr->field_0;
    a2[7] = ptr;
    ptr = v10 + v10*2;
    v10 = 0;
    v10 = 0;
    v10 += v10*2;
    v11 = *(__int64 *)(a3 + (__int64)(__int64)ptr6*4);
    ptr6 = 0;
    a3 = 0;
    ptr6 = (v11 >= *(__int64 *)(ptr3 + (__int64)(__int64)ptr2*4)) ? 1 : 0;
    ptr2 = (struct Struct_5_t *)src;
    if (v10 < 0) ptr2 = a1;
    ptr3 = (v10 < 0) ? 1 : 0;
    v11 = ptr2->field_8;
    a2[5] = v11;
    ptr2 = ptr2->field_0;
    a2[4] = ptr2;
    v11 = *(__int64 *)(ptr4 + (__int64)(__int64)ptr*4);
    v8 = *(__int64 *)(ptr5 + v10*4);
    /* cmp v11 , v8 */;
    ptr2 = 0;
    ptr2 -= 1;
    ptr6 += (__int64)(__int64)ptr6*2;
    src += (__int64)(__int64)ptr6*4;
    /* cmp v11 , v8 */;
    ptr4 += (__int64)(__int64)ptr*4;
    ptr5 += v10*4;
    ptr = (struct Struct_4_t *)ptr4;
    if (ptr5 < 0) ptr = ptr5;
    v11 = ptr->field_8;
    a2[7] = v11;
    ptr = ptr->field_0;
    result = 0;
    a2[6] = ptr;
    result += (__int64)(__int64)result*2;
    result = ptr5 + (__int64)(__int64)result*4;
    result += 12;
    if (src == result) {
        result = a3 + (__int64)(__int64)a3*2;
        result = a1 + (__int64)(__int64)result*4;
        a1 = ptr2 + (__int64)(__int64)ptr2*2;
        a1 = ptr4 + (__int64)(__int64)a1*4;
        a1 += 12;
        if (result == a1) {
            return (__int64)a1;
        }
    }
    sub_1400F3AE0(a1, a2, ptr3, ptr3);
    ptr2 = (struct Struct_5_t *)a3;
    src = (__int64 *)a2;
    if (ptr3 >= 8) {
        ptr3 = (struct Struct_6_t *)((__int64)(__int64)ptr3 >> 3);
        result = (struct Struct_3_t *)ptr3;
        result = (struct Struct_3_t *)((__int64)(__int64)result << 4);
        ptr = result + (__int64)(__int64)result*2;
        a2 = (__int64)a1 + (__int64)ptr;
        ptr6 = (__int64)(__int64)ptr3 * 84;
        a3 = (__int64)a1 + (__int64)ptr6;
        v10 = (__int64)ptr3;
        sub_14008BD10(a1, a2, a3, ptr3);
        v8 = (__int64)result;
        a2 = (__int64)src + (__int64)ptr;
        a3 = (__int64)src + (__int64)ptr6;
        sub_14008BD10(src, a2, a3, v10);
        src = (__int64 *)result;
        ptr = (struct Struct_4_t *)((__int64)ptr + (__int64)ptr2);
        ptr6 = (struct Struct_9_t *)((__int64)ptr6 + (__int64)ptr2);
        sub_14008BD10(ptr2, ptr, ptr6, v10);
        a1 = (struct Struct_1_t *)result;
        ptr2 = (struct Struct_5_t *)result;
    }
    result = a1->field_0;
    a2 = *src;
    a3 = (result < a2) ? 1 : 0;
    ptr3 = ptr2->field_0;
    result = (result < ptr3) ? 1 : 0;
    result = (struct Struct_3_t *)((__int64)(__int64)result ^ (__int64)a3);
    a2 = (a2 < ptr3) ? 1 : 0;
    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)a3);
    if (a2 != 0) src = ptr2;
    if (result != 0) src = a1;
    result = (struct Struct_3_t *)src;
    return (__int64)result;
}