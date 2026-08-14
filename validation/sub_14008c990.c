// inferred from 2 accesses on `a4`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 6 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    int field_8; // offset 8
    int field_C; // offset 12
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[4];
    __int64 field_24; // offset 36
};

// inferred from 4 accesses on `ptr3`
struct Struct_4_t {
    __int64 field_0; // offset 0
    int field_8; // offset 8
    __int64 field_C; // offset 12
    __int64 field_14; // offset 20
};

// inferred from 2 accesses on `ptr4`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr5`
struct Struct_6_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr6`
struct Struct_7_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14008BD10();
__int64 sub_14008B960();
__int64 sub_14008D2F0();

__int64 __fastcall sub_14008C990(size_t *a1, size_t *a2, int *a3,struct Struct_1_t *a4) {
    __int64 rsp;
    int arg_8;
    int v_28;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    int v_44;
    int v_4c;
    int v_50;
    int v_58;
    __int64 v_5c;
    __int64 v_64;
    int *v_0;
    int *v_4;
    int *v_8;
    __int64 v8;
    struct Struct_3_t *ptr2;
    __int64 v2;
    struct Struct_7_t *ptr6;
    __int64 *result;
    __int64 v4;
    struct Struct_5_t *ptr4;
    struct Struct_2_t *ptr;
    struct Struct_4_t *ptr3;
    int v11;
    struct Struct_6_t *ptr5;

    v8 = (__int64)a2;
    ptr2 = (struct Struct_3_t *)a1;
    if (a2 >= 33) {
        v2 = (__int64)a4;
        ptr6 = (struct Struct_7_t *)a3;
        --v2;
        while (!((v2 < 0))) {
            a4 = (struct Struct_1_t *)v8;
            a4 = (struct Struct_1_t *)((__int64)(__int64)a4 >> 3);
            result = a4 + (__int64)(__int64)a4*2;
            result = (__int64 *)((__int64)(__int64)result << 4);
            result = (__int64 *)((__int64)result + (__int64)ptr2);
            a3 = (__int64)(__int64)a4 * 84;
            a3 = (int *)((__int64)a3 + (__int64)ptr2);
            if (v8 >= 64) {
                sub_14008BD10(ptr2, result, a3, a4);
                result = (__int64 *)((__int64)result - (__int64)ptr2);
                if (ptr6 == 0) {
                    a1 = ptr2->field_8;
                    v_40 = (__int64)a1;
                    a1 = ptr2->field_0;
                    v_38 = (__int64)a1;
                    a1 = *(__int64 *)((__int64)ptr2 + (__int64)result + 8);
                    a2 = *(__int64 *)((__int64)ptr2 + (__int64)result);
                    *(__int64 *)ptr2 = (__int64)(a2);
                    ptr2->field_8 = a1;
                    a1 = (size_t *)v_40;
                    *(__int64 *)((__int64)ptr2 + (__int64)result + 8) = a1;
                    a1 = (size_t *)v_38;
                    *(__int64 *)((__int64)ptr2 + (__int64)result) = a1;
                    result = ptr2 + 12;
                    a4 = ptr2->field_0;
                    a1 = ptr2->field_C;
                    v4 = ptr2->field_10;
                    ptr4 =  + v8*2;
                    ptr4 += v8;
                    ptr = ptr2 + (__int64)(__int64)ptr4*4;
                    ptr -= 12;
                    ptr3 = ptr2 + 24;
                    if (ptr3 >= ptr) {
                        ptr = (struct Struct_2_t *)result;
                        a2 = 0;
                        ptr4 = ptr2 + (__int64)(__int64)ptr4*4;
                        if (ptr3 == ptr4) {
                            /* cmp a1 , a4 */;
                            a3 = a2 + (__int64)(__int64)a2*2;
                            a4 = v_0[(__int64)a3];
                            ptr3 = v_8[(__int64)a3];
                            ptr->field_8 = ptr3;
                            *(__int64 *)ptr = (__int64)(a4);
                            v_0[(__int64)a3] = a1;
                            v_4[(__int64)a3] = v4;
                            a2 += 0;
                            if (a2 >= v8) JUMPOUT(0x14008d2e5);
                            result = a2 + (__int64)(__int64)a2*2;
                            v4 = ptr2 + (__int64)(__int64)result*4;
                            a1 = ptr2->field_8;
                            v_40 = (__int64)a1;
                            a1 = ptr2->field_0;
                            v_38 = (__int64)a1;
                            a1 = *(__int64 *)(ptr2 + (__int64)(__int64)result*4 + 8);
                            a3 = *(__int64 *)(ptr2 + (__int64)(__int64)result*4);
                            *(__int64 *)ptr2 = (__int64)(a3);
                            ptr2->field_8 = a1;
                            a1 = (size_t *)v_40;
                            *(__int64 *)(ptr2 + (__int64)(__int64)result*4 + 8) = (__int64)(a1);
                            a1 = (size_t *)v_38;
                            *(__int64 *)(ptr2 + (__int64)(__int64)result*4) = (__int64)(a1);
                            ptr = ptr2 + (__int64)(__int64)result*4;
                            ptr += 12;
                            result = (__int64 *)a2;
                            result = (__int64 *)(~(__int64)result);
                            v8 += (__int64)result;
                            sub_14008C990(ptr2, a2, ptr6, v2);
                            ptr6 = (struct Struct_7_t *)v4;
                            ptr2 = (struct Struct_3_t *)ptr;
                            if (v8 >= 2) {
                                v2 = v8;
                                v2 >>= 1;
                                ptr6 =  + v8*2;
                                ptr6 += v8;
                                if (v8 <= 15) {
                                    if (v8 <= 7) {
                                        result = ptr2->field_8;
                                        v_40 = (__int64)result;
                                        result = ptr2->field_0;
                                        v_38 = (__int64)result;
                                        result =  + v2*4;
                                        result += (__int64)(__int64)result*2;
                                        a1 = *(__int64 *)((__int64)ptr2 + (__int64)result + 8);
                                        *(__int64 *)(rsp + result + 64) = a1;
                                        a1 = *(__int64 *)((__int64)ptr2 + (__int64)result);
                                        *(__int64 *)(rsp + result + 56) = a1;
                                        a1 = 1;
                                        a2 = (size_t *)v8;
                                        a2 -= v2;
                                        if (a1 < v2) {
                                            ptr3 = a1 + 1;
                                            result =  + (__int64)(__int64)a1*4;
                                            result += (__int64)(__int64)result*2;
                                            a3 = rsp + 56;
                                            a4 = (struct Struct_1_t *)a1;
                                            do {
                                                a4 = (struct Struct_1_t *)((__int64)(__int64)a4 << 2);
                                                ptr4 = a4 + (__int64)(__int64)a4*2;
                                                a4 = (struct Struct_1_t *)ptr3;
                                                ptr3 = *(__int64 *)((__int64)ptr2 + (__int64)ptr4 + 8);
                                                *(__int64 *)(rsp + ptr4 + 64) = ptr3;
                                                ptr3 = *(__int64 *)((__int64)ptr2 + (__int64)ptr4);
                                                *(__int64 *)(rsp + ptr4 + 56) = ptr3;
                                                /* cmp a4 , v2 */;
                                                ptr3 = (struct Struct_4_t *)a4;
                                                ptr3 += 0;
                                                result += 12;
                                            } while (a4 < v2);
                                        }
                                    } else {
                                        result = ptr2->field_C;
                                        a1 = ptr2->field_24;
                                        a4 = 0;
                                        a2 = 0;
                                        a4 = (result >= ptr2->field_0) ? 1 : 0;
                                        a2 = (result < ptr2->field_0) ? 1 : 0;
                                        a3 = ptr2 + 36;
                                        ptr3 = ptr2 + 24;
                                        /* cmp a1 , ptr2->field_18 */;
                                        ptr4 = a2 + (__int64)(__int64)a2*2;
                                        a2 = ptr2 + (__int64)(__int64)ptr4*4;
                                        a4 += (__int64)(__int64)a4*2;
                                        a1 = (size_t *)ptr3;
                                        if (a4 < 0) a1 = a3;
                                        result = ptr2 + (__int64)(__int64)a4*4;
                                        if (a4 < 0) a3 = ptr3;
                                        ptr3 = *a1;
                                        v11 = *a3;
                                        a4 = *(__int64 *)(ptr2 + (__int64)(__int64)a4*4);
                                        ptr = (struct Struct_2_t *)result;
                                        if (v11 < a4) ptr = a1;
                                        if (ptr3 < *(__int64 *)(ptr2 + (__int64)(__int64)ptr4*4)) ptr = a2;
                                        if (ptr3 < *(__int64 *)(ptr2 + (__int64)(__int64)ptr4*4)) a2 = a1;
                                        if (ptr3 < *(__int64 *)(ptr2 + (__int64)(__int64)ptr4*4)) a1 = result;
                                        if (v11 >= a4) result = a3;
                                        if (v11 < a4) a1 = a3;
                                        a3 = *a1;
                                        a3 = (int *)ptr;
                                        if (a3 < ptr->field_0) a3 = a1;
                                        if (0 /* unresolved: flags < */) a1 = ptr;
                                        a4 = (struct Struct_1_t *)arg_8;
                                        v_40 = (__int64)a4;
                                        a2 = *a2;
                                        v_38 = (__int64)a2;
                                        a2 = (size_t *)arg_8;
                                        v_4c = (int)a2;
                                        a2 = *a3;
                                        v_44 = (int)a2;
                                        a2 = (size_t *)arg_8;
                                        v_58 = (int)a2;
                                        a1 = *a1;
                                        v_50 = (int)a1;
                                        a1 =  + v2*4;
                                        a1 += (__int64)(__int64)a1*2;
                                        ptr3 = (__int64)ptr2 + (__int64)a1;
                                        a2 = *(__int64 *)((__int64)ptr2 + (__int64)a1 + 12);
                                        a3 = *(__int64 *)((__int64)ptr2 + (__int64)a1 + 36);
                                        ptr4 = 0;
                                        ptr = 0;
                                        ptr4 = (a2 >= *(__int64 *)((__int64)ptr2 + (__int64)a1)) ? 1 : 0;
                                        ptr = (a2 < *(__int64 *)((__int64)ptr2 + (__int64)a1)) ? 1 : 0;
                                        a4 = (__int64)ptr2 + (__int64)a1;
                                        a4 += 36;
                                        ptr5 = (__int64)ptr2 + (__int64)a1;
                                        ptr5 += 24;
                                        /* cmp a3 , *(__int64 *)((__int64)ptr2 + (__int64)a1 + 24) */;
                                        ptr += (__int64)(__int64)ptr*2;
                                        ptr4 += (__int64)(__int64)ptr4*2;
                                        a2 = ptr3 + (__int64)(__int64)ptr4*4;
                                        a3 = (int *)ptr5;
                                        if (ptr4 < 0) a3 = a4;
                                        if (ptr4 < 0) a4 = ptr5;
                                        v11 = a4->field_0;
                                        ptr4 = *(__int64 *)(ptr3 + (__int64)(__int64)ptr4*4);
                                        ptr5 = (struct Struct_6_t *)a2;
                                        if (v11 < ptr4) ptr5 = a3;
                                        v4 = v8;
                                        v8 = *a3;
                                        /* cmp v8 , *(ptr3 + (__int64)(__int64)ptr*4) */;
                                        v8 = v4;
                                        ptr3 += (__int64)(__int64)ptr*4;
                                        if (ptr3 < 0) ptr5 = ptr3;
                                        if (ptr3 < 0) ptr3 = a3;
                                        ptr = (struct Struct_2_t *)arg_8;
                                        if (ptr3 < 0) a3 = a2;
                                        if (v11 >= ptr4) a2 = a4;
                                        if (v11 < ptr4) a3 = a4;
                                        v_64 = (__int64)ptr;
                                        a4 = *a3;
                                        result = *result;
                                        a4 = (struct Struct_1_t *)ptr5;
                                        if (a4 < ptr5->field_0) ptr5 = a3;
                                        v_5c = (__int64)result;
                                        if (0 /* unresolved: flags < */) a3 = ptr5;
                                        result = ptr3->field_8;
                                        *(__int64 *)(rsp + a1 + 64) = result;
                                        result = ptr3->field_0;
                                        *(__int64 *)(rsp + a1 + 56) = result;
                                        result = ptr5->field_0;
                                        *(__int64 *)(rsp + a1 + 68) = result;
                                        result = ptr5->field_8;
                                        *(__int64 *)(rsp + a1 + 76) = result;
                                        result = *a3;
                                        *(__int64 *)(rsp + a1 + 80) = result;
                                        result = (__int64 *)arg_8;
                                        *(__int64 *)(rsp + a1 + 88) = result;
                                        result = *a2;
                                        *(__int64 *)(rsp + a1 + 92) = result;
                                        result = (__int64 *)arg_8;
                                        *(__int64 *)(rsp + a1 + 100) = result;
                                        a1 = 4;
                                        a2 = (size_t *)v4;
                                        a2 -= v2;
                                        if (a1 < v2) {
                                            return (__int64)a2;
                                        } else {
                                        }
                                    }
                                } else {
                                    a3 = rsp + (__int64)(__int64)ptr6*4;
                                    a3 += 56;
                                    a2 = rsp + 56;
                                    sub_14008B960(ptr2, a2, a3);
                                    result =  + v2*4;
                                    result += (__int64)(__int64)result*2;
                                    a1 = (__int64)ptr2 + (__int64)result;
                                    a2 = rsp + result;
                                    a2 += 56;
                                    a3 = rsp + (__int64)(__int64)ptr6*4;
                                    a3 += 152;
                                    sub_14008B960(a1, a2, a3);
                                    a1 = 8;
                                    a2 = (size_t *)v8;
                                    a2 -= v2;
                                    if (a1 < v2) {
                                        return (__int64)a2;
                                    } else {
                                    }
                                }
                                result =  + v2*4;
                                a3 = result + (__int64)(__int64)result*2;
                                result = rsp + a3;
                                result += 56;
                                if (a1 < a2) {
                                    a3 = (int *)((__int64)a3 + (__int64)ptr2);
                                    ptr3 = a1 + 1;
                                    a4 =  + (__int64)(__int64)a1*4;
                                    a4 += (__int64)(__int64)a4*2;
                                    do {
                                        a1 = (size_t *)((__int64)(__int64)a1 << 2);
                                        ptr4 = a1 + (__int64)(__int64)a1*2;
                                        a1 = (size_t *)ptr3;
                                        ptr3 = *(__int64 *)((__int64)a3 + (__int64)ptr4 + 8);
                                        *(__int64 *)((__int64)result + (__int64)ptr4 + 8) = ptr3;
                                        ptr3 = *(__int64 *)((__int64)a3 + (__int64)ptr4);
                                        *(__int64 *)((__int64)result + (__int64)ptr4) = ptr3;
                                        /* cmp a1 , a2 */;
                                        ptr3 = (struct Struct_4_t *)a1;
                                        ptr3 += 0;
                                        a4 += 12;
                                    } while (a1 < a2);
                                }
                                a4 = ptr2 + (__int64)(__int64)ptr6*4;
                                a4 -= 12;
                                a1 = rsp + (__int64)(__int64)ptr6*4;
                                a1 += 44;
                                a2 = result - 12;
                                a3 = rsp + 56;
                                do {
                                    ptr3 = (struct Struct_4_t *)result;
                                    ptr4 = (struct Struct_5_t *)a3;
                                    a3 = *result;
                                    result += 12;
                                    a3 = ptr4 + 12;
                                    if (a3 < ptr4->field_0) a3 = ptr4;
                                    if (0 /* unresolved: flags < */) ptr4 = ptr3;
                                    v11 = ptr4->field_8;
                                    ptr2->field_8 = v11;
                                    if (0 /* unresolved: flags >= */) result = ptr3;
                                    ptr3 = *a1;
                                    v11 = *a2;
                                    /* cmp ptr3 , v11 */;
                                    ptr6 = 0;
                                    ptr6 -= 1;
                                    ptr3 = (struct Struct_4_t *)a1;
                                    if (ptr3 < v11) ptr3 = a2;
                                    ptr4 = ptr4->field_0;
                                    ptr = 0;
                                    ptr = 0;
                                    *(__int64 *)ptr2 = (__int64)(ptr4);
                                    ptr2 += 12;
                                    ptr4 = ptr3->field_8;
                                    a4->field_8 = ptr4;
                                    ptr3 = ptr3->field_0;
                                    *(__int64 *)a4 = (__int64)(ptr3);
                                    ptr3 = ptr6 + (__int64)(__int64)ptr6*2;
                                    a1 += (__int64)(__int64)ptr3*4;
                                    ptr3 = ptr + (__int64)(__int64)ptr*2;
                                    a2 += (__int64)(__int64)ptr3*4;
                                    a4 -= 12;
                                    --v2;
                                } while ((v2 != 0));
                                a2 += 12;
                                if ((v8 & 1) != 0) {
                                    a4 = a3 + 12;
                                    ptr3 = result + 12;
                                    ptr4 = (struct Struct_5_t *)result;
                                    if (a3 < a2) ptr4 = a3;
                                    v4 = ptr4->field_8;
                                    ptr2->field_8 = v4;
                                    ptr4 = ptr4->field_0;
                                    *(__int64 *)ptr2 = (__int64)(ptr4);
                                    if (a3 < a2) a3 = a4;
                                    if (0 /* unresolved: flags >= */) result = ptr3;
                                }
                                if (a3 != a2) JUMPOUT(0x14008d2e0);
                                a1 += 12;
                                if (result != a1) JUMPOUT(0x14008d2e0);
                            }
                            return (__int64)a1;
                        }
                        a3 = (int *)v8;
                        for (; ptr3 != ptr4; ptr3 += 12) {
                            /* cmp *ptr3 , a4 */;
                            ptr5 = a2 + (__int64)(__int64)a2*2;
                            v8 = v_0[(__int64)ptr5];
                            v11 = v_8[(__int64)ptr5];
                            ptr->field_8 = v11;
                            *(__int64 *)ptr = (__int64)(v8);
                            v11 = ptr3->field_8;
                            v_8[(__int64)ptr5] = v11;
                            ptr = ptr3->field_0;
                            a2 += 0;
                            v_0[(__int64)ptr5] = ptr;
                            ptr = (struct Struct_2_t *)ptr3;
                        }
                        ptr3 -= 12;
                        ptr = (struct Struct_2_t *)ptr3;
                        v8 = (__int64)a3;
                        return v8;
                    }
                    v_28 = v4;
                    v_30 = v8;
                    a2 = 0;
                    do {
                        v11 = ptr3->field_8;
                        ptr5 = 0;
                        ptr5 = (ptr3->field_0 < a4) ? 1 : 0;
                        v8 = a2 + (__int64)(__int64)a2*2;
                        v4 = v_8[v8];
                        a3 = v_0[v8];
                        *(__int64 *)(ptr3 - 12) = (__int64)(a3);
                        *(__int64 *)(ptr3 - 4) = (__int64)(v4);
                        v_8[v8] = v11;
                        a3 = ptr3->field_0;
                        v_0[v8] = a3;
                        a3 = (__int64)a2 + (__int64)ptr5;
                        v4 = ptr3->field_14;
                        /* cmp ptr3->field_C , a4 */;
                        a3 += (__int64)(__int64)a3*2;
                        v11 = v_8[(__int64)a3];
                        v8 = v_0[(__int64)a3];
                        *(__int64 *)ptr3 = (__int64)(v8);
                        ptr3->field_8 = v11;
                        v_8[(__int64)a3] = v4;
                        v4 = ptr3->field_C;
                        v_0[(__int64)a3] = v4;
                        a2 = (size_t *)((__int64)a2 + (__int64)ptr5);
                        ptr3 += 24;
                    } while (ptr3 < ptr);
                    ptr = ptr3 - 12;
                    v8 = v_30;
                    v4 = v_28;
                    ptr4 = ptr2 + (__int64)(__int64)ptr4*4;
                    if (ptr3 != ptr4) {
                        return (__int64)ptr4;
                    }
                    return (__int64)ptr4;
                }
                a1 = ptr6->field_0;
                if (a1 >= *(__int64 *)((__int64)ptr2 + (__int64)result)) {
                    result = (__int64 *)((__int64)result + (__int64)ptr2);
                    a1 = ptr2->field_8;
                    v_40 = (__int64)a1;
                    a1 = ptr2->field_0;
                    v_38 = (__int64)a1;
                    a1 = (size_t *)arg_8;
                    a2 = *result;
                    *(__int64 *)ptr2 = (__int64)(a2);
                    ptr2->field_8 = a1;
                    a1 = (size_t *)v_40;
                    arg_8 = (int)a1;
                    a1 = (size_t *)v_38;
                    *result = a1;
                    a1 = ptr2 + 12;
                    a4 = ptr2->field_0;
                    a2 = ptr2->field_C;
                    a3 = ptr2->field_10;
                    ptr4 =  + v8*2;
                    ptr4 += v8;
                    ptr6 = ptr2 + (__int64)(__int64)ptr4*4;
                    ptr6 -= 12;
                    ptr3 = ptr2 + 24;
                    if (ptr3 >= ptr6) {
                        ptr6 = (struct Struct_7_t *)a1;
                        result = 0;
                        ptr4 = ptr2 + (__int64)(__int64)ptr4*4;
                        if (ptr3 == ptr4) {
                            /* cmp a4 , a2 */;
                            a4 = result + (__int64)(__int64)result*2;
                            ptr3 = v_0[(__int64)a4];
                            ptr4 = v_8[(__int64)a4];
                            ptr6->field_8 = ptr4;
                            *(__int64 *)ptr6 = (__int64)(ptr3);
                            v_0[(__int64)a4] = a2;
                            v_4[(__int64)a4] = a3;
                            result += 1;
                            if (result >= v8) JUMPOUT(0x14008d2e5);
                            a1 = result + (__int64)(__int64)result*2;
                            a2 = ptr2->field_8;
                            v_40 = (__int64)a2;
                            a2 = ptr2->field_0;
                            v_38 = (__int64)a2;
                            a2 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*4 + 8);
                            a3 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*4);
                            *(__int64 *)ptr2 = (__int64)(a3);
                            ptr2->field_8 = a2;
                            a2 = (size_t *)v_40;
                            *(__int64 *)(ptr2 + (__int64)(__int64)a1*4 + 8) = (__int64)(a2);
                            a2 = (size_t *)v_38;
                            *(__int64 *)(ptr2 + (__int64)(__int64)a1*4) = (__int64)(a2);
                            result = (__int64 *)(~(__int64)result);
                            v8 += (__int64)result;
                            ptr2 += (__int64)(__int64)a1*4;
                            ptr2 += 12;
                            ptr6 = 0;
                            return (__int64)ptr6;
                        }
                        for (; ptr3 != ptr4; ptr3 += 12) {
                            /* cmp a4 , ptr3->field_0 */;
                            v4 = result + (__int64)(__int64)result*2;
                            ptr = v_0[v4];
                            v11 = v_8[v4];
                            ptr6->field_8 = v11;
                            *(__int64 *)ptr6 = (__int64)(ptr);
                            v11 = ptr3->field_8;
                            v_8[v4] = v11;
                            ptr6 = ptr3->field_0;
                            result += 1;
                            v_0[v4] = ptr6;
                            ptr6 = (struct Struct_7_t *)ptr3;
                        }
                        ptr3 -= 12;
                        ptr6 = (struct Struct_7_t *)ptr3;
                        return (__int64)ptr6;
                    }
                    result = 0;
                    do {
                        /* cmp a4 , ptr3->field_0 */;
                        v4 = result + (__int64)(__int64)result*2;
                        v11 = v_8[v4];
                        ptr = v_0[v4];
                        *(__int64 *)(ptr3 - 12) = (__int64)(ptr);
                        *(__int64 *)(ptr3 - 4) = (__int64)(v11);
                        v11 = ptr3->field_8;
                        v_8[v4] = v11;
                        ptr = ptr3->field_0;
                        result += 1;
                        v_0[v4] = ptr;
                        /* cmp a4 , ptr3->field_C */;
                        v4 = result + (__int64)(__int64)result*2;
                        v11 = v_8[v4];
                        ptr = v_0[v4];
                        *(__int64 *)ptr3 = (__int64)(ptr);
                        ptr3->field_8 = v11;
                        v11 = ptr3->field_14;
                        v_8[v4] = v11;
                        ptr = ptr3->field_C;
                        v_0[v4] = ptr;
                        result += 1;
                        ptr3 += 24;
                    } while (ptr3 < ptr6);
                    ptr6 = ptr3 - 12;
                    ptr4 = ptr2 + (__int64)(__int64)ptr4*4;
                    if (ptr3 != ptr4) {
                        return (__int64)ptr4;
                    }
                    return (__int64)ptr4;
                }
                return (__int64)ptr4;
            }
            a1 = ptr2->field_0;
            a2 = *result;
            a4 = (a1 < a2) ? 1 : 0;
            ptr3 = *a3;
            a1 = (a1 < ptr3) ? 1 : 0;
            a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
            a2 = (a2 < ptr3) ? 1 : 0;
            a2 = (size_t *)((__int64)(__int64)a2 ^ (__int64)a4);
            if (a2 != 0) result = a3;
            if (a1 != 0) result = ptr2;
            result = (__int64 *)((__int64)result - (__int64)ptr2);
            if (ptr6 != 0) {
                return (__int64)result;
            }
            return (__int64)result;
        }
        a1 = (size_t *)ptr2;
        a2 = (size_t *)v8;
        return sub_14008D2F0();
    }
    return (__int64)result;
}