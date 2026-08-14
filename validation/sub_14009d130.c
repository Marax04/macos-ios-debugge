// inferred from 3 accesses on `a1`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    char _pad_start[4];
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a3`
struct Struct_3_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

__int64 sub_1400F3AE0();
__int64 sub_14009D4A6();

__int64 __fastcall sub_14009D130(struct Struct_1_t *a1,struct Struct_2_t *a2,struct Struct_3_t *a3, int *a4) {
    int v_130;
    __int64 *src;
    __int64 *src2;
    __int64 result;
    __int64 *src3;
    __int64 *src4;
    __int64 *src5;
    int v11;
    __int64 *src6;
    __int64 *src7;
    __int64 v8;
    __int64 v7;
    __m128i xmm6;

    a4 = a1->field_4;
    src = ((__int64 *)a1)[1];
    src2 = 0;
    result = 0;
    src2 = (a4 >= a1->field_0) ? 1 : 0;
    result = (a4 < a1->field_0) ? 1 : 0;
    a4 = 0;
    a4 = (src < a1->field_8) ? 1 : 0;
    src3 = a4 + 2;
    a4 = (int *)((__int64)(__int64)a4 ^ 3);
    src4 = *(__int64 *)(a1 + (__int64)(__int64)src3*4);
    src5 = *(__int64 *)(a1 + result*4);
    v11 = *(__int64 *)(a1 + (__int64)(__int64)a4*4);
    src = src3;
    if (src4 < src5) src = src2;
    if (v11 < *(__int64 *)(a1 + (__int64)(__int64)src2*4)) src = a4;
    if (v11 < *(__int64 *)(a1 + (__int64)(__int64)src2*4)) a4 = src2;
    if (v11 < *(__int64 *)(a1 + (__int64)(__int64)src2*4)) src2 = src3;
    src4 = *(__int64 *)(a1 + (__int64)(__int64)src*4);
    if (src4 < src5) src2 = result;
    if (0 /* unresolved: flags < */) result = src3;
    result = *(__int64 *)(a1 + result*4);
    src3 = src2;
    if (src4 < *(__int64 *)(a1 + (__int64)(__int64)src2*4)) src3 = src;
    *(__int64 *)a3 = (__int64)(result);
    src3 = *(__int64 *)(a1 + (__int64)(__int64)src3*4);
    if (0 /* unresolved: flags >= */) src2 = src;
    a3->field_4 = src3;
    src2 = *(__int64 *)(a1 + (__int64)(__int64)src2*4);
    a3->field_8 = src2;
    src2 = *(__int64 *)(a1 + (__int64)(__int64)a4*4);
    ((__int64 *)a3)[1] = (__int64)(src2);
    src = ((__int64 *)a1)[2];
    src4 = ((__int64 *)a1)[3];
    src3 = 0;
    a4 = 0;
    src3 = (src >= ((__int64 *)a1)[2]) ? 1 : 0;
    a4 = (src < ((__int64 *)a1)[2]) ? 1 : 0;
    src = 0;
    src = (src4 < ((__int64 *)a1)[3]) ? 1 : 0;
    src5 = src + 2;
    src = (__int64 *)((__int64)(__int64)src ^ 3);
    v11 = *(__int64 *)(a1 + (__int64)(__int64)src5*4 + 16);
    src6 = *(__int64 *)(a1 + (__int64)(__int64)a4*4 + 16);
    src7 = *(__int64 *)(a1 + (__int64)(__int64)src*4 + 16);
    src4 = src5;
    if (v11 < src6) src4 = src3;
    if (src7 < *(__int64 *)(a1 + (__int64)(__int64)src3*4 + 16)) src4 = src;
    if (src7 < *(__int64 *)(a1 + (__int64)(__int64)src3*4 + 16)) src = src3;
    if (src7 < *(__int64 *)(a1 + (__int64)(__int64)src3*4 + 16)) src3 = src5;
    if (v11 < src6) src3 = a4;
    v11 = *(__int64 *)(a1 + (__int64)(__int64)src4*4 + 16);
    if (src < 0) a4 = src5;
    src5 = a3 + 16;
    v11 = *(__int64 *)(a1 + (__int64)(__int64)a4*4 + 16);
    ((__int64 *)a3)[2] = (__int64)(v11);
    a4 = (int *)src3;
    if (v11 < *(__int64 *)(a1 + (__int64)(__int64)src3*4 + 16)) a4 = src4;
    a4 = *(__int64 *)(a1 + (__int64)(__int64)a4*4 + 16);
    ((__int64 *)a3)[2] = (__int64)(a4);
    if (0 /* unresolved: flags >= */) src3 = src4;
    a4 = *(__int64 *)(a1 + (__int64)(__int64)src3*4 + 16);
    ((__int64 *)a3)[3] = (__int64)(a4);
    a4 = a3 + 28;
    a1 = *(__int64 *)(a1 + (__int64)(__int64)src*4 + 16);
    ((__int64 *)a3)[3] = (__int64)(a1);
    src = 0;
    src3 = 0;
    src = (v11 >= result) ? 1 : 0;
    src3 = (v11 < result) ? 1 : 0;
    if (v11 >= result) src5 = a3;
    result = *src5;
    *(__int64 *)a2 = (__int64)(result);
    result = 0;
    src4 = 0;
    src4 = (a1 >= src2) ? 1 : 0;
    src6 = 0;
    src6 = 0;
    a1 = a3 + (__int64)(__int64)src3*4;
    a1 += 16;
    src2 = src4;
    src2 = (__int64 *)((__int64)(__int64)src2 << 4);
    src2 = *(__int64 *)((__int64)a3 + (__int64)src2 + 12);
    ((__int64 *)a2)[3] = (__int64)(src2);
    src4 = (__int64 *)((__int64)(__int64)src4 << 2);
    a4 = (int *)((__int64)a4 - (__int64)src4);
    src2 = *(__int64 *)(a3 + (__int64)(__int64)src3*4 + 16);
    src4 = 0;
    src5 = 0;
    src7 = a3 + (__int64)(__int64)src*4;
    src4 = (src2 >= *(__int64 *)(a3 + (__int64)(__int64)src*4)) ? 1 : 0;
    src5 = (src2 < *(__int64 *)(a3 + (__int64)(__int64)src*4)) ? 1 : 0;
    src2 = src7;
    if (a4 < 0) src2 = a1;
    src2 = *src2;
    a2->field_4 = src2;
    src = *a4;
    src3 = *(__int64 *)(a3 + (__int64)(__int64)src6*4 + 12);
    /* cmp src , src3 */;
    src2 = 0;
    src2 -= 1;
    /* cmp src , src3 */;
    src6 = a3 + (__int64)(__int64)src6*4 + 12;
    src = a1 + (__int64)(__int64)src5*4;
    a3 = (struct Struct_3_t *)a4;
    if (src6 < 0) a3 = src6;
    src3 = src7 + (__int64)(__int64)src4*4;
    a3 = a3->field_0;
    ((__int64 *)a2)[3] = (__int64)(a3);
    v8 = 0;
    v8 = 0;
    a1 = *(__int64 *)(a1 + (__int64)(__int64)src5*4);
    src5 = 0;
    v7 = 0;
    src5 = (a1 >= *(src7 + (__int64)(__int64)src4*4)) ? 1 : 0;
    v7 = (a1 < *(src7 + (__int64)(__int64)src4*4)) ? 1 : 0;
    a1 = (struct Struct_1_t *)src3;
    if (src6 < 0) a1 = src;
    a1 = a1->field_0;
    a2->field_8 = a1;
    a1 = *(a4 + (__int64)(__int64)src2*4);
    src4 = *(src6 + v8*4);
    /* cmp a1 , src4 */;
    a3 = 0;
    a3 -= 1;
    /* cmp a1 , src4 */;
    a4 += (__int64)(__int64)src2*4;
    src2 = src6 + v8*4;
    a1 = src + v7*4;
    src6 = src3 + (__int64)(__int64)src5*4;
    src4 = (__int64 *)a4;
    if (a4 < 0) src4 = src2;
    v11 = *src4;
    src4 = 0;
    src4 = 0;
    ((__int64 *)a2)[2] = (__int64)(v11);
    v11 = *(src + v7*4);
    src7 = 0;
    src = 0;
    src7 = (v11 >= *(src3 + (__int64)(__int64)src5*4)) ? 1 : 0;
    src5 = (v11 < *(src3 + (__int64)(__int64)src5*4)) ? 1 : 0;
    src7 = src6 + (__int64)(__int64)src7*4;
    if (src7 < 0) src6 = a1;
    src3 = *src6;
    ((__int64 *)a2)[1] = (__int64)(src3);
    v11 = *(a4 + (__int64)(__int64)a3*4);
    src6 = *(src2 + (__int64)(__int64)src4*4);
    /* cmp v11 , src6 */;
    src3 = 0;
    src3 -= 1;
    /* cmp v11 , src6 */;
    a3 = a4 + (__int64)(__int64)a3*4;
    a4 = src2 + (__int64)(__int64)src4*4;
    src2 = (__int64 *)a3;
    if (a3 < 0) src2 = a4;
    src2 = *src2;
    ((__int64 *)a2)[2] = (__int64)(src2);
    result = 0;
    result = a4 + result*4;
    result += 4;
    if (src7 == result) {
        src = src5;
        result = a1 + (__int64)(__int64)src*4;
        a1 = a3 + (__int64)(__int64)src3*4;
        a1 += 4;
        if (result == a1) {
            return result;
        }
    }
    sub_1400F3AE0(a1, a2, a3, a4);
    _mm_store_si128((__m128i *)&v_130, xmm6);
    v7 = ((__int64 *)a2)[2];
    if (v7 >= 64) JUMPOUT(0x14009d44d);
    a1->field_8 = 0;
    return sub_14009D4A6();
}