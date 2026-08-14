// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 4 accesses on `a2`
struct Struct_2_t {
    char _pad_start[80];
    __int64 field_50; // offset 80
    char _pad_50[80];
    __int64 field_A8; // offset 168
    char _pad_A8[80];
    __int64 field_100; // offset 256
    char _pad_100[80];
    __int64 field_158; // offset 344
};

// inferred from 3 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[64];
    __int64 field_50; // offset 80
};

// inferred from 2 accesses on `ptr`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr2`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[64];
    __int64 field_50; // offset 80
};

// inferred from 3 accesses on `v_cap`
struct Struct_6_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[64];
    __int64 field_50; // offset 80
};

// inferred from 2 accesses on `v_cap2`
struct Struct_7_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

extern __int64 off_14011EB88;
extern __int64 off_14011EBA0;
extern __int64 off_14011EBB8;
extern __int64 off_14011EBD0;
extern __int64 off_14011EBE8;
extern __int64 off_14011EC00;
extern __int64 off_14011EC18;
extern __int64 off_14011EC30;
extern __int64 off_14011EC48;
extern __int64 off_14011EC60;

__int64 __fastcall sub_140072CF0(struct Struct_1_t *a1,struct Struct_2_t *a2, int a3) {
    struct Struct_3_t *result;
    __int64 *v5;
    struct Struct_6_t *v_cap;
    struct Struct_5_t *ptr2;
    __int64 *v7;
    struct Struct_7_t *v_cap2;
    __int64 v3;
    __int64 *v4;
    struct Struct_4_t *ptr;
    int v11;
    __int64 v9;
    __int64 v10;
    __int64 *v8;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    result = 80;
    a3 = 0;
    /* cmp a3 , a1[11] */;
    a3 = 80;
    if (!((0 /* unresolved: flags !OF */))) {
        a3 = ((__int64 *)a1)[12];
        v5 = a3 - 3;
        /* cmp a3 , 3 */;
        v_cap = 2;
        if (v5 >= 2) v_cap = v5;
        v5 = &off_14011EB88;
        v_cap = v5[(__int64)v_cap];
    }
    v5 = 0;
    if (__OFSUB(v5, a1->field_0)) {
        result = a1->field_8;
        v5 = result - 3;
        /* cmp result , 3 */;
        if (v5 >= 2) result = v5;
        v5 = &off_14011EBA0;
        result = v5[(__int64)result];
    }
    v5 = 80;
    ptr2 = 0;
    v7 = 80;
    if (__OFSUB(ptr2, a1[33])) {
        ptr2 = ((__int64 *)a1)[34];
        v7 = ptr2 - 3;
        /* cmp ptr2 , 3 */;
        if (v7 >= 2) ptr2 = v7;
        v7 = &off_14011EBB8;
        v7 = v7[(__int64)ptr2];
    }
    v_cap = *(__int64 *)((__int64)a1 + (__int64)v_cap + 88);
    ptr2 = *(__int64 *)((__int64)a1 + (__int64)result);
    result = *(__int64 *)((__int64)a1 + (__int64)v7 + 264);
    v7 = 0;
    if (__OFSUB(v7, a1[22])) {
        v5 = ((__int64 *)a1)[23];
        v7 = v5 - 3;
        /* cmp v5 , 3 */;
        v_cap2 = 2;
        if (v7 >= 2) v_cap2 = v7;
        v7 = &off_14011EBD0;
        v_cap2 = v7[(__int64)v_cap2];
    }
    v3 = 0;
    v7 = 0;
    v3 = (v_cap >= ptr2) ? 1 : 0;
    v7 = (v_cap < ptr2) ? 1 : 0;
    v_cap = (__int64)(__int64)v7 * 88;
    v_cap = (struct Struct_6_t *)((__int64)v_cap + (__int64)a1);
    ptr2 = a1 + 176;
    result = a1 + 264;
    v_cap2 = (struct Struct_7_t *)ptr2;
    if (result < *(__int64 *)((__int64)a1 + (__int64)v_cap2 + 176)) v_cap2 = result;
    if (0 /* unresolved: flags < */) result = ptr2;
    ptr2 = 80;
    v7 = 0;
    /* cmp v7 , v_cap2->field_0 */;
    v7 = 80;
    if (!((0 /* unresolved: flags !OF */))) {
        v7 = v_cap2->field_8;
        v4 = v7 - 3;
        /* cmp v7 , 3 */;
        if (v4 >= 2) v7 = v4;
        v4 = &off_14011EBE8;
        v7 = v4[(__int64)v7];
    }
    v3 *= 88;
    v4 = 0;
    if (__OFSUB(v4, v_cap->field_0)) {
        ptr2 = v_cap->field_8;
        v4 = ptr2 - 3;
        /* cmp ptr2 , 3 */;
        if (v4 >= 2) ptr2 = v4;
        v4 = &off_14011EC00;
        ptr2 = v4[(__int64)ptr2];
    }
    a1 += v3;
    ptr = 80;
    v3 = 0;
    v4 = 80;
    if (__OFSUB(v3, result->field_0)) {
        v3 = result->field_8;
        v4 = v3 - 3;
        /* cmp v3 , 3 */;
        if (v4 >= 2) v3 = v4;
        v4 = &off_14011EC18;
        v4 = v4[v3];
    }
    v7 = *(__int64 *)((__int64)v_cap2 + (__int64)v7);
    v3 = *(__int64 *)((__int64)v_cap + (__int64)ptr2);
    v4 = *(__int64 *)((__int64)result + (__int64)v4);
    ptr2 = 0;
    if (__OFSUB(ptr2, a1->field_0)) {
        ptr2 = a1->field_8;
        ptr = ptr2 - 3;
        /* cmp ptr2 , 3 */;
        if (ptr >= 2) ptr2 = ptr;
        ptr = &off_14011EC30;
        ptr = ((__int64 *)ptr)[(__int64)ptr2];
    }
    v11 = *(__int64 *)((__int64)a1 + (__int64)ptr);
    ptr = (struct Struct_4_t *)a1;
    if (v4 < v11) a1 = v_cap2;
    if (v7 < v3) a1 = v_cap;
    ptr2 = (struct Struct_5_t *)v_cap2;
    if (v7 < v3) ptr2 = a1;
    if (v4 < v11) ptr2 = result;
    v9 = 80;
    v10 = 0;
    /* cmp v10 , ptr2->field_0 */;
    v10 = 80;
    if (!((0 /* unresolved: flags !OF */))) {
        v10 = ptr2->field_8;
        v8 = v10 - 3;
        /* cmp v10 , 3 */;
        if (v8 >= 2) v10 = v8;
        v8 = &off_14011EC48;
        v10 = v8[v10];
    }
    v10 = *(__int64 *)(ptr2 + v10);
    v8 = 0;
    if (__OFSUB(v8, ptr->field_0)) {
        v9 = ptr->field_8;
        v8 = v9 - 3;
        /* cmp v9 , 3 */;
        if (v8 >= 2) v9 = v8;
        v8 = &off_14011EC60;
        v9 = v8[v9];
    }
    if (v4 < v11) result = a1;
    if (v7 < v3) v_cap = v_cap2;
    a1 = (struct Struct_1_t *)ptr;
    if (v10 < *(__int64 *)(ptr + v9)) a1 = ptr2;
    if (v10 < *(__int64 *)(ptr + v9)) ptr2 = ptr;
    v_cap2 = v_cap->field_50;
    a2->field_50 = v_cap2;
    xmm0 = _mm_loadu_si128((__m128i *)(v_cap + 64));
    _mm_storeu_si128((__m128i *)(a2 + 64), xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)v_cap);
    xmm1 = _mm_loadu_si128((__m128i *)(v_cap + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(v_cap + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(v_cap + 48));
    _mm_storeu_si128((__m128i *)(a2 + 48), xmm3);
    _mm_storeu_si128((__m128i *)(a2 + 32), xmm2);
    _mm_storeu_si128((__m128i *)(a2 + 16), xmm1);
    _mm_storeu_si128((__m128i *)a2, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)a1);
    xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a1 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(a1 + 48));
    _mm_storeu_si128((__m128i *)(a2 + 88), xmm0);
    _mm_storeu_si128((__m128i *)(a2 + 104), xmm1);
    _mm_storeu_si128((__m128i *)(a2 + 120), xmm2);
    _mm_storeu_si128((__m128i *)(a2 + 136), xmm3);
    xmm0 = _mm_loadu_si128((__m128i *)(a1 + 64));
    _mm_storeu_si128((__m128i *)(a2 + 152), xmm0);
    a1 = ((__int64 *)a1)[10];
    a2->field_A8 = a1;
    a1 = ptr2->field_50;
    a2->field_100 = a1;
    xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + 64));
    _mm_storeu_si128((__m128i *)(a2 + 240), xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
    xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(ptr2 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(ptr2 + 48));
    _mm_storeu_si128((__m128i *)(a2 + 224), xmm3);
    _mm_storeu_si128((__m128i *)(a2 + 208), xmm2);
    _mm_storeu_si128((__m128i *)(a2 + 192), xmm1);
    _mm_storeu_si128((__m128i *)(a2 + 176), xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)result);
    xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(result + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(result + 48));
    _mm_storeu_si128((__m128i *)(a2 + 264), xmm0);
    _mm_storeu_si128((__m128i *)(a2 + 280), xmm1);
    _mm_storeu_si128((__m128i *)(a2 + 296), xmm2);
    _mm_storeu_si128((__m128i *)(a2 + 312), xmm3);
    xmm0 = _mm_loadu_si128((__m128i *)(result + 64));
    _mm_storeu_si128((__m128i *)(a2 + 328), xmm0);
    result = result->field_50;
    a2->field_158 = result;
    return (__int64)result;
}