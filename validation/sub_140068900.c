// inferred from 2 accesses on `a3`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 6 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    char field_8; // offset 8
    char field_9; // offset 9
    int field_A; // offset 10
    __int16 field_E; // offset 14
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_14004F470();

__int64 __fastcall sub_140068900(__int64 *a1, __int64 *a2,struct Struct_1_t *a3, size_t a4) {
    int v_50;
    int v_70;
    int v_78;
    int v_80;
    char *str;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    __int64 result;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;
    __int64 v2;

    ptr = (struct Struct_2_t *)a1;
    ptr2 = a3->field_10;
    result = a3->field_18;
    if (result != 0) {
        a4 = ptr2->field_0;
        v5 = result - 1;
        v6 = ptr2 + 1;
        a3->field_10 = v6;
        a3->field_18 = v5;
        a4 += 208;
        if (a4 <= 9) {
            *(__int64 *)ptr = (__int64)(3);
            ptr->field_8 = 0;
            ptr->field_10 = 8;
            return result;
        }
    }
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_80, xmm0);
    str = 1;
    v_70 = 0;
    v_78 = 8;
    a3->field_10 = ptr2;
    a3->field_18 = result;
    if (result == 0) JUMPOUT(0x140068a1f);
    v6 = *a2;
    a4 = result - 1;
    v2 = ptr2 + 1;
    a3->field_10 = v2;
    a3->field_18 = a4;
    if ((v6 != ptr2->field_0)) JUMPOUT(0x140068a17);
    if (a4 == 0) JUMPOUT(0x140068a97);
    v6 = ptr2->field_1;
    result -= 2;
    ptr2 += 2;
    a3->field_10 = ptr2;
    a3->field_18 = result;
    v6 += 208;
    if (v6 >= 10) JUMPOUT(0x140068a8f);
    v5 = 3;
    *(__int64 *)ptr = (__int64)(v2);
    ptr->field_8 = a2;
    ptr->field_9 = a4;
    ptr->field_A = a3;
    a3 = (struct Struct_1_t *)((__int64)(__int64)a3 >> 32);
    ptr->field_E = a3;
    ptr->field_10 = ptr2;
    xmm0 = _mm_load_si128((__m128i *)&v_50);
    _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
    ptr->field_28 = result;
    return sub_14004F470(str, a2, a3, a4);
}