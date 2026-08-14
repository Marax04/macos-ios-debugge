// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    int field_2; // offset 2
    char _pad_2[2];
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 6 accesses on `ptr`
struct Struct_3_t {
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
struct Struct_4_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_14006842C();
__int64 sub_14004F470();

__int64 __fastcall sub_1400682A0(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3, __int64 a4) {
    int v_50;
    int v_68;
    int v_70;
    int v_78;
    char *str;
    struct Struct_3_t *ptr;
    struct Struct_4_t *ptr2;
    __int64 v5;
    __int64 v4;
    __int64 v3;
    __int64 v1;
    __m128i xmm0;

    ptr = (struct Struct_3_t *)a1;
    ptr2 = a3->field_10;
    v5 = a3->field_18;
    if (v5 != 0) {
        v5 = a2->field_1;
        a4 = a2->field_2;
        v4 = ptr2->field_0;
        v3 = v5 - 1;
        v1 = ptr2 + 1;
        a3->field_10 = v1;
        a3->field_18 = v3;
        if (v5 <= v4) {
            if (v4 <= a4) {
                *(__int64 *)ptr = (__int64)(3);
                ptr->field_8 = 0;
                ptr->field_10 = 8;
                return sub_14006842C();
            }
        }
    }
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_78, xmm0);
    str = 1;
    v_68 = 0;
    v_70 = 8;
    a3->field_10 = ptr2;
    a3->field_18 = v5;
    if (v5 == 0) JUMPOUT(0x1400683c6);
    v5 = a2->field_8;
    a4 = v5 - 1;
    v4 = ptr2 + 1;
    a3->field_10 = v4;
    a3->field_18 = a4;
    if ((v5 != ptr2->field_0)) JUMPOUT(0x1400683be);
    if (a4 == 0) JUMPOUT(0x14006843f);
    v3 = ((__int64 *)a2)[5];
    v5 = ((__int64 *)a2)[5];
    v1 = ptr2->field_1;
    v5 -= 2;
    ptr2 += 2;
    a3->field_10 = ptr2;
    a3->field_18 = v5;
    if (v3 > v1) JUMPOUT(0x140068437);
    if (v1 > v5) JUMPOUT(0x140068437);
    v4 = 3;
    *(__int64 *)ptr = (__int64)(v4);
    ptr->field_8 = a2;
    ptr->field_9 = a4;
    ptr->field_A = a3;
    a3 = (struct Struct_2_t *)((__int64)(__int64)a3 >> 32);
    ptr->field_E = a3;
    ptr->field_10 = ptr2;
    xmm0 = _mm_load_si128((__m128i *)&v_50);
    _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
    ptr->field_28 = v5;
    sub_14004F470(str, a2, a3, a4);
    return sub_14006842C();
}