// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140011760();
__int64 sub_14002B13D();
extern __int64 off_140112170;
extern __int64 off_1400182E0;
extern __int64 off_140112180;
extern __int64 off_14011AB0E;

__int64 __fastcall sub_14002B1BF() {
    int arg_10;
    int arg_18;
    int arg_b0;
    int arg_b8;
    int v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    int v_40;
    __int64 v_50;
    char *str;
    __int64 v3;
    __int64 v4;
    __int64 v7;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __int64 v8;
    __int64 v5;
    __int64 v12;
    __int64 v9;
    __int64 v10;
    __int64 v13;
    struct Struct_2_t *ptr2;
    __int64 *src;
    __int64 v6;

    v3 = v13 + 16;
    v_30 = v3;
    v_28 = 2;
    v3 = ptr->field_0;
    v4 = ptr->field_8;
    v7 = v13 - 64;
    sub_140011760(v3, v4, v7);
    if (ptr != 0) JUMPOUT(0x14002b13b);
    ptr = ptr2->field_0;
    v3 = ptr->field_0;
    ptr = ptr->field_8;
    v4 = &off_140112170;
    v7 = 16;
    ((__int64 (*)())(ptr->field_18))();
    if (ptr != 0) JUMPOUT(0x14002b13b);
    v3 = ptr2->field_8;
    ptr = ptr2->field_10;
    v4 = ptr2->field_0;
    v_40 = v4;
    xmm0 = _mm_loadu_si128((__m128i *)src);
    _mm_storeu_si128((__m128i *)&v_38, xmm0);
    v8 = *(src + 16);
    v_28 = v8;
    ((__int64 (*)())(ptr->field_20))();
    if (ptr != 0) JUMPOUT(0x14002b13b);
    ptr = ptr2->field_0;
    v3 = v13 - 84;
    arg_10 = v3;
    v5 = &off_1400182E0;
    arg_18 = v5;
    v12 = &off_140112180;
    v_40 = v12;
    v_38 = 1;
    v_20 = 0;
    v_30 = (__int64)str;
    v_28 = 1;
    v3 = ptr->field_0;
    v4 = ptr->field_8;
    v9 = v13 - 64;
    sub_140011760(v3, v4, v9, v8);
    if (ptr != 0) JUMPOUT(0x14002b13b);
    ptr = (struct Struct_1_t *)arg_b0;
    if (((__int64)ptr & 1) != 0) {
        ptr = (struct Struct_1_t *)arg_b8;
        v_50 = (__int64)ptr;
        ptr = ptr2->field_0;
        v3 = v13 - 80;
        arg_10 = v3;
        arg_18 = v5;
        v_40 = v12;
        v_38 = 1;
        v_20 = 0;
        v_30 = (__int64)str;
        v_28 = 1;
        v3 = ptr->field_0;
        v4 = ptr->field_8;
        v10 = v13 - 64;
        sub_140011760(v3, v4, v10);
        if (ptr != 0) JUMPOUT(0x14002b13b);
    }
    ptr = ptr2->field_0;
    v3 = ptr->field_0;
    ptr = ptr->field_8;
    v4 = &off_14011AB0E;
    v7 = 1;
    ((__int64 (*)())(ptr->field_18))();
    v3 = (__int64)ptr;
    ptr = 1;
    v3 = v6;
    if ((v3 == 0)) JUMPOUT(0x14002ae8f);
    return sub_14002B13D();
}