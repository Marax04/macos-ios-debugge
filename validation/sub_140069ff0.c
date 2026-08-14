// inferred from 4 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
};

// inferred from 6 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[144];
    __int64 field_A8; // offset 168
    char _pad_A8[168];
    __int64 field_158; // offset 344
    __int64 field_160; // offset 352
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[24];
    __int64 field_30; // offset 48
};

__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140069FF0(__int64 a1,struct Struct_1_t *a2) {
    struct Struct_3_t *ptr2;
    struct Struct_2_t *ptr;
    __int64 v8;
    __int64 v9;
    __int64 v7;
    __int64 v5;
    __int64 v2;
    __int64 v6;
    __m128i xmm0;
    __int64 result;

    ptr2 = (struct Struct_3_t *)a2;
    ptr = (struct Struct_2_t *)a1;
    v8 = a2->field_18;
    v9 = a2->field_20;
    v7 = a2->field_28;
    v5 = a2->field_38;
    if (v5 != 0) {
        v2 = ptr2->field_30;
        v5 =  + v5*8 + 23;
        v5 &= -16;
        v2 -= v5;
        off_140108030();
        off_140108038(v5, 0);
    }
    v6 = v7 * 328;
    v6 += v9;
    ptr->field_158 = v9;
    ptr->field_160 = v9;
    ptr->field_168 = v8;
    ptr->field_170 = v6;
    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
    _mm_storeu_si128((__m128i *)ptr, xmm0);
    result = ptr2->field_10;
    ptr->field_10 = result;
    ptr->field_A8 = 12;
    return result;
}