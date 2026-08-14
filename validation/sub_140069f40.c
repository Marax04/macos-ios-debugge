// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `a2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

// inferred from 5 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[56];
    __int64 field_38; // offset 56
    char _pad_38[8];
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    char _pad_50[8];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140069F40(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    struct Struct_3_t *ptr;
    __int64 v6;
    __m128i xmm0;
    __int64 v7;
    __int64 v4;
    __int64 v8;
    __int64 v2;
    __int64 v10;
    __int64 result;
    __int64 v9;
    __int64 v5;

    ptr = (struct Struct_3_t *)a2;
    v6 = a2->field_28;
    a1->field_28 = v6;
    xmm0 = _mm_loadu_si128((__m128i *)(a2 + 24));
    _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
    v7 = a2->field_10;
    a1->field_10 = v7;
    xmm0 = _mm_loadu_si128((__m128i *)a2);
    _mm_storeu_si128((__m128i *)a1, xmm0);
    if (a2->field_30 > 0) {
        v4 = ptr->field_38;
        off_140108030();
        ((__int64 (*)())off_140108038)(v7, 0, v4);
    }
    v8 = ptr->field_48;
    v2 = 0x8000000000000003;
    if (v8 != v2) {
        if (v8 > 0) {
            v10 = ptr->field_50;
            off_140108030();
            ((__int64 (*)())off_140108038)(v8, 0, v10);
        }
    }
    result = ptr->field_60;
    if (result != v2) {
        if (result > 0) {
            ptr = ptr->field_68;
            off_140108030();
            v9 = result;
            a2 = 0;
            v5 = (__int64)ptr;
            JUMPOUT(off_140108038);
        }
    }
    return result;
}