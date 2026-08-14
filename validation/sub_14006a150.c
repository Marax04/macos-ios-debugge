// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[64];
    __int64 field_58; // offset 88
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[64];
    __int64 field_58; // offset 88
};

// inferred from 6 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[96];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    char _pad_68[8];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    char _pad_80[8];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14006A150(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    struct Struct_3_t *ptr;
    __m128i xmm0;
    __int64 v6;
    __m128i xmm1;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    __int64 v9;
    __int64 result;
    __int64 v8;
    __int64 v5;

    ptr = (struct Struct_3_t *)a2;
    xmm0 = _mm_loadu_si128((__m128i *)a2);
    v6 = a2->field_10;
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 24));
    _mm_storeu_si128((__m128i *)(a1 + 24), xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 40));
    _mm_storeu_si128((__m128i *)(a1 + 40), xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 56));
    _mm_storeu_si128((__m128i *)(a1 + 56), xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 72));
    _mm_storeu_si128((__m128i *)(a1 + 72), xmm1);
    a2 = a2->field_58;
    a1->field_58 = a2;
    _mm_storeu_si128((__m128i *)a1, xmm0);
    a1->field_10 = v6;
    if (ptr->field_60 > 0) {
        v4 = ptr->field_68;
        off_140108030(a1, a2);
        ((__int64 (*)())off_140108038)(v6, 0, v4);
    }
    v7 = ptr->field_78;
    v2 = 0x8000000000000003;
    if (v7 != v2) {
        if (v7 > 0) {
            v9 = ptr->field_80;
            off_140108030();
            ((__int64 (*)())off_140108038)(v7, 0, v9);
        }
    }
    result = ptr->field_90;
    if (result != v2) {
        if (result > 0) {
            ptr = ptr->field_98;
            off_140108030();
            v8 = result;
            a2 = 0;
            v5 = (__int64)ptr;
            JUMPOUT(off_140108038);
        }
    }
    return result;
}