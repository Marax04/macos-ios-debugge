// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[64];
    __int64 field_58; // offset 88
};

// inferred from 6 accesses on `a2`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[64];
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    __int64 field_78; // offset 120
    char _pad_78[8];
    __int64 field_88; // offset 136
    __int64 field_90; // offset 144
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14006A090(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    __m128i xmm0;
    __int64 v7;
    __m128i xmm1;
    __int64 v5;
    __int64 v8;
    __int64 v4;
    __int64 v3;
    __int64 v2;
    __int64 result;
    __int64 v10;
    __int64 v9;
    __int64 v6;

    xmm0 = _mm_loadu_si128((__m128i *)(a2 + 16));
    v7 = a2->field_20;
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 40));
    _mm_storeu_si128((__m128i *)(a1 + 24), xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 56));
    _mm_storeu_si128((__m128i *)(a1 + 40), xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 72));
    _mm_storeu_si128((__m128i *)(a1 + 56), xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 88));
    _mm_storeu_si128((__m128i *)(a1 + 72), xmm1);
    v5 = a2->field_68;
    a1->field_58 = v5;
    _mm_storeu_si128((__m128i *)a1, xmm0);
    a1->field_10 = v7;
    v8 = a2->field_70;
    v4 = 0x8000000000000003;
    if (v8 != v4) {
        if (v8 > 0) {
            v3 = a2->field_78;
            v2 = (__int64)a2;
            off_140108030(a1, a2, v5);
            ((__int64 (*)())off_140108038)(v8, 0, v3);
        }
    }
    result = a2->field_88;
    if (result != v4) {
        if (result > 0) {
            v10 = a2->field_90;
            off_140108030(a1, v2);
            v9 = result;
            a2 = 0;
            v6 = v10;
            JUMPOUT(off_140108038);
        }
    }
    return result;
}