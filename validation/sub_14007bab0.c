// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[36];
    int field_24; // offset 36
    __int64 field_28; // offset 40
};

// inferred from 5 accesses on `a2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[40];
    __int64 field_58; // offset 88
    char _pad_58[32];
    __int64 field_80; // offset 128
};

__int64 sub_14007BC29();
__int64 sub_14007BC95();
extern __int64 off_14012285C;

__int64 __fastcall sub_14007BAB0(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    int v3;
    __int64 v1;
    __int64 *src;
    __int64 v6;
    int v4;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v2;

    v3 = a2->field_10;
    if (v3 != 4) {
        v1 = a2->field_20;
        if (v1 != 4) {
            src = &off_14012285C;
            v1 = *(src + v1*4);
            v1 += (__int64)src;
            JUMPOUT(v1);
            v6 = a2->field_28;
            v4 = 1;
            if (v3 != 1) JUMPOUT(0x14007bb3f);
            return sub_14007BC29();
        }
    }
    v1 = a2->field_80;
    a1->field_24 = v1;
    xmm0 = _mm_loadu_si128((__m128i *)(a2 + 96));
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 112));
    _mm_storeu_si128((__m128i *)(a1 + 20), xmm1);
    _mm_storeu_si128((__m128i *)(a1 + 4), xmm0);
    v2 = a2->field_58;
    *(__int64 *)a1 = (__int64)(1);
    a1->field_28 = v2;
    return sub_14007BC95();
}