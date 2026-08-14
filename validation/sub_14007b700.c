// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[4];
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 6 accesses on `a2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[56];
    __int64 field_58; // offset 88
    int field_60; // offset 96
    __int64 field_64; // offset 100
    char _pad_64[16];
    __int64 field_7C; // offset 124
};

__int64 sub_14007B800();
__int64 sub_14007B8AA();
extern __int64 off_14012284C;

__int64 __fastcall sub_14007B700(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    int v_a0;
    __int64 v1;
    int v2;
    __int64 *src;
    __int64 v7;
    int v3;
    __int64 v4;
    __int64 v5;
    __m128i xmm0;

    v1 = a2->field_10;
    if (v1 != 4) {
        v2 = v_a0;
        src = &off_14012284C;
        v1 = *(src + v1*4);
        v1 += (__int64)src;
        JUMPOUT(v1);
        v7 = a2->field_18;
        v3 = 1;
        return sub_14007B800();
    } else {
        v1 = a2->field_60;
        v4 = a2->field_64;
        v5 = a2->field_7C;
        ((__int64 *)a1)[4] = (__int64)(v5);
        xmm0 = _mm_loadu_si128((__m128i *)(a2 + 108));
        _mm_storeu_si128((__m128i *)(a1 + 16), xmm0);
        a2 = a2->field_58;
        *(__int64 *)a1 = (__int64)(1);
        a1->field_4 = v1;
        a1->field_8 = v4;
        ((__int64 *)a1)[5] = (__int64)(a2);
        return sub_14007B8AA();
    }
}