// inferred from 3 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_14003F65C();
extern __int64 off_140112DC0;

__int64 __fastcall sub_14003F5F0(__int64 a1,struct Struct_1_t *a2, int a3) {
    int v_10;
    int v_20;
    __int64 v3;
    __int64 v1;
    __int64 v2;
    __int64 v6;
    __int64 v5;
    __int64 v4;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_10, xmm6);
    v3 = a1;
    a3 ^= 1;
    v1 = a3;
    a3 = 2;
    if (a2->field_0 == 0) a3 = v1;
    v2 = a2->field_10;
    v6 = a2->field_18;
    v5 = v2 + v6;
    v4 = &off_140112DC0;
    v_20 = v5;
    return sub_14003F65C();
}