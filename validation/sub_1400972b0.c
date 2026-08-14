// inferred from 3 accesses on `a1`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[16];
    __int64 field_40; // offset 64
};

__int64 sub_14009748C();
__int64 sub_140097E9F();

__int64 __fastcall sub_1400972B0(struct Struct_1_t *a1, __int64 a2, int a3, __int64 a4) {
    int v_170;
    int v_78;
    int v_80;
    int v_90;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    __int64 v8;
    __int64 v4;
    int v6;
    __int64 v10;
    __int64 v7;
    __int64 v11;
    __int64 *src;
    __int64 v1;
    __int64 v5;
    __int64 v3;
    __int64 v9;
    __m128i xmm12;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;
    __m128i xmm8;
    __m128i xmm7;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_f0, xmm12);
    _mm_store_si128((__m128i *)&v_e0, xmm11);
    _mm_store_si128((__m128i *)&v_d0, xmm10);
    _mm_store_si128((__m128i *)&v_c0, xmm9);
    _mm_store_si128((__m128i *)&v_b0, xmm8);
    _mm_store_si128((__m128i *)&v_a0, xmm7);
    _mm_store_si128((__m128i *)&v_90, xmm6);
    v8 = a1->field_28;
    v4 = 1;
    v6 = 0x70000;
    if (v8 <= 0xFFFF) {
        v10 = (__int64)a1;
        v_78 = a3;
        v_80 = a4;
        v7 = v_170;
        v11 =  + v8*4;
        v11 += v8;
        v11 <<= 3;
        v11 += a1->field_40;
        src = a1->field_20;
        v1 =  + v8*8;
        v1 += v8;
        v5 = v1 + v1*2;
        v5 += v8;
        a1 = src + v5;
        a4 = 0;
        do {
            v3 = a4;
            if (v5 == a4) JUMPOUT(0x14009748c);
            a3 = *(src + v3 + 20);
            a4 = v3 + 28;
        } while (a3 == 0);
        v9 = src + v3;
        v9 += 28;
        if (v9 == a1) JUMPOUT(0x14009748c);
        v1 = (__int64)a1;
        v1 -= v9;
        v4 = v1;
        v4 >>= 2;
        v7 = 0x6DB6DB6DB6DB6DB7;
        v7 *= v4;
        if (v1 != 28) JUMPOUT(0x1400973db);
        a4 = 0;
        v7 = v_170;
        v4 = 1;
        if (((v7 & 1) != 0)) JUMPOUT(0x140097476);
        return sub_14009748C();
    } else {
        v1 = 0;
        a1 = 0;
        return sub_140097E9F();
    }
}