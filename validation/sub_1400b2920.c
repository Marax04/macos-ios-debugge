// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    char _pad_start[96];
    __int64 field_60; // offset 96
    char _pad_60[12];
    __int64 field_74; // offset 116
};

__int64 sub_1400F1D90();
__int64 sub_1400B2A30();
__int64 sub_1400B2F5A();

__int64 __fastcall sub_1400B2920(int a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    int v_18480;
    int v_18490;
    int v_184a0;
    int v_184b0;
    int v_184c0;
    int v_184d0;
    int v_184e0;
    int v_184f0;
    int v_18500;
    int v_18510;
    int v_40;
    int v_48;
    int v_50;
    int v_60;
    int v_88;
    int v_b8;
    int v8;
    __int64 v3;
    int v1;
    __int64 v7;
    __int64 v6;
    int v4;
    int v5;
    __int64 v2;
    __m128i xmm15;
    __m128i xmm14;
    __m128i xmm13;
    __m128i xmm12;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;
    __m128i xmm8;
    __m128i xmm7;
    __m128i xmm6;

    sub_1400F1D90(0x18528);
    _mm_store_si128((__m128i *)&v_18510, xmm15);
    _mm_store_si128((__m128i *)&v_18500, xmm14);
    _mm_store_si128((__m128i *)&v_184f0, xmm13);
    _mm_store_si128((__m128i *)&v_184e0, xmm12);
    _mm_store_si128((__m128i *)&v_184d0, xmm11);
    _mm_store_si128((__m128i *)&v_184c0, xmm10);
    _mm_store_si128((__m128i *)&v_184b0, xmm9);
    _mm_store_si128((__m128i *)&v_184a0, xmm8);
    _mm_store_si128((__m128i *)&v_18490, xmm7);
    _mm_store_si128((__m128i *)&v_18480, xmm6);
    v_88 = (int)a3;
    v8 = a3->field_74;
    v3 = a3->field_60;
    v_60 = v3;
    v_50 = (int)a2;
    v_b8 = a1;
    if ((v8 & 16) != 0) {
        v_40 = v8;
        v1 = 1;
        v_48 = v3;
        v7 = a2->field_20;
        v6 = a2->field_28;
        v4 = 0;
        if (v6 == 0) JUMPOUT(0x1400b2af4);
        v1 = 0x68707A2E;
        a1 = 0x62747368;
        a2 = 0x736C7468;
        v5 = 0x65727A2E;
        v3 = 0x636F6C65;
        v8 = 0x6D766362;
        v2 = v7;
        return sub_1400B2A30();
    } else {
        v1 = 1;
        v_48 = v3;
        v2 = 0;
        return sub_1400B2F5A();
    }
}