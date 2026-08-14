// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[795];
    char field_31B; // offset 795
    __int64 field_31C; // offset 796
};

__int64 sub_1400F1D90();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400EA962();

__int64 __fastcall sub_1400EA760(int a1,struct Struct_1_t *a2, __int64 a3, __int64 a4) {
    int v_100;
    int v_108;
    int v_110;
    int v_118;
    int v_1190;
    int v_11a0;
    int v_11b0;
    int v_11c0;
    int v_11d0;
    int v_11e0;
    int v_11f0;
    int v_120;
    int v_1200;
    int v_1210;
    int v_1220;
    int v_158;
    int v_160;
    int v_168;
    int v_170;
    int v_2b0;
    int v_70;
    int v_f8;
    __int64 v2;
    __int64 result;
    int v9;
    __int64 v7;
    __int64 v3;
    __int64 v4;
    __int64 v8;
    __int64 v5;
    __int64 v6;
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

    sub_1400F1D90(0x1238);
    _mm_store_si128((__m128i *)&v_1220, xmm15);
    _mm_store_si128((__m128i *)&v_1210, xmm14);
    _mm_store_si128((__m128i *)&v_1200, xmm13);
    _mm_store_si128((__m128i *)&v_11f0, xmm12);
    _mm_store_si128((__m128i *)&v_11e0, xmm11);
    _mm_store_si128((__m128i *)&v_11d0, xmm10);
    _mm_store_si128((__m128i *)&v_11c0, xmm9);
    _mm_store_si128((__m128i *)&v_11b0, xmm8);
    _mm_store_si128((__m128i *)&v_11a0, xmm7);
    _mm_store_si128((__m128i *)&v_1190, xmm6);
    v2 = a4;
    v_2b0 = a1;
    result = a2->field_31B;
    if (result == 0) {
        v9 = 1;
    } else {
        a1 = result;
        v9 = 10;
        if (result < 10) v9 = result;
    }
    v_158 = (int)a2;
    result = a2->field_31C;
    a1 = 100;
    if (result < 100) a1 = result;
    v_70 = a1;
    v7 = v9;
    if (v7 != 0) {
        result = v7;
        result <<= 7;
        v3 = result + result*4;
        sub_14002EDF0(0, v3);
        if (result == 0) JUMPOUT(0x1400ef4b1);
        v_110 = v7;
        v_118 = result;
        v_120 = 0;
        v4 = v7 * 920;
        sub_14002EDF0(0, v4);
        if (result == 0) JUMPOUT(0x1400ef4b1);
        v8 = result;
        v_f8 = v7;
        v_100 = result;
        v_108 = 0;
        result = v7;
        result <<= 9;
        v5 = result + v7*8;
        sub_14002EDF0(0, v5);
        v6 = result;
        result = v7;
        if (v6 == 0) {
            sub_1400F3326(1, v5);
            v_110 = 0;
            v_118 = 8;
            v_120 = 0;
            v_f8 = 0;
            v_100 = 8;
            v_108 = 0;
            v6 = 1;
            v8 = 8;
            result = 0;
        }
        v_160 = result;
        v_168 = v6;
        v_170 = 0;
        if (v2 == 0) JUMPOUT(0x1400eaa08);
        a1 = 0;
        result = 0;
        return sub_1400EA962();
    }
    return result;
}