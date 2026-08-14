// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

__int64 sub_140020E30();
__int64 sub_140020C60();
__int64 sub_1400F37D0();
__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F8E15();
__int64 sub_1400F4640();
extern __int64 off_140073680;
extern __int64 off_14011B42B;
extern __int64 off_140117360;

__int64 __fastcall sub_1400F8B80(struct Struct_1_t *a1, int a2, __int64 *a3, __int64 *a4) {
    __int64 rsp;
    int v_1040;
    int v_1050;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    int v_90;
    int v_98;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    char *str;
    __int64 v3;
    struct Struct_2_t *result;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v4;
    __int64 v9;
    __int64 v7;
    __int64 v8;
    __int64 v5;
    __int64 v6;
    __m128i xmm7;
    __m128i xmm6;

    v3 = (__int64)a3;
    result = (struct Struct_2_t *)a2;
    v2 = (__int64)a1;
    a1 = a3 + 272;
    a2 = a3[32];
    v_d0 = (int)a1;
    v_d8 = 0;
    v_e0 = a2;
    v_e8 = 1;
    xmm0 = _mm_loadu_si128((__m128i *)a4);
    xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a4 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(a4 + 48));
    _mm_store_si128((__m128i *)&str, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm1);
    _mm_store_si128((__m128i *)&v_40, xmm2);
    _mm_store_si128((__m128i *)&v_50, xmm3);
    xmm0 = _mm_loadu_si128((__m128i *)(a4 + 64));
    _mm_store_si128((__m128i *)&v_60, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(a4 + 80));
    _mm_store_si128((__m128i *)&v_70, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(a4 + 96));
    _mm_store_si128((__m128i *)&v_80, xmm0);
    a1 = a4[14];
    v_90 = (int)a1;
    v_98 = 0;
    a2 = &off_140073680;
    sub_140020E30(result, a2, str);
    result = (struct Struct_2_t *)v_d8;
    if (result == 3) {
        result = (struct Struct_2_t *)v_98;
        xmm0 = _mm_load_si128((__m128i *)&v_a0);
        if (result != 1) {
            if (result == 2) {
                a1 = _mm_cvtsi128_si64(xmm0);
                xmm0 = _mm_shuffle_epi32(xmm0, 238);
                a2 = _mm_cvtsi128_si64(xmm0);
                sub_140020C60(a1, a2);
            }
            a1 = &off_14011B42B;
            v4 = &off_140117360;
            sub_1400F37D0(a1, 40, v4);
            sub_1400F1D90(0x1068);
            _mm_store_si128((__m128i *)&v_1050, xmm7);
            _mm_store_si128((__m128i *)&v_1040, xmm6);
            v9 = a2;
            result = a1->field_0;
            v7 = result->field_108;
            v8 = result->field_100;
            v3 = a2;
            v3 <<= 4;
            result = (struct Struct_2_t *)a2;
            result = (struct Struct_2_t *)((__int64)(__int64)result >> 60);
            result = (result == 0) ? 1 : 0;
            a2 = 0x7FFFFFFFFFFFFFF9;
            a2 = (v3 < a2) ? 1 : 0;
            if (((__int64)result & a2) == 0) {
                sub_1400F3360(a1, a2);
            }
            v5 = a1->field_8;
            v6 = ((__int64 *)a1)[2];
            if (v3 == 0) JUMPOUT(0x1400f8d7a);
            v2 = (__int64)a1;
            sub_14002EDF0(0, v3);
            a1 = (struct Struct_1_t *)v2;
            if (result == 0) JUMPOUT(0x1400f91d3);
            if (v7 != v8) JUMPOUT(0x1400f8d88);
            return sub_1400F8E15();
        }
        _mm_storeu_si128((__m128i *)v2, xmm0);
        xmm0 = _mm_load_si128((__m128i *)&v_b0);
        xmm1 = _mm_load_si128((__m128i *)&v_c0);
        _mm_storeu_si128((__m128i *)(v2 + 16), xmm0);
        _mm_storeu_si128((__m128i *)(v2 + 32), xmm1);
        return _mm_cvtsi128_si64(xmm1);
    }
    a2 = rsp + 216;
    sub_1400F4640(v3, a2);
    result = (struct Struct_2_t *)v_98;
    xmm0 = _mm_load_si128((__m128i *)&v_a0);
    while (result != 1) {
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}