// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[256];
    char field_100; // offset 256
    __int64 field_101; // offset 257
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F27F0();
extern __int64 off_14011D57D;
extern __int64 off_14011D570;
extern __int64 off_14011D560;
extern __int64 off_14011D550;
extern __int64 off_14011D540;
extern __int64 off_14011D58D;

__int64 __fastcall sub_1400E9AF0(__int64 a1, __int64 *a2) {
    __int64 rsp;
    int arg_8;
    int v_100;
    int v_110;
    int v_130;
    int v_140;
    int v_150;
    int v_160;
    int v_16d;
    int v_20;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    int v_90;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __int64 v8;
    __int64 v7;
    __int64 v6;
    __int64 i;
    __int64 v2;
    __int64 v9;
    __int64 result;
    __int64 v10;

    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&v_110, xmm0);
    _mm_store_si128((__m128i *)&v_100, xmm0);
    _mm_store_si128((__m128i *)&v_f0, xmm0);
    _mm_store_si128((__m128i *)&v_e0, xmm0);
    _mm_store_si128((__m128i *)&v_d0, xmm0);
    _mm_store_si128((__m128i *)&v_c0, xmm0);
    _mm_store_si128((__m128i *)&v_b0, xmm0);
    _mm_store_si128((__m128i *)&v_a0, xmm0);
    _mm_store_si128((__m128i *)&v_90, xmm0);
    _mm_store_si128((__m128i *)&v_80, xmm0);
    _mm_store_si128((__m128i *)&v_70, xmm0);
    _mm_store_si128((__m128i *)&v_60, xmm0);
    _mm_store_si128((__m128i *)&v_50, xmm0);
    _mm_store_si128((__m128i *)&v_40, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm0);
    _mm_store_si128((__m128i *)&v_20, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D57D);
    _mm_storeu_si128((__m128i *)&v_16d, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D570);
    _mm_storeu_si128((__m128i *)&v_160, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D560);
    _mm_storeu_si128((__m128i *)&v_150, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D550);
    _mm_storeu_si128((__m128i *)&v_140, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D540);
    _mm_storeu_si128((__m128i *)&v_130, xmm0);
    v8 = *a2;
    a1 = arg_8;
    v7 = a2[2];
    v6 = a2[3];
    i = 0;
    v2 = 5;
    v9 = &off_14011D58D;
    do {
        result = a1 + a1*4;
        result = __ROL8__(result, 7);
        result += result*8;
        v10 = a1;
        v10 <<= 17;
        v7 ^= v8;
        v6 ^= a1;
        v8 ^= v6;
        v6 = __ROL8__(v6, 45);
        a1 ^= v7;
        result *= v2; /* unsigned; high half in a2 */;
        v7 ^= v10;
        result = *(__int64 *)(rsp + i + 304);
        ++i;
        a2 = *(a2 + v9);
        *(__int64 *)(rsp + result + 32) = a2;
    } while (result == 0);
    result = a1;
    result <<= 17;
    v7 ^= v8;
    v6 ^= a1;
    a2 = (__int64 *)v7;
    a2 = (__int64 *)((__int64)(__int64)a2 ^ a1);
    v8 ^= v6;
    v7 ^= result;
    v6 = __ROL8__(v6, 45);
    v7 ^= v8;
    v6 ^= (__int64)a2;
    result = v7;
    result ^= (__int64)a2;
    i = a2 + (__int64)(__int64)a2*4;
    a2 = (__int64 *)((__int64)(__int64)a2 << 17);
    ptr2->field_8 = result;
    v8 ^= v6;
    *(__int64 *)ptr2 = (__int64)(v8);
    v7 ^= (__int64)a2;
    ptr2->field_10 = v7;
    v6 = __ROL8__(v6, 45);
    ptr2->field_18 = v6;
    i = __ROL8__(i, 7);
    i += i*8;
    result = a1 + a1*4;
    result = __ROL8__(result, 7);
    v2 = result + result*8;
    a2 = rsp + 32;
    sub_1400F27F0(ptr, a2, 256, v6);
    ptr->field_100 = v2;
    ptr->field_101 = i;
    return result;
}