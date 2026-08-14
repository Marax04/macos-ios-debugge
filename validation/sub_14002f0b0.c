// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140011760();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140113FD8;
extern __int64 off_140114EE0;

__int64 __fastcall sub_14002F0B0() {
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_40;
    __int64 v_50;
    int v_58;
    int v_60;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v9;
    __int64 v4;
    __int64 v3;
    __int64 v7;
    struct Struct_1_t *result;
    __int64 v12;
    __int64 v2;
    __int64 v6;
    __int64 v13;
    __int64 v11;
    __int64 v10;
    struct Struct_2_t *ptr;

    v_10 = 0;
    src = *src;
    xmm0 = _mm_loadu_si128((__m128i *)src);
    xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(src + 32));
    _mm_store_si128((__m128i *)&v_60, xmm0);
    _mm_store_si128((__m128i *)&v_40, xmm2);
    _mm_store_si128((__m128i *)&v_50, xmm1);
    v9 = v_58;
    if (v9 != 1) {
    }
    v4 = &off_140113FD8;
    v3 = v13 - 32;
    v7 = v13 - 96;
    sub_140011760(v3, v4, v7);
    xmm0 = _mm_loadu_si128((__m128i *)&v_20);
    _mm_store_si128((__m128i *)&v_60, xmm0);
    result = (struct Struct_1_t *)v_10;
    v_50 = (__int64)result;
    ptr->field_10 = result;
    _mm_storeu_si128((__m128i *)ptr, xmm0);
    v12 = ptr->field_0;
    v2 = ptr->field_8;
    v6 = ptr->field_10;
    *(__int64 *)ptr = (__int64)(0);
    ptr->field_8 = 1;
    ptr->field_10 = 0;
    sub_14002EDF0(0, 24);
    if (result == 0) {
        v_30 = v12;
        v_28 = v2;
        sub_1400F3340(8, 24);
        v_10 = v4;
        v13 = v4 + 128;
        if (v_20 != 0) {
            v11 = v_18;
            off_140108030();
            off_140108038(result, 0, v11);
        }
        return v11;
    } else {
        *(__int64 *)result = (__int64)(v12);
        result->field_8 = v2;
        result->field_10 = v6;
        v10 = &off_140114EE0;
        return (__int64)result;
    }
}