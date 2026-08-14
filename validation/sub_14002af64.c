// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[24];
    __int64 field_20; // offset 32
};

__int64 sub_140011760();
extern __int64 off_14002B320;
extern __int64 off_1401121E8;
extern __int64 off_140112140;
extern __int64 off_14002B3F0;
extern __int64 off_1401175D8;
extern __int64 off_140112218;
extern __int64 off_14011AB0E;
extern __int64 off_14011220E;

__int64 __fastcall sub_14002AF64() {
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_28;
    int arg_30;
    int arg_38;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    char *str;
    __int64 v3;
    __int64 v4;
    __int64 v6;
    struct Struct_1_t *result;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v7;
    __int64 *v9;
    struct Struct_2_t *ptr;
    __int64 *v8;

    v_30 = v7;
    v_28 = 1;
    v3 = result->field_0;
    v4 = result->field_8;
    v6 = v9 - 64;
    sub_140011760(v3, v4, v6);
    if (result == 0) {
        if (ptr->field_20 == 1) {
            result = ptr->field_0;
            v3 = v9 - 96;
            arg_10 = v3;
            v3 = &off_14002B320;
            arg_18 = v3;
            arg_20 = 0;
            arg_28 = 18;
            v3 = &off_1401121E8;
            v_40 = v3;
            v_38 = 2;
            v3 = &off_140112140;
            v_20 = v3;
            v_18 = 1;
            v_30 = v7;
            v_28 = 2;
            v3 = result->field_0;
            v4 = result->field_8;
            v5 = v9 - 64;
            sub_140011760(v3, v4, v5);
            if (result == 0) {
                if (*v8 != 3) {
                    if (ptr->field_20 == 0) {
                        xmm0 = _mm_loadu_si128((__m128i *)(v8 + 64));
                        _mm_store_si128((__m128i *)&*v9, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)v8);
                        xmm1 = _mm_loadu_si128((__m128i *)(v8 + 16));
                        xmm2 = _mm_loadu_si128((__m128i *)(v8 + 32));
                        xmm3 = _mm_loadu_si128((__m128i *)(v8 + 48));
                        _mm_store_si128((__m128i *)&str, xmm3);
                        _mm_store_si128((__m128i *)&v_20, xmm2);
                        _mm_store_si128((__m128i *)&v_30, xmm1);
                        _mm_store_si128((__m128i *)&v_40, xmm0);
                        result = ptr->field_0;
                        v3 = v9 - 64;
                        v_50 = v3;
                        v3 = &off_14002B3F0;
                        v_48 = v3;
                        v3 = &off_1401175D8;
                        arg_10 = v3;
                        arg_18 = 1;
                        v3 = &off_140112218;
                        arg_30 = v3;
                        arg_38 = 1;
                    } else {
                        xmm0 = _mm_loadu_si128((__m128i *)(v8 + 64));
                        _mm_store_si128((__m128i *)&*v9, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)v8);
                        xmm1 = _mm_loadu_si128((__m128i *)(v8 + 16));
                        xmm2 = _mm_loadu_si128((__m128i *)(v8 + 32));
                        xmm3 = _mm_loadu_si128((__m128i *)(v8 + 48));
                        _mm_store_si128((__m128i *)&str, xmm3);
                        _mm_store_si128((__m128i *)&v_20, xmm2);
                        _mm_store_si128((__m128i *)&v_30, xmm1);
                        _mm_store_si128((__m128i *)&v_40, xmm0);
                        result = ptr->field_0;
                        v3 = v9 - 64;
                        v_50 = v3;
                        v3 = &off_14002B3F0;
                        v_48 = v3;
                        v3 = &off_1401175D8;
                        arg_10 = v3;
                        arg_18 = 1;
                        arg_30 = 0;
                    }
                    v3 = v9 - 80;
                    arg_20 = v3;
                    arg_28 = 1;
                    v3 = result->field_0;
                    v4 = result->field_8;
                    sub_140011760(v3, v4, str);
                    if (result == 0) {
                        result = ptr->field_0;
                        v3 = result->field_0;
                        result = result->field_8;
                        v4 = &off_14011AB0E;
                        v6 = 1;
                        ((__int64 (*)())(result->field_18))();
                        if (result == 0) JUMPOUT(0x14002b14f);
                    }
                } else {
                    result = ptr->field_0;
                    v3 = result->field_0;
                    result = result->field_8;
                    v4 = &off_14011220E;
                    v6 = 9;
                    ((__int64 (*)())(result->field_18))();
                    if (result == 0) {
                        return v6;
                    } else {
                    }
                }
            }
            result = 1;
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}