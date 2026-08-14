// inferred from 2 accesses on `result`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

__int64 sub_14004F470();
__int64 sub_140055430();

__int64 __fastcall sub_1400586E0(__int64 *a1, __int64 *str, int a3, int a4) {
    __int64 arg_10;
    int arg_18;
    int v_28;
    int v_30;
    int v_38;
    int v_60;
    int v_68;
    int v_78;
    int v_88;
    int v_90;
    int v_98;
    char *str2;
    char *str3;
    struct Struct_2_t *ptr;
    struct Struct_1_t *result;
    __int64 v6;
    __m128i xmm0;
    __int64 v4;
    __int64 v2;
    __int64 v5;
    __int64 v7;

    ptr = (struct Struct_2_t *)a1;
    result = (struct Struct_1_t *)arg_10;
    v6 = arg_18;
    if (v6 == 0) {
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_38, xmm0);
        str = 1;
        v_28 = 0;
        v_30 = 8;
        arg_10 = (__int64)result;
        sub_14004F470(str);
    } else {
        a4 = result->field_0;
        a3 = v6 - 1;
        v4 = result + 1;
        arg_10 = v4;
        arg_18 = a3;
        if (a4 != 10) {
            if (a4 == 13) {
                if (a3 != 0) {
                    a3 = result->field_1;
                    a4 = v6 - 2;
                    v2 = result + 2;
                    arg_10 = v2;
                    arg_18 = a4;
                    if (a3 == 10) {
                        *(__int64 *)ptr = (__int64)(3);
                        return arg_18;
                    }
                }
            }
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_38, xmm0);
            str = 1;
            v_28 = 0;
            v_30 = 8;
            arg_10 = (__int64)result;
            arg_18 = v6;
            _mm_storeu_si128((__m128i *)&v_98, xmm0);
            str3 = 1;
            v_88 = 0;
            v_90 = 8;
            sub_140055430(str2, str, str3, a4);
            v5 = v_60;
            v7 = v_78;
            ptr->field_28 = v7;
            xmm0 = _mm_loadu_si128((__m128i *)&v_68);
            _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
            xmm0 = _mm_load_si128((__m128i *)&str2);
            _mm_storeu_si128((__m128i *)ptr, xmm0);
            ptr->field_10 = v5;
            return _mm_cvtsi128_si64(xmm0);
        }
    }
    return (__int64)result;
}