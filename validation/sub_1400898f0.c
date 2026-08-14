// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[2];
    __int64 field_2; // offset 2
    char _pad_2[30];
    __int64 field_28; // offset 40
    char _pad_28[48];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    char _pad_30[8];
    __int64 field_40; // offset 64
};

__int64 sub_1400831E0();

__int64 __fastcall sub_1400898F0(int *a1, size_t a2, __int64 a3, int *a4) {
    int v_120;
    int v_128;
    int v_130;
    int v_20;
    int v_2c;
    int v_2e;
    int v_30;
    int v_38;
    int v_41;
    int v_43;
    int v_44;
    int v_4c;
    int v_50;
    int v_54;
    int v_60;
    int v_64;
    int v_70;
    int v_74;
    int v_7c;
    int v_84;
    int v_90;
    int v_92;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    char *str;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 result;
    __int64 v5;
    __m128i xmm0;
    __int64 v6;
    __int64 v7;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    ptr2 = (struct Struct_2_t *)a4;
    ptr = (struct Struct_1_t *)a1;
    v2 = v_120;
    v_20 = 1;
    sub_1400831E0(str, a2, a3, v2);
    a1 = (int *)str;
    result = v_41;
    v_90 = result;
    result = v_43;
    v_92 = result;
    if (a1 != 4) {
        result = v_130;
        a2 = v_4c;
        v_38 = a2;
        a2 = v_44;
        v_30 = a2;
        a3 = v_50;
        a2 = v_90;
        v_2c = a2;
        a2 = v_92;
        v_2e = a2;
        a2 = ptr2->field_40;
        if (a2 <= 3) {
            a3 &= 15;
            a4 = (v2 == 5) ? 1 : 0;
            v5 = (__int64)a4;
            v5 <<= 4;
            v5 |= a3;
            v5 += 16;
            a4 = (int *)((__int64)(__int64)a4 | 4);
            a2 <<= 4;
            *(__int64 *)(ptr2 + a2) = (__int64)(0);
            *(__int64 *)(ptr2 + a2 + 1) = (__int64)(a4);
            *(__int64 *)(ptr2 + a2 + 2) = (__int64)(v5);
            a2 = ptr2->field_40;
            ++a2;
            ptr2->field_40 = a2;
            if (a2 <= 3) {
                a2 <<= 4;
                xmm0 = _mm_loadu_si128((__m128i *)v_128);
                _mm_storeu_si128((__m128i *)(ptr2 + a2), xmm0);
                a2 = ptr2->field_40;
                ++a2;
                ptr2->field_40 = a2;
                if (a2 <= 3) {
                    a2 <<= 4;
                    *(__int64 *)(ptr2 + a2) = (__int64)(a1);
                    a1 = (int *)v_2e;
                    *(__int64 *)(ptr2 + a2 + 3) = (__int64)(a1);
                    a1 = (int *)v_2c;
                    *(__int64 *)(ptr2 + a2 + 1) = (__int64)(a1);
                    v6 = v_30;
                    *(__int64 *)(ptr2 + a2 + 4) = (__int64)(v6);
                    a1 = (int *)v_38;
                    *(__int64 *)(ptr2 + a2 + 12) = (__int64)(a1);
                    ptr2->field_40 = ptr2->field_40 + 1;
                }
            }
        }
        v7 = ptr2->field_40;
        v_d0 = v7;
        xmm0 = _mm_loadu_si128((__m128i *)ptr2);
        xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(ptr2 + 32));
        xmm3 = _mm_loadu_si128((__m128i *)(ptr2 + 48));
        _mm_store_si128((__m128i *)&v_c0, xmm3);
        _mm_store_si128((__m128i *)&v_b0, xmm2);
        _mm_store_si128((__m128i *)&v_a0, xmm1);
        _mm_store_si128((__m128i *)&v_90, xmm0);
        *(__int64 *)ptr2 = (__int64)(4);
        ptr2->field_10 = 4;
        ptr2->field_20 = 4;
        ptr2->field_30 = 4;
        ptr2->field_40 = 0;
        v_84 = v_d0;
        xmm0 = _mm_load_si128((__m128i *)&v_90);
        xmm1 = _mm_load_si128((__m128i *)&v_a0);
        xmm2 = _mm_load_si128((__m128i *)&v_b0);
        xmm3 = _mm_load_si128((__m128i *)&v_c0);
        _mm_storeu_si128((__m128i *)&v_74, xmm3);
        _mm_storeu_si128((__m128i *)&v_64, xmm2);
        _mm_storeu_si128((__m128i *)&v_54, xmm1);
        _mm_storeu_si128((__m128i *)&v_44, xmm0);
        *(__int64 *)ptr = (__int64)(186);
        ptr->field_2 = result;
        xmm0 = _mm_loadu_si128((__m128i *)&str);
        xmm1 = _mm_loadu_si128((__m128i *)&v_50);
        xmm2 = _mm_loadu_si128((__m128i *)&v_60);
        xmm3 = _mm_loadu_si128((__m128i *)&v_70);
        _mm_storeu_si128((__m128i *)(ptr + 36), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 52), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 68), xmm2);
        _mm_storeu_si128((__m128i *)(ptr + 84), xmm3);
        v5 = v_7c;
        ptr->field_60 = v5;
        result = v_84;
        ptr->field_68 = result;
    } else {
        result = v_92;
        ptr->field_2 = result;
        result = v_90;
        *(__int64 *)ptr = (__int64)(result);
        ptr->field_28 = 5;
    }
    return result;
}