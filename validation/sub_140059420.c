// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140059720();
__int64 sub_14004F470();
__int64 sub_1400596F2();
__int64 sub_140059AA0();
__int64 sub_140055430();
__int64 sub_14005969C();

__int64 __fastcall sub_140059420(size_t *a1, int *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int v_100;
    int v_108;
    int v_110;
    int v_118;
    int v_20;
    int v_21;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_60;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_a0;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    int v_f8;
    char *str;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 v10;
    __int64 v7;
    __int64 result;
    __int64 v8;
    __int64 v11;
    __int64 v9;
    __int64 v2;
    __m128i xmm0;
    __int64 v5;
    __int64 v6;

    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    v10 = arg_10;
    v7 = arg_18;
    v_a0 = 0;
    v_b0 = 1;
    result = 0x9207E5D005B2300;
    v_b8 = result;
    v_c0 = 0xFF800021;
    a1 = rsp + 112;
    a2 = rsp + 160;
    sub_140059720(a1, a2, ptr2);
    v8 = v_70;
    if (v8 != 1) {
        v11 = v_78;
        v9 = v_80;
        v2 = v_88;
        xmm0 = _mm_loadu_si128((__m128i *)&v_90);
        _mm_store_si128((__m128i *)&v_20, xmm0);
        if (v8 == 3) JUMPOUT(0x1400596df);
        if (v8 == 1) {
            v_30 = 1;
            v_38 = v11;
            v_40 = v9;
            v_48 = v2;
            xmm0 = _mm_load_si128((__m128i *)&v_20);
            _mm_storeu_si128((__m128i *)&v_50, xmm0);
            ptr2->field_10 = v10;
            ptr2->field_18 = v7;
            result = 0x8000000000000001;
            ptr->field_8 = result;
            *(__int64 *)ptr = (__int64)(3);
            a1 = rsp + 48;
            sub_14004F470(a1);
            return sub_1400596F2();
        }
    } else {
        ptr2->field_10 = v10;
        ptr2->field_18 = v7;
        a1 = rsp + 48;
        sub_140059AA0(a1, ptr2);
        v5 = v_30;
        if (v5 != 3) {
            v11 = v_38;
            v6 = v_40;
            v2 = v_48;
            xmm0 = _mm_loadu_si128((__m128i *)&v_50);
            _mm_store_si128((__m128i *)&v_60, xmm0);
            if (v8 != 1) JUMPOUT(0x1400596c1);
            str = 1;
            v_d0 = v11;
            v_d8 = v6;
            v_e0 = v2;
            xmm0 = _mm_load_si128((__m128i *)&v_60);
            _mm_storeu_si128((__m128i *)&v_e8, xmm0);
            a1 = rsp + 248;
            a2 = rsp + 112;
            sub_140055430(a1, a2, str);
            v8 = v_f8;
            v11 = v_100;
            v9 = v_108;
            v2 = v_110;
            xmm0 = _mm_loadu_si128((__m128i *)&v_118);
            _mm_store_si128((__m128i *)&v_20, xmm0);
            if (v8 == 1) {
                return result;
            }
        } else {
            a1 = (size_t *)v_38;
            v_20 = 0;
            if (a1 >= 128) {
                result = (__int64)a1;
                result &= 63;
                result |= 128;
                a2 = (int *)a1;
                a2 = (int *)((__int64)(__int64)a2 >> 6);
                if (a1 >= 0x800) JUMPOUT(0x14005964b);
                a2 = (int *)((__int64)(__int64)a2 | 192);
                v_20 = (int)a2;
                v_21 = result;
                v2 = 2;
                return sub_14005969C();
            } else {
                v_20 = (int)a1;
                v2 = 1;
                return sub_14005969C();
            }
        }
    }
    xmm0 = _mm_load_si128((__m128i *)&v_20);
    _mm_storeu_si128((__m128i *)(ptr + 32), xmm0);
    *(__int64 *)ptr = (__int64)(v8);
    ptr->field_8 = v11;
    ptr->field_10 = v9;
    ptr->field_18 = v2;
    return sub_1400596F2();
}