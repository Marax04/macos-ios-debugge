// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[64];
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
};

// inferred from 4 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[240];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 4 accesses on `ptr2`
struct Struct_4_t {
    char _pad_start[272];
    __int64 field_110; // offset 272
    __int64 field_118; // offset 280
    __int64 field_120; // offset 288
    __int64 field_128; // offset 296
};

__int64 sub_1400F8CE0();
__int64 sub_1400F50F0();
__int64 sub_1400700E0();
__int64 sub_140073B30();
__int64 sub_140020C60();
__int64 sub_140074030();
extern __int64 off_1400739D0;

__int64 __fastcall sub_140073270(int *a1,struct Struct_1_t *a2, int *a3, int a4) {
    __int64 rsp;
    int arg_100;
    int arg_118;
    int arg_128;
    int arg_8;
    int v_100;
    int v_110;
    int v_120;
    int v_130;
    int v_140;
    int v_150;
    __int64 v_20;
    int v_28;
    int v_38;
    int v_50;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    __int64 v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_c8;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_f0;
    char *str;
    __int64 v2;
    struct Struct_4_t *ptr2;
    struct Struct_3_t *ptr;
    struct Struct_2_t *result;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v8;
    __int64 v6;
    __int64 i;
    __int64 v5;
    __int64 v7;

    v2 = a4;
    ptr2 = (struct Struct_4_t *)a3;
    ptr = (struct Struct_3_t *)a1;
    result = a3 + 272;
    a1 = (int *)arg_100;
    v_a0 = (__int64)result;
    v_a8 = 0;
    v_b0 = (int)a1;
    v_b8 = 0;
    xmm0 = _mm_loadu_si128((__m128i *)a2);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a2 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(a2 + 48));
    _mm_store_si128((__m128i *)&str, xmm0);
    _mm_store_si128((__m128i *)&v_50, xmm1);
    _mm_store_si128((__m128i *)&v_60, xmm2);
    _mm_store_si128((__m128i *)&v_70, xmm3);
    v_80 = 0;
    result = (struct Struct_2_t *)arg_118;
    v8 = result->field_108;
    v6 = result->field_100;
    result = (struct Struct_2_t *)arg_118;
    i = result->field_108;
    a1 = result->field_100;
    result = (struct Struct_2_t *)arg_128;
    a3 = (int *)i;
    a3 = (int *)((__int64)a3 - (__int64)a1);
    if (a3 >= result) {
        result = (struct Struct_2_t *)((__int64)result + (__int64)result);
        a1 = ptr2 + 280;
        v5 = (__int64)a2;
        sub_1400F8CE0(a1, result);
        a2 = (struct Struct_1_t *)v5;
        result = ptr2->field_128;
    }
    v8 -= v6;
    a1 = ptr2->field_120;
    --result;
    result = (struct Struct_2_t *)((__int64)(__int64)result & i);
    result = (struct Struct_2_t *)((__int64)(__int64)result << 4);
    v7 = &off_1400739D0;
    *(__int64 *)((__int64)a1 + (__int64)result) = v7;
    *(__int64 *)((__int64)a1 + (__int64)result + 8) = str;
    result = ptr2->field_118;
    ++i;
    result->field_108 = i;
    a1 = ptr2->field_110;
    a4 = 0x100000000;
    result = a1[62];
    while (!((i < 0))) {
        a3 = (int *)result;
        a3 = (int *)((__int64)(__int64)a3 | a4);
        /* cmpxchg %(__int64)a3, 496(%(__int64)a1) */;
        result = (struct Struct_2_t *)a3;
        result = (struct Struct_2_t *)((__int64)(__int64)result & 0xFFFF);
        if ((result != 0)) {
            if (v8 <= 0) {
                a3 = (int *)((__int64)(__int64)a3 >> 16);
                if (a3 == result) {
                    a1 += 472;
                    v8 = (__int64)a2;
                    sub_1400F50F0(a1, 1);
                    a2 = (struct Struct_1_t *)v8;
                }
                result = a2->field_40;
                a1 = a2->field_48;
                xmm0 = _mm_loadu_si128((__m128i *)(a2 + 80));
                a2 += 96;
                result = result->field_0;
                a4 = *a1;
                a1 = (int *)arg_8;
                v_38 = (int)a2;
                _mm_storeu_si128((__m128i *)&v_28, xmm0);
                v_20 = (__int64)a1;
                a1 = rsp + 192;
                sub_1400700E0(a1, result, v2, a4);
                v2 = v_c0;
                i = v_c8;
                v8 = v_d0;
                result = (struct Struct_2_t *)v_a8;
                if (result != 3) {
                    sub_140073B30(ptr2);
                    while (result != 0) {
                        a1 = (int *)str;
                        a1 = (int *)((__int64)(__int64)a1 ^ (__int64)a2);
                        a3 = (int *)result;
                        a3 = (int *)((__int64)(__int64)a3 ^ v7);
                        a3 = (int *)((__int64)(__int64)a3 | (__int64)a1);
                        if (!((a3 == 0))) {
                            ((__int64 (*)())result)(a2, a2, a3);
                            result = (struct Struct_2_t *)v_a8;
                            result = (struct Struct_2_t *)v_80;
                            a1 = (int *)v_88;
                            a2 = (struct Struct_1_t *)v_90;
                            if (result != 1) {
                                if (result != 2) JUMPOUT(0x140073638);
                                sub_140020C60(a1, a2);
                            }
                            *(__int64 *)ptr = (__int64)(v2);
                            ptr->field_8 = i;
                            ptr->field_10 = v8;
                            v8 = v_98;
                            ptr->field_18 = a1;
                            result = 40;
                            a1 = 32;
                            *(__int64 *)((__int64)ptr + (__int64)a1) = a2;
                            *(__int64 *)((__int64)ptr + (__int64)result) = v8;
                            return (__int64)a1;
                        }
                        xmm0 = _mm_load_si128((__m128i *)&str);
                        xmm1 = _mm_load_si128((__m128i *)&v_50);
                        xmm2 = _mm_load_si128((__m128i *)&v_60);
                        xmm3 = _mm_load_si128((__m128i *)&v_70);
                        _mm_store_si128((__m128i *)&v_c0, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_b0);
                        _mm_store_si128((__m128i *)&v_130, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_a0);
                        _mm_store_si128((__m128i *)&v_120, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_90);
                        _mm_store_si128((__m128i *)&v_110, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_80);
                        _mm_store_si128((__m128i *)&v_100, xmm0);
                        _mm_store_si128((__m128i *)&v_f0, xmm3);
                        _mm_store_si128((__m128i *)&v_e0, xmm2);
                        _mm_store_si128((__m128i *)&v_d0, xmm1);
                        result = (struct Struct_2_t *)v_c0;
                        if (result == 0) JUMPOUT(0x140073665);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_d8);
                        a1 = (int *)v_c8;
                        a2 = (struct Struct_1_t *)v_78;
                        v_150 = (int)a2;
                        xmm1 = _mm_loadu_si128((__m128i *)&v_68);
                        _mm_store_si128((__m128i *)&v_140, xmm1);
                        a2 = result->field_0;
                        a2 -= *a1;
                        result = (struct Struct_2_t *)v_d0;
                        a4 = result->field_0;
                        result = result->field_8;
                        a1 = ptr + 24;
                        a3 = rsp + 320;
                        v_38 = (int)a3;
                        _mm_storeu_si128((__m128i *)&v_28, xmm0);
                        v_20 = (__int64)result;
                        sub_1400700E0(a1, a2, v2, a4);
                        a1 = rsp + 256;
                        sub_140074030(a1);
                        *(__int64 *)ptr = (__int64)(v2);
                        result = 16;
                        a1 = 8;
                        a2 = (struct Struct_1_t *)i;
                        return (__int64)a2;
                    }
                    result = (struct Struct_2_t *)v_a8;
                    if (result != 3) JUMPOUT(0x140073650);
                }
                return (__int64)result;
            }
            return (__int64)result;
        } else {
        }
        return (__int64)result;
    }
    a3 = (int *)result;
    result = (struct Struct_2_t *)a3;
    result = (struct Struct_2_t *)((__int64)(__int64)result & 0xFFFF);
    if (!((result == 0))) {
        return (__int64)result;
    }
    return (__int64)result;
}