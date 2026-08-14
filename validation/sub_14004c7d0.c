// inferred from 3 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 5 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[168];
    __int64 field_A8; // offset 168
    char _pad_A8[168];
    __int64 field_158; // offset 344
    __int64 field_160; // offset 352
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
};

__int64 sub_14004CB70();
__int64 sub_14004CD40();
__int64 sub_140046560();
__int64 sub_140046740();
__int64 sub_14004CA9E();
__int64 sub_140046040();
__int64 sub_140046190();
__int64 sub_1400462A0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14004C7D0(int *a1, __int64 a2) {
    __int64 rsp;
    int arg_10;
    int v_100;
    int v_108;
    int v_110;
    int v_118;
    int v_128;
    int v_138;
    int v_148;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_50;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_e8;
    int v_f0;
    char *str;
    char *str2;
    char *str3;
    char *str4;
    char *str5;
    struct Struct_2_t *ptr;
    __int64 v7;
    __int64 v8;
    __int64 v2;
    __int64 v4;
    struct Struct_1_t *result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v5;
    __int64 v6;
    __m128i xmm2;
    __m128i xmm3;

    ptr = (struct Struct_2_t *)a2;
    v_20 = (int)a1;
    v_28 = 0;
    v_38 = 0;
    sub_14004CB70(str5, ptr);
    v7 = (__int64)str5;
    v8 = v_100;
    v2 = v_108;
    v4 = v_110;
    while (v7 == 2) {
        result = (struct Struct_1_t *)v8;
        result = (struct Struct_1_t *)(-(__int64)result);
        if (!((0 /* overflow check on (-result) */))) {
            sub_14004CD40(str2, ptr);
            v7 = (__int64)str2;
            if (v7 == 2) {
                xmm0 = _mm_loadu_si128((__m128i *)&*str3);
                xmm1 = _mm_loadu_si128((__m128i *)&arg_10);
                _mm_store_si128((__m128i *)&v_50, xmm1);
                _mm_store_si128((__m128i *)&str, xmm0);
                str4 = (char *)v8;
                v_e8 = v2;
                v_f0 = v4;
                a2 = rsp + 40;
                sub_140046560(str2, a2, str4, str);
                sub_140046740(str2);
            }
            v5 = (__int64)str3;
            v6 = v_70;
            v4 = v_78;
            xmm0 = _mm_loadu_si128((__m128i *)&v_80);
            _mm_store_si128((__m128i *)&str, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_90);
            _mm_store_si128((__m128i *)&v_50, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
            _mm_store_si128((__m128i *)&v_c0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_b0);
            _mm_store_si128((__m128i *)&v_d0, xmm0);
            if (v8 != 0) {
                off_140108030();
                off_140108038(result, 0, v2);
            }
            v2 = v6;
            v8 = v5;
            result = (struct Struct_1_t *)v_20;
            xmm0 = _mm_load_si128((__m128i *)&str);
            xmm1 = _mm_load_si128((__m128i *)&v_50);
            _mm_storeu_si128((__m128i *)(result + 48), xmm1);
            _mm_storeu_si128((__m128i *)(result + 32), xmm0);
            *(__int64 *)result = (__int64)(v7);
            result->field_8 = v8;
            result->field_10 = v2;
            result->field_18 = v4;
            xmm0 = _mm_load_si128((__m128i *)&v_c0);
            xmm1 = _mm_load_si128((__m128i *)&v_d0);
            _mm_storeu_si128((__m128i *)(result + 80), xmm1);
            _mm_storeu_si128((__m128i *)(result + 64), xmm0);
            a1 = (int *)v_28;
            if (a1 == 0) JUMPOUT(0x14004ca9a);
            a2 = v_30;
            result = (struct Struct_1_t *)v_38;
            str3 = 0;
            v_70 = (int)a1;
            v_78 = a2;
            v_88 = 0;
            v_90 = (int)a1;
            v_98 = a2;
            a1 = 1;
            return sub_14004CA9E();
        }
        result = (struct Struct_1_t *)v_38;
        a1 = (int *)v_20;
        a1[3] = result;
        xmm0 = _mm_loadu_si128((__m128i *)&v_28);
        _mm_storeu_si128((__m128i *)(a1 + 8), xmm0);
        *a1 = 2;
        a1 = ptr->field_160;
        result = ptr->field_170;
        result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
        result = (struct Struct_1_t *)((__int64)(__int64)result >> 3);
        a2 = 0x8F9C18F9C18F9C19;
        a2 *= (__int64)result;
        sub_140046040(a1, a2);
        if (ptr->field_168 != 0) {
            v4 = ptr->field_158;
            off_140108030();
            off_140108038(result, 0, v4);
        }
        if (ptr->field_A8 != 12) {
            v4 = ptr + 168;
            ptr += 24;
            sub_140046190(ptr);
            sub_1400462A0(v4);
        }
        return (__int64)ptr;
    }
    xmm0 = _mm_loadu_si128((__m128i *)&v_118);
    xmm1 = _mm_loadu_si128((__m128i *)&v_128);
    xmm2 = _mm_loadu_si128((__m128i *)&v_138);
    xmm3 = _mm_loadu_si128((__m128i *)&v_148);
    _mm_store_si128((__m128i *)&v_50, xmm1);
    _mm_store_si128((__m128i *)&str, xmm0);
    _mm_store_si128((__m128i *)&v_c0, xmm2);
    _mm_store_si128((__m128i *)&v_d0, xmm3);
    return (__int64)result;
}