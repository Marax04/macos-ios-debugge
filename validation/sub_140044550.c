// inferred from 2 accesses on `a3`
struct Struct_1_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int64 field_3D0; // offset 976
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[336];
    __int64 field_160; // offset 352
};

// inferred from 5 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[80];
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3600();
__int64 sub_1400F27F0();
__int64 sub_1400F37D0();
__int64 sub_140037300();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140114588;
extern __int64 off_1401145A0;
extern __int64 off_14011D858;
extern __int64 off_140114570;

__int64 __fastcall sub_140044550(int *a1, int *a2,struct Struct_1_t *a3) {
    __int64 rsp;
    int arg_10;
    int arg_20;
    int arg_30;
    int arg_40;
    int arg_48;
    int arg_50;
    __int64 arg_58;
    int arg_60;
    __int64 v_10;
    __int64 v_18;
    __int64 v_20;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_8;
    __int64 *src;
    __int64 *src2;
    struct Struct_3_t *ptr;
    __int64 *dst;
    __int64 v7;
    __int64 *dst2;
    __int64 v8;
    struct Struct_2_t *result;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v5;
    __int64 v6;
    __m128i xmm3;

    src = rsp + 128;
    arg_60 = -2;
    src2 = (__int64 *)a2;
    ptr = (struct Struct_3_t *)a1;
    dst = *a2;
    v7 = *(dst + 978);
    sub_14002EDF0(0, 0x438);
    if (result == 0) {
        sub_1400F3340(8, 0x438);
    } else {
        dst2 = (__int64 *)result;
        result->field_160 = 0;
        v8 = *(src2 + 16);
        result = *(dst + 978);
        v2 = v8;
        v2 = ~v2;
        v2 += (__int64)result;
        *(dst2 + 978) = v2;
        result = v8 * 56;
        a1 = *(__int64 *)((__int64)dst + (__int64)result + 408);
        arg_40 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)result + 360));
        xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)result + 376));
        xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)result + 392));
        _mm_store_si128((__m128i *)&arg_30, xmm2);
        _mm_store_si128((__m128i *)&arg_20, xmm1);
        _mm_store_si128((__m128i *)&arg_10, xmm0);
        result = (struct Struct_2_t *)v8;
        result = (struct Struct_2_t *)((__int64)(__int64)result << 5);
        a1 = *(__int64 *)((__int64)dst + (__int64)result);
        a2 = *(__int64 *)((__int64)dst + (__int64)result + 8);
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)result + 16));
        _mm_store_si128((__m128i *)&v_60, xmm0);
        arg_50 = (int)a2;
        arg_48 = (int)a1;
        if (v2 >= 12) {
            arg_58 = (__int64)dst2;
            v5 = &off_140114588;
            sub_1400F3600(0, v2, 11, v5);
        } else {
            arg_58 = (__int64)src2;
            result = dst + 360;
            v6 = v8 + 1;
            a1 = dst2 + 360;
            a2 = v6 * 56;
            a2 = (int *)((__int64)a2 + (__int64)result);
            a3 = v2 * 56;
            sub_1400F27F0(a1, a2, a3);
            v6 <<= 5;
            v6 += (__int64)dst;
            v2 <<= 5;
            sub_1400F27F0(dst2, v6, v2);
            *(dst + 978) = v8;
            xmm0 = _mm_load_si128((__m128i *)&arg_10);
            xmm1 = _mm_load_si128((__m128i *)&arg_20);
            xmm2 = _mm_load_si128((__m128i *)&arg_30);
            _mm_store_si128((__m128i *)&v_50, xmm0);
            _mm_store_si128((__m128i *)&v_40, xmm1);
            _mm_store_si128((__m128i *)&v_30, xmm2);
            result = (struct Struct_2_t *)arg_40;
            v_20 = (__int64)result;
            xmm0 = _mm_load_si128((__m128i *)&v_60);
            _mm_storeu_si128((__m128i *)&v_8, xmm0);
            result = (struct Struct_2_t *)arg_48;
            v_18 = (__int64)result;
            result = (struct Struct_2_t *)arg_50;
            v_10 = (__int64)result;
            v2 = *(dst2 + 978);
            a3 = v2 + 1;
            if (v2 >= 12) {
                arg_58 = (__int64)dst2;
                v5 = &off_1401145A0;
                sub_1400F3600(0, a3, 12, v5);
            } else {
                v7 -= v8;
                if (v7 != a3) {
                    arg_58 = (__int64)dst2;
                    a1 = &off_14011D858;
                    a3 = &off_140114570;
                    sub_1400F37D0(a1, 40, a3);
                } else {
                    a1 = (int *)dst2;
                    a1 += 984;
                    a2 = dst + v8*8;
                    a2 += 992;
                    a3 = (struct Struct_1_t *)((__int64)(__int64)a3 << 3);
                    sub_1400F27F0(a1, a2, a3);
                    result = (struct Struct_2_t *)arg_58;
                    result = result->field_8;
                    a1 = 0;
                    a2 = a1;
                    a1 += 0;
                    a3 = *(dst2 + (__int64)(__int64)a2*8 + 984);
                    a3->field_160 = dst2;
                    a3->field_3D0 = a2;
                    while (a2 < v2) {
                    }
                    a1 = *src;
                    ptr->field_50 = a1;
                    xmm0 = _mm_load_si128((__m128i *)&v_10);
                    _mm_storeu_si128((__m128i *)(ptr + 64), xmm0);
                    xmm0 = _mm_load_si128((__m128i *)&v_50);
                    xmm1 = _mm_load_si128((__m128i *)&v_40);
                    xmm2 = _mm_load_si128((__m128i *)&v_30);
                    xmm3 = _mm_load_si128((__m128i *)&v_20);
                    _mm_storeu_si128((__m128i *)(ptr + 48), xmm3);
                    _mm_storeu_si128((__m128i *)(ptr + 32), xmm2);
                    _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                    ptr->field_58 = dst;
                    ptr->field_60 = result;
                    ptr->field_68 = dst2;
                    ptr->field_70 = result;
                    return _mm_cvtsi128_si64(xmm3);
                }
            }
        }
        v_10 = (__int64)a2;
        src = a2 + 128;
        if (arg_48 != 0) {
            off_140108030();
            a3 = (struct Struct_1_t *)arg_50;
            off_140108038(result, 0, a3);
        }
        a1 = src + 16;
        return sub_140037300(a1);
    }
    return (__int64)result;
}