// inferred from 2 accesses on `a4`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 4 accesses on `result`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[336];
    __int64 field_160; // offset 352
    char _pad_160[48];
    __int64 field_198; // offset 408
    char _pad_198[562];
    __int64 field_3D2; // offset 978
};

// inferred from 5 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

// inferred from 4 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
};

__int64 sub_14004274F();
__int64 sub_140042B20();
__int64 sub_14002EDF0();
__int64 sub_14004273D();
__int64 sub_140044330();
__int64 sub_140041BDC();
__int64 sub_1400F27F6();
__int64 sub_140042736();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140041760(__int64 a1, int *a2, __int64 *a3,struct Struct_1_t *a4) {
    int arg_18;
    __int64 arg_1a0;
    __int64 arg_1a8;
    int arg_1b0;
    int arg_1c8;
    __int64 arg_1d0;
    int arg_1e0;
    __int64 arg_20;
    int arg_28;
    int arg_38;
    int arg_40;
    int arg_48;
    __int64 arg_50;
    __int64 arg_58;
    int arg_60;
    int arg_68;
    __int64 arg_70;
    int arg_8;
    __int64 arg_a0;
    __int64 arg_a8;
    int arg_b0;
    int arg_d0;
    int arg_d8;
    int arg_e0;
    int arg_e8;
    __int64 v_20;
    int v_30;
    int v_50;
    char *str;
    struct Struct_3_t *ptr;
    __int64 *i;
    __int64 v8;
    struct Struct_2_t *result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *dst;
    __int64 v2;
    struct Struct_4_t *ptr2;
    __int64 v4;
    __int64 v7;
    __m128i xmm2;
    __int64 v6;

    arg_1e0 = -2;
    ptr = (struct Struct_3_t *)a3;
    i = (__int64 *)a2;
    v8 = a1;
    a2 = *a2;
    if (a2 == 0) {
        a1 = ptr->field_0;
        result = ptr->field_8;
        xmm0 = _mm_loadu_si128((__m128i *)(ptr + 16));
        a2 = ptr->field_20;
        xmm1 = _mm_loadu_si128((__m128i *)(ptr + 40));
        _mm_store_si128((__m128i *)&v_30, xmm1);
        dst = 0;
        a3 = (__int64 *)a1;
        a3 = (__int64 *)(-(__int64)a3);
        if (!((0 /* overflow check on (-a3) */))) {
            xmm0 = _mm_shuffle_epi32(xmm0, 238);
            i = _mm_cvtsi128_si64(xmm0);
            dst = (__int64 *)result;
            i = (__int64 *)((__int64)(__int64)i << 5);
            xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)i));
            xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)i + 16));
            _mm_store_si128((__m128i *)&arg_e0, xmm1);
            _mm_store_si128((__m128i *)&arg_d0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)a4);
            xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
            _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)i + 16), xmm1);
            _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)i), xmm0);
            xmm0 = _mm_load_si128((__m128i *)&arg_d0);
            xmm1 = _mm_load_si128((__m128i *)&arg_e0);
            _mm_storeu_si128((__m128i *)(v8 + 16), xmm1);
            _mm_storeu_si128((__m128i *)v8, xmm0);
            return sub_14004274F();
        }
    } else {
        arg_1c8 = (int)a4;
        a3 = (__int64 *)arg_8;
        v2 = ptr->field_28;
        arg_1d0 = (__int64)ptr;
        result = ptr->field_30;
        v_20 = (__int64)result;
        a1 = str + 208;
        sub_140042B20(a1, a2, a3, v2);
        dst = (__int64 *)arg_d8;
        if (arg_d0 == 0) {
            i = (__int64 *)arg_e8;
            ptr2 = (struct Struct_4_t *)arg_1d0;
            if (ptr2->field_0 != 0) {
                v4 = ptr2->field_8;
                off_140108030(a1, a2, a3, a4);
                off_140108038(result, 0, v4);
            }
            if (ptr2->field_20 != 0) {
                off_140108030();
                off_140108038(result, 0, v2);
            }
            a4 = (struct Struct_1_t *)arg_1c8;
        } else {
            a2 = (int *)arg_1d0;
            a3 = a2 + 40;
            xmm0 = _mm_loadu_si128((__m128i *)&arg_e0);
            _mm_store_si128((__m128i *)&v_50, xmm0);
            a1 = *a2;
            result = (struct Struct_2_t *)arg_8;
            xmm0 = _mm_loadu_si128((__m128i *)(a2 + 16));
            a2 = a2[4];
            xmm1 = _mm_loadu_si128((__m128i *)a3);
            _mm_store_si128((__m128i *)&v_30, xmm1);
            a4 = (struct Struct_1_t *)arg_1c8;
            a3 = (__int64 *)a1;
            a3 = (__int64 *)(-(__int64)a3);
            if ((0 /* overflow check on (-a3) */)) {
                return (__int64)a3;
            } else {
                arg_18 = a1;
                arg_20 = (__int64)result;
                _mm_storeu_si128((__m128i *)&arg_28, xmm0);
                arg_38 = (int)a2;
                xmm0 = _mm_load_si128((__m128i *)&v_30);
                _mm_storeu_si128((__m128i *)&arg_40, xmm0);
                arg_50 = (__int64)i;
                arg_58 = (__int64)dst;
                xmm0 = _mm_load_si128((__m128i *)&v_50);
                _mm_storeu_si128((__m128i *)&arg_60, xmm0);
                ptr2 = a4->field_0;
                v2 = a4->field_8;
                v7 = a4 + 16;
                if (dst == 0) {
                    v4 = (__int64)a4;
                    sub_14002EDF0(0, 984, a3, a4);
                    if (result == 0) JUMPOUT(0x140042780);
                    result->field_160 = 0;
                    *i = result;
                    arg_8 = 0;
                    result->field_3D2 = 1;
                    xmm0 = _mm_loadu_si128((__m128i *)&arg_18);
                    xmm1 = _mm_loadu_si128((__m128i *)&arg_28);
                    xmm2 = _mm_loadu_si128((__m128i *)&arg_38);
                    _mm_storeu_si128((__m128i *)(result + 360), xmm0);
                    _mm_storeu_si128((__m128i *)(result + 376), xmm1);
                    _mm_storeu_si128((__m128i *)(result + 392), xmm2);
                    a1 = arg_48;
                    result->field_198 = a1;
                    *(__int64 *)result = (__int64)(ptr2);
                    result->field_8 = v2;
                    xmm0 = _mm_loadu_si128((__m128i *)v7);
                    _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                    return sub_14004273D();
                } else {
                    arg_1d0 = v7;
                    arg_1a8 = (__int64)ptr2;
                    arg_1b0 = v2;
                    arg_1a0 = (__int64)i;
                    v6 = arg_68;
                    i = *(dst + 978);
                    if (i >= 11) {
                        result = (struct Struct_2_t *)arg_60;
                        i = str + 296;
                        arg_1c8 = (int)a4;
                        arg_70 = (__int64)dst;
                        if (v6 >= 5) JUMPOUT(0x140041b32);
                        v4 = v8;
                        arg_a0 = (__int64)dst;
                        arg_a8 = (__int64)result;
                        arg_b0 = 4;
                        a1 = str + 208;
                        a2 = str + 160;
                        sub_140044330(a1, a2);
                        return sub_140041BDC();
                    } else {
                        v2 = v6 + 1;
                        result = v6 * 56;
                        ptr2 = (__int64)dst + (__int64)result;
                        ptr2 += 360;
                        if (v2 <= i) {
                            result = dst + 360;
                            a1 = v2 * 56;
                            a1 += (__int64)result;
                            v4 = (__int64)dst;
                            dst = i;
                            dst -= v6;
                            a3 = (__int64)(__int64)dst * 56;
                            sub_1400F27F6(a1, ptr2, a3);
                            xmm0 = _mm_loadu_si128((__m128i *)&arg_18);
                            xmm1 = _mm_loadu_si128((__m128i *)&arg_28);
                            xmm2 = _mm_loadu_si128((__m128i *)&arg_38);
                            _mm_storeu_si128((__m128i *)ptr2, xmm0);
                            _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                            _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm2);
                            result = (struct Struct_2_t *)arg_48;
                            ptr2->field_30 = result;
                            result = (struct Struct_2_t *)arg_1d0;
                            xmm0 = _mm_loadu_si128((__m128i *)result);
                            _mm_store_si128((__m128i *)&arg_d0, xmm0);
                            a2 = (int *)v6;
                            a2 = (int *)((__int64)(__int64)a2 << 5);
                            a2 += v4;
                            v2 <<= 5;
                            v2 += v4;
                            dst = (__int64 *)((__int64)(__int64)dst << 5);
                            dst = (__int64 *)v4;
                            sub_1400F27F6(v2, a2, dst);
                        } else {
                            result = (struct Struct_2_t *)arg_48;
                            ptr2->field_30 = result;
                            xmm0 = _mm_loadu_si128((__m128i *)&arg_18);
                            xmm1 = _mm_loadu_si128((__m128i *)&arg_28);
                            xmm2 = _mm_loadu_si128((__m128i *)&arg_38);
                            _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm2);
                            _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                            _mm_storeu_si128((__m128i *)ptr2, xmm0);
                            result = (struct Struct_2_t *)arg_1d0;
                            xmm0 = _mm_loadu_si128((__m128i *)result);
                            _mm_store_si128((__m128i *)&arg_d0, xmm0);
                        }
                        ++i;
                        v6 <<= 5;
                        result = (struct Struct_2_t *)arg_1a8;
                        *(dst + v6) = result;
                        result = (struct Struct_2_t *)arg_1b0;
                        *(dst + v6 + 8) = result;
                        xmm0 = _mm_load_si128((__m128i *)&arg_d0);
                        _mm_storeu_si128((__m128i *)(dst + v6 + 16), xmm0);
                        *(dst + 978) = i;
                        return sub_140042736();
                    }
                }
            }
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}