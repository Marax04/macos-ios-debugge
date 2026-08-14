// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_1400F27F0();
__int64 sub_14006A4F6();
__int64 sub_140053180();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_140054AA0();
__int64 sub_14004F470();
__int64 sub_140055430();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140122338;
extern __int64 off_14011E7C0;
extern __int64 off_14011E788;
extern __int64 off_14011AB0E;

__int64 __fastcall sub_140068F70(size_t *a1, int *a2) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    __int64 arg_18;
    int arg_20;
    __int64 arg_28;
    __int64 arg_30;
    __int64 arg_38;
    int arg_40;
    int arg_58;
    int arg_70;
    int arg_8;
    int arg_88;
    int v_100;
    int v_108;
    int v_110;
    int v_150;
    __int64 v_20;
    __int64 v_200;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    int v_68;
    int v_70;
    int v_78;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_c8;
    int v_d8;
    __int64 v_e0;
    int v_e8;
    int v_f0;
    __int64 *v_0;
    __int64 *result;
    __int64 v5;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 v2;
    __int64 v9;
    __int64 v6;
    struct Struct_2_t *ptr2;
    __int64 v8;
    __int64 v10;
    __m128i xmm0;
    __m128i xmm6;

    result = *a2;
    v5 = result - 8;
    ptr = 1;
    if (result < 8) v5 = ptr;
    dst = (__int64 *)a1;
    switch (v5) {
        case 0:
            a1 = dst + 8;
            sub_1400F27F0(a1, a2, 176);
            return (__int64)a1;
        case 1:
            a1 = dst + 8;
            sub_1400F27F0(a1, a2, 176);
            return (__int64)a1;
        case 4:
            a1 = &off_140122338;
            result = v_0[(__int64)result];
            result = (__int64 *)((__int64)result + (__int64)a1);
            JUMPOUT(result);
            v_28 = 0x305C;
            return sub_14006A4F6();
        default:
            v_40 = (__int64)dst;
            result = (__int64 *)arg_20;
            v_38 = (__int64)result;
            result = (__int64 *)arg_28;
            v_20 = (__int64)result;
            result = (__int64 *)arg_30;
            v_30 = (__int64)result;
            if (result != 0) {
                ptr = v_30 * 176;
                v2 = rsp + 520;
                v9 = rsp + 336;
                v6 = rsp + 144;
                ptr2 = (struct Struct_2_t *)v_20;
                do {
                    v_150 = 8;
                    dst = rsp + 696;
                    sub_1400F27F0(dst, ptr2, 176);
                    sub_1400F27F0(ptr2, v9, 176);
                    sub_140068F70(v6, dst);
                    v8 = v_90;
                    a2 = rsp + 152;
                    sub_1400F27F0(v2, a2, 176);
                    dst = 1;
                    a2 = (int *)v9;
                    v10 = v2;
                    v8 = ptr2 + 176;
                    sub_1400F27F0(v6, a2, 176);
                    v_200 = (__int64)dst;
                    sub_140053180(v10);
                    sub_140053180(ptr2);
                    sub_1400F27F0(ptr2, v6, 176);
                    ptr2 = (struct Struct_2_t *)v8;
                    ptr -= 176;
                } while (!((ptr == 0)));
            }
            v9 = v_30 * 176;
            ptr = (struct Struct_1_t *)v_20;
            v9 += (__int64)ptr;
            result = 0;
            ptr2 = 6;
            v8 = 0x8000000000000003;
            v6 = 0x8000000000000000;
            v2 = &off_14011E7C0;
            while (ptr != v9) {
                a1 = ptr->field_0;
                ptr += 176;
                v10 = result + 1;
                if (result == 0) {
                    dst = (__int64 *)v2;
                    result = a1 - 2;
                    if (a1 < 2) result = ptr2;
                    a1 = &off_14011E788;
                    v2 = v_0[(__int64)result];
                    result = *(__int64 *)(ptr + v2 - 176);
                    if (result == v8) {
                        result = *(__int64 *)(ptr + v2 - 152);
                        if (result == v8) {
                            *(__int64 *)(ptr + v2 - 176) = (__int64)(v6);
                            *(__int64 *)(ptr + v2 - 160) = (__int64)(1);
                            *(__int64 *)(ptr + v2 - 152) = (__int64)(v6);
                            result = (__int64 *)v10;
                            v2 = (__int64)dst;
                        }
                        if (result <= 0) {
                            return v2;
                        }
                        result = *(__int64 *)(ptr + v2 - 144);
                        v_28 = (__int64)result;
                        off_140108030();
                        v5 = v_28;
                        off_140108038(result, 0, v5);
                        return v5;
                    }
                    if (result <= 0) {
                        return v5;
                    }
                    result = *(__int64 *)(ptr + v2 - 168);
                    v_28 = (__int64)result;
                    off_140108030(a1);
                    v5 = v_28;
                    off_140108038(result, 0, v5);
                    return v5;
                }
                result = a1 - 2;
                if (a1 < 2) result = ptr2;
                ptr2 = v_0[(__int64)result];
                sub_14002EDF0(0, 1);
                if (result != 0) {
                    dst = result;
                    *result = 32;
                    result = *(__int64 *)((__int64)ptr + (__int64)ptr2 - 176);
                    if (result == v8) {
                        result = *(__int64 *)((__int64)ptr + (__int64)ptr2 - 152);
                        if (result == v8) {
                            *(__int64 *)((__int64)ptr + (__int64)ptr2 - 176) = 1;
                            *(__int64 *)((__int64)ptr + (__int64)ptr2 - 168) = dst;
                            *(__int64 *)((__int64)ptr + (__int64)ptr2 - 160) = 1;
                            *(__int64 *)((__int64)ptr + (__int64)ptr2 - 152) = v6;
                            result = (__int64 *)v10;
                            ptr2 = 6;
                        }
                        if (result <= 0) {
                            return (__int64)ptr2;
                        }
                        v6 = v2;
                        v2 = *(__int64 *)((__int64)ptr + (__int64)ptr2 - 144);
                        off_140108030();
                        v2 = v6;
                        v6 = 0x8000000000000000;
                        off_140108038(result, 0, v2);
                        return v6;
                    }
                    if (result <= 0) {
                        return v6;
                    }
                    v6 = v2;
                    v2 = *(__int64 *)((__int64)ptr + (__int64)ptr2 - 168);
                    off_140108030();
                    v2 = v6;
                    v6 = 0x8000000000000000;
                    off_140108038(result, 0, v2);
                    return v6;
                }
                sub_1400F3326(1, 1);
                _mm_store_si128((__m128i *)&v_110, xmm6);
                ptr = (struct Struct_1_t *)a1;
                result = (__int64 *)arg_18;
                if (result != 0) {
                    dst = (__int64 *)a2;
                    a1 = (size_t *)arg_10;
                    a2 = *a1;
                    v6 = result - 1;
                    ptr2 = a1 + 1;
                    arg_10 = (__int64)ptr2;
                    arg_18 = v6;
                    if (a2 != 10) {
                        if (a2 == 13) {
                            if (v6 != 0) {
                                if (arg_1 != 10) {
                                    xmm0 = _mm_setzero_si128();
                                    _mm_store_si128((__m128i *)&v_20, xmm0);
                                    v2 = 1;
                                } else {
                                    result -= 2;
                                    a1 += 2;
                                    ptr2 = (struct Struct_2_t *)a1;
                                    v6 = (__int64)result;
                                    v_c8 = 0;
                                    v_d8 = 0;
                                    result = &off_14011AB0E;
                                    v_e0 = (__int64)result;
                                    v_e8 = 1;
                                    v_f0 = 0;
                                    v_100 = 1;
                                    v_108 = 0x920;
                                    xmm6 = _mm_setzero_si128();
                                    if (v6 == 0) {
                                        result = rsp + 176;
                                        _mm_storeu_si128((__m128i *)result, xmm6);
                                        v_98 = 1;
                                        v_a0 = 0;
                                        v_a8 = 8;
                                        arg_10 = (__int64)ptr2;
                                        arg_18 = v6;
                                        a1 = rsp + 104;
                                        a2 = rsp + 240;
                                        sub_140054AA0(a1, a2, dst);
                                        v2 = v_68;
                                        while (v2 != 1) {
                                            v9 = v_70;
                                            v10 = v_78;
                                            result = rsp + 128;
                                            xmm0 = _mm_loadu_si128((__m128i *)result);
                                            _mm_store_si128((__m128i *)&v_50, xmm0);
                                            v8 = v_90;
                                            a1 = rsp + 152;
                                            sub_14004F470(a1);
                                            if (v2 == 3) {
                                                result = (__int64 *)arg_18;
                                                while (result != v6) {
                                                    ptr2 = (struct Struct_2_t *)arg_10;
                                                    v6 = (__int64)result;
                                                    if (result != 0) {
                                                        a1 = ptr2->field_0;
                                                        result = v6 - 1;
                                                        a2 = ptr2 + 1;
                                                        arg_10 = (__int64)a2;
                                                        arg_18 = (__int64)result;
                                                        a1 = ptr2->field_1;
                                                        result = v6 - 2;
                                                        a2 = ptr2 + 2;
                                                        arg_10 = (__int64)a2;
                                                        arg_18 = (__int64)result;
                                                    }
                                                }
                                                xmm0 = _mm_setzero_si128();
                                                _mm_store_si128((__m128i *)&v_20, xmm0);
                                                v2 = 2;
                                                v10 = 8;
                                                v9 = 0;
                                                *(__int64 *)ptr = (__int64)(v2);
                                                ptr->field_8 = v9;
                                                ptr->field_10 = v10;
                                                xmm0 = _mm_load_si128((__m128i *)&v_20);
                                                _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
                                                ptr->field_28 = v8;
                                                xmm6 = _mm_load_si128((__m128i *)&v_110);
                                                return _mm_cvtsi128_si64(xmm6);
                                            }
                                            if (v2 != 1) {
                                                xmm0 = _mm_load_si128((__m128i *)&v_50);
                                                _mm_store_si128((__m128i *)&v_20, xmm0);
                                                return _mm_cvtsi128_si64(xmm0);
                                            } else {
                                                v_20 = 1;
                                                v_28 = v9;
                                                v_30 = v10;
                                                xmm0 = _mm_load_si128((__m128i *)&v_50);
                                                _mm_storeu_si128((__m128i *)&v_38, xmm0);
                                                v_48 = v8;
                                                arg_10 = (__int64)ptr2;
                                                arg_18 = v6;
                                                a1 = rsp + 32;
                                                sub_14004F470(a1);
                                                *(__int64 *)ptr = (__int64)(3);
                                            }
                                            return (__int64)a1;
                                        }
                                        a1 = rsp + 32;
                                        a2 = rsp + 152;
                                        v5 = rsp + 104;
                                        sub_140055430(a1, a2, v5);
                                        v2 = v_20;
                                        v9 = v_28;
                                        v10 = v_30;
                                        xmm0 = _mm_loadu_si128((__m128i *)&v_38);
                                        _mm_store_si128((__m128i *)&v_50, xmm0);
                                        v8 = v_48;
                                        return v8;
                                    }
                                    return v8;
                                }
                                return v8;
                            }
                        }
                        return v8;
                    }
                    return v8;
                }
                return v8;
            }
            dst = (__int64 *)v_40;
            arg_8 = 7;
            arg_10 = 0;
            result = (__int64 *)v_38;
            arg_28 = (__int64)result;
            result = (__int64 *)v_20;
            arg_30 = (__int64)result;
            result = (__int64 *)v_30;
            arg_38 = (__int64)result;
            arg_40 = v6;
            arg_58 = v8;
            arg_70 = v8;
            arg_88 = 0;
            ptr = 0;
            *dst = ptr;
            return (__int64)result;
    }
}