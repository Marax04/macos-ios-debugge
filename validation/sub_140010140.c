// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    char _pad_18[16];
    __int64 field_30; // offset 48
};

// inferred from 6 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
__int64 sub_140010C30();
__int64 sub_140010C70();
__int64 sub_140010701();
__int64 sub_140010EC0();
__int64 sub_140010C90();
__int64 sub_140010D10();
__int64 sub_140010E50();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140010C50;
extern __int64 off_1401175D8;
extern __int64 off_14010AE27;
extern __int64 off_14011AB10;
extern __int64 off_14010AD70;
extern __int64 off_140114C51;
extern __int64 off_140114C66;
extern __int64 off_14010AE33;
extern __int64 off_140108560;
extern __int64 off_14010AE48;
extern __int64 off_14000C620;

__int64 __fastcall sub_140010140(int *a1, __int64 *a2) {
    int arg_10;
    __int64 arg_100;
    int arg_108;
    __int64 arg_110;
    int arg_118;
    int arg_120;
    int arg_150;
    int arg_158;
    __int64 arg_160;
    __int64 arg_170;
    __int64 arg_178;
    int arg_18;
    int arg_180;
    int arg_188;
    int arg_190;
    __int64 arg_30;
    int arg_38;
    int arg_78;
    __int64 arg_8;
    int arg_80;
    int arg_88;
    __int64 arg_90;
    __int64 arg_c0;
    __int64 arg_c8;
    __int64 arg_d0;
    int arg_d8;
    __int64 v_10;
    int v_18;
    __int64 v_20;
    int v_40;
    __int64 str;
    char *dst;
    struct Struct_3_t *ptr3;
    struct Struct_2_t *ptr2;
    __int64 *result;
    __int64 v3;
    struct Struct_1_t *ptr;
    __m128i xmm6;
    __int64 v4;
    __int64 v5;
    __int64 *v11;
    __int64 v9;
    __m128i xmm0;
    __int64 v6;
    __int64 v7;

    _mm_store_si128((__m128i *)&arg_190, xmm6);
    arg_188 = -2;
    ptr3 = (struct Struct_3_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    result = *a1;
    ((__int64 (*)())(arg_8))();
    v3 = (__int64)result;
    ptr = (struct Struct_1_t *)a2;
    v_20 = (__int64)result;
    v_18 = (int)a2;
    if ((a2[2] & 128) != 0) {
        result = ptr->field_18;
        a1 = (int *)v3;
        a2 = (__int64 *)ptr3;
        xmm6 = _mm_load_si128((__m128i *)&arg_190);
        JUMPOUT(result);
    } else {
        result = dst - 32;
        arg_c0 = (__int64)result;
        v4 = &off_140010C50;
        arg_c8 = v4;
        result = &off_1401175D8;
        arg_100 = (__int64)result;
        arg_108 = 1;
        arg_120 = 0;
        result = dst + 192;
        arg_110 = (__int64)result;
        arg_118 = 1;
        a1 = ptr3->field_0;
        a2 = ptr3->field_8;
        v5 = dst + 256;
        sub_140011760(a1, a2, v5);
        a1 = 1;
        if (result == 0) {
            a1 = (int *)v3;
            ((__int64 (*)())(ptr->field_30))();
            arg_178 = (__int64)ptr3;
            if (result != 0) {
                ptr = (struct Struct_1_t *)result;
                v11 = a2;
                a1 = ptr3->field_0;
                result = ptr3->field_8;
                a2 = &off_14010AE27;
                v5 = 12;
                ((__int64 (*)())(arg_18))();
                if (result == 0) {
                    a1 = (int *)ptr;
                    ((__int64 (*)())(*(v11 + 48)))();
                    a1 = 0;
                    a1 = (result != 0) ? 1 : 0;
                    arg_180 = (int)a1;
                    ptr3 = 0;
                    xmm6 = _mm_setzero_si128();
                    if (ptr == 0) {
                        do {
                            ptr = 0;
                            v3 = (__int64)ptr3;
                            result = dst + 144;
                            v9 = 0;
                            *result = v9;
                            result = (__int64 *)arg_90;
                            ptr3 = (struct Struct_3_t *)arg_178;
                            while (result != 0) {
                                a1 = (int *)v_40;
                                arg_8 = (__int64)result;
                                arg_10 = (int)a1;
                                result = &off_14011AB10;
                                arg_100 = (__int64)result;
                                arg_108 = 1;
                                arg_110 = 8;
                                _mm_storeu_si128((__m128i *)&arg_118, xmm6);
                                a1 = ptr3->field_0;
                                a2 = ptr3->field_8;
                                v9 = dst + 256;
                                sub_140010C30(a1, a2, v9);
                                if (result == 0) {
                                    arg_d0 = (__int64)ptr3;
                                    result = (__int64 *)arg_180;
                                    arg_c0 = (__int64)result;
                                    result = (__int64 *)arg_170;
                                    arg_c8 = (__int64)result;
                                    arg_d8 = 0;
                                    result = dst + 8;
                                    arg_30 = (__int64)result;
                                    arg_38 = v4;
                                    result = &off_1401175D8;
                                    arg_100 = (__int64)result;
                                    arg_108 = 1;
                                    arg_120 = 0;
                                    result = dst + 48;
                                    arg_110 = (__int64)result;
                                    arg_118 = 1;
                                    a1 = dst + 192;
                                    sub_140010C70(a1, v9);
                                    if (result == 0) {
                                        ptr3 = (struct Struct_3_t *)v3;
                                        if (ptr != 0) {
                                            v9 = (__int64)v11;
                                            a1 = (int *)ptr;
                                            ((__int64 (*)())(*(v11 + 48)))();
                                            v11 = a2;
                                            arg_90 = (__int64)ptr;
                                            v3 = ptr3 + 1;
                                            ptr = (struct Struct_1_t *)result;
                                            arg_170 = (__int64)ptr3;
                                            result = dst - 64;
                                        }
                                    }
                                }
                                a1 = 1;
                                result = (__int64 *)a1;
                                xmm6 = _mm_load_si128((__m128i *)&arg_190);
                                return _mm_cvtsi128_si64(xmm6);
                            }
                            result = ptr2->field_8;
                            if (result != 3) {
                                ptr2 += 8;
                                if (result == 2) {
                                    arg_78 = 0;
                                    arg_80 = 1;
                                    arg_88 = 0;
                                    result = 0xE0000020;
                                    *dst = result;
                                    result = dst + 120;
                                    v_10 = (__int64)result;
                                    result = &off_14010AD70;
                                    str = (__int64)result;
                                    result = ptr2->field_0;
                                    if (result == 0) {
                                        a2 = &off_140114C51;
                                        a1 = dst + 120;
                                    } else {
                                        if (result != 1) {
                                            result = ptr2->field_28;
                                            if (result != 0) JUMPOUT(0x1400106ab);
                                            ptr = 0x800000;
                                            v3 = ptr2->field_18;
                                            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & *dst);
                                            if ((ptr != 0)) JUMPOUT(0x1400106fd);
                                            a1 = ptr2->field_20;
                                            result = (__int64 *)v3;
                                            result = (__int64 *)((__int64)result - (__int64)a1);
                                            if ((result < 0)) JUMPOUT(0x140010a27);
                                            v4 = (__int64)(__int64)a1 * 56;
                                            v4 += ptr2->field_10;
                                            v3 = (__int64)result;
                                            return sub_140010701();
                                        } else {
                                            a2 = &off_140114C66;
                                            a1 = dst + 120;
                                            v5 = 18;
                                        }
                                    }
                                    sub_140010EC0(a1, a2, 21);
                                    if (result != 0) JUMPOUT(0x140010a4a);
                                    xmm0 = _mm_loadu_si128((__m128i *)&arg_78);
                                    _mm_store_si128((__m128i *)&arg_150, xmm0);
                                    result = (__int64 *)arg_88;
                                    arg_160 = (__int64)result;
                                    a1 = ptr3->field_0;
                                    result = ptr3->field_8;
                                    a2 = &off_14010AE33;
                                    v5 = 2;
                                    ((__int64 (*)())(arg_18))();
                                    if (result == 0) {
                                        v3 = arg_160;
                                        if (v3 >= 16) {
                                            result = (__int64 *)arg_158;
                                            xmm0 = _mm_loadu_si128((__m128i *)result);
                                            xmm0 = _mm_cmpeq_epi8(xmm0, _mm_load_si128((__m128i *)&off_140108560));
                                            result = _mm_movemask_epi8(xmm0);
                                            if (result == 0xFFFF) {
                                                a1 = dst + 336;
                                                sub_140010C90(a1);
                                                v3 = arg_160;
                                            } else {
                                                result = &off_14010AE48;
                                                arg_100 = (__int64)result;
                                                arg_108 = 1;
                                                arg_110 = 8;
                                                xmm0 = _mm_setzero_si128();
                                                _mm_storeu_si128((__m128i *)&arg_118, xmm0);
                                                a1 = ptr3->field_0;
                                                a2 = ptr3->field_8;
                                                v6 = dst + 256;
                                                sub_140010C30(a1, a2, v6);
                                                if (result == 0) {
                                                    a1 = (int *)arg_158;
                                                    sub_140010D10(a1, v3);
                                                    v3 = dst + 336;
                                                    sub_140010E50(v3, result);
                                                    arg_c0 = v3;
                                                    result = &off_14000C620;
                                                    arg_c8 = (__int64)result;
                                                    result = &off_1401175D8;
                                                    arg_100 = (__int64)result;
                                                    arg_108 = 1;
                                                    arg_120 = 0;
                                                    result = dst + 192;
                                                    arg_110 = (__int64)result;
                                                    arg_118 = 1;
                                                    a1 = ptr3->field_0;
                                                    a2 = ptr3->field_8;
                                                    v7 = dst + 256;
                                                    sub_140010C30(a1, a2, v7);
                                                    if (result == 0) {
                                                        if (arg_150 != 0) {
                                                            v3 = arg_158;
                                                            off_140108030();
                                                            off_140108038(result, 0, v3);
                                                        }
                                                        a1 = 0;
                                                    } else {
                                                        if (arg_150 != 0) {
                                                            v3 = arg_158;
                                                            off_140108030();
                                                            off_140108038(result, 0, v3);
                                                        }
                                                        return v3;
                                                    }
                                                    return v3;
                                                } else {
                                                }
                                                return v3;
                                            }
                                            return v3;
                                        }
                                        return v3;
                                    }
                                    return v3;
                                }
                            } else {
                                result = ptr2->field_0;
                                a1 = (int *)ptr2;
                                ((__int64 (*)())(arg_30))();
                                if (result == 0) JUMPOUT(0x140010693);
                                ptr2 = (struct Struct_2_t *)result;
                                result = *result;
                                if (result == 2) {
                                    return (__int64)result;
                                } else {
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            return (__int64)result;
                        } while (true);
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}