// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_1400675A0();
__int64 sub_14004F470();
__int64 sub_140055430();
__int64 sub_1400F8440();
__int64 sub_140068B20();
__int64 sub_1400685B0();
__int64 sub_1400F37A0();
__int64 sub_1400679E0();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_1400196A0();
__int64 sub_14002EDF0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401085D0;
extern __int64 off_140108480;
extern __int64 off_140116BB0;
extern __int64 off_1401085D8;
extern __int64 off_140116BA8;
extern __int64 off_14011AF40;
extern __int64 off_1401162A8;
extern __int64 off_140115A48;

__int64 __fastcall sub_140065200(size_t *a1, int *a2) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    __int64 arg_18;
    int arg_2;
    int arg_8;
    int v_100;
    int v_108;
    int v_110;
    int v_111;
    int v_118;
    int v_119;
    int v_11d;
    int v_11f;
    int v_120;
    int v_128;
    int v_130;
    int v_138;
    int v_140;
    int v_148;
    int v_150;
    int v_151;
    int v_155;
    __int64 v_157;
    int v_158;
    int v_160;
    int v_168;
    int v_170;
    int v_178;
    int v_180;
    int v_181;
    int v_185;
    __int64 v_187;
    int v_188;
    int v_190;
    int v_198;
    int v_1a0;
    int v_1a8;
    int v_1b0;
    int v_1b8;
    int v_1c0;
    int v_1c8;
    int v_1d0;
    int v_1d8;
    int v_1e0;
    int v_1e8;
    int v_1f0;
    int v_1f8;
    int v_200;
    int v_208;
    int v_210;
    int v_220;
    int v_228;
    int v_230;
    int v_238;
    int v_248;
    int v_250;
    __int64 v_28;
    int v_30;
    int v_31;
    int v_35;
    __int64 v_37;
    int v_38;
    int v_40;
    __int64 v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    int v_68;
    __int64 v_70;
    int v_78;
    __int64 v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_c8;
    int v_d8;
    int v_e8;
    int v_f0;
    int v_f8;
    __int64 *v_0;
    __int64 *v_10;
    __int64 *v_8;
    __int64 i;
    struct Struct_2_t *ptr;
    __int64 v8;
    __int64 i2;
    __int64 *src;
    __int64 v11;
    __int64 v2;
    __int64 v12;
    struct Struct_1_t *result;
    __m128i xmm0;
    __int64 v5;
    __int64 v7;
    __int64 v6;
    __m128i xmm1;

    i = (__int64)a2;
    ptr = (struct Struct_2_t *)a1;
    v8 = a2[2];
    i2 = a2[3];
    a1 = rsp + 40;
    sub_1400675A0(a1);
    src = (__int64 *)v_28;
    v_a8 = i2;
    if (src != 3) {
        v_70 = v8;
        v8 = v_30;
        v11 = v_38;
        i2 = v_40;
        v2 = v_48;
        v12 = v_50;
        if (src == 1) {
            v_1a8 = 1;
            v_1b0 = v8;
            v_1b8 = v11;
            v_1c0 = i2;
            v_1c8 = v2;
            v_1d0 = v12;
            v11 = v_a8;
            src = (__int64 *)v_70;
            if (v11 != 0) {
                v2 = *src;
                result = v11 - 1;
                a1 = src + 1;
                arg_10 = (__int64)a1;
                arg_18 = (__int64)result;
                v12 = 1;
                if (v2 != 43) {
                    if (v2 != 45) {
                        xmm0 = _mm_setzero_pd();
                        _mm_storeu_si128((__m128i *)&v_40, xmm0);
                        v_28 = 1;
                        v_30 = 0;
                        v_38 = 8;
                        arg_10 = (__int64)src;
                        arg_18 = v11;
                        a1 = rsp + 40;
                        sub_14004F470(a1);
                        v12 = 0;
                        result = (struct Struct_1_t *)v11;
                        a1 = (size_t *)src;
                    }
                }
                if (result == 0) {
                    xmm0 = _mm_setzero_pd();
                    _mm_storeu_si128((__m128i *)&v_90, xmm0);
                    v_78 = 1;
                    v_80 = 0;
                    v_88 = 8;
                } else {
                    a2 = (*a1 != 105) ? 1 : 0;
                    v5 = (result == 1) ? 1 : 0;
                    v5 |= (__int64)a2;
                    if (!((v5 != 0))) {
                        a2 = (arg_1 != 110) ? 1 : 0;
                        v5 = (result == 2) ? 1 : 0;
                        v5 |= (__int64)a2;
                        if (!((v5 != 0))) {
                            a2 = (arg_2 != 102) ? 1 : 0;
                            v5 = (result < 3) ? 1 : 0;
                            v5 |= (__int64)a2;
                            if ((v5 == 0)) {
                                a1 += 3;
                                result -= 3;
                                arg_10 = (__int64)a1;
                                arg_18 = (__int64)result;
                                xmm0 = _mm_loadl_epi64((__m128i *)&off_1401085D0);
                                src = 3;
                                if (v12 != 0) {
                                    if (v2 != 43) {
                                        result = (struct Struct_1_t *)v2;
                                        if (v2 != 45) JUMPOUT(0x140065ef0);
                                        xmm0 = _mm_xor_si128(xmm0, _mm_load_si128((__m128i *)&off_140108480));
                                    }
                                }
                            } else {
                                xmm0 = _mm_setzero_pd();
                                _mm_storeu_si128((__m128i *)&v_90, xmm0);
                                v_78 = 1;
                                v_80 = 0;
                                v_88 = 8;
                                a2 = (*a1 != 110) ? 1 : 0;
                                v5 = (result == 1) ? 1 : 0;
                                v5 |= (__int64)a2;
                                if (!((v5 != 0))) {
                                    a2 = (arg_1 != 97) ? 1 : 0;
                                    v5 = (result == 2) ? 1 : 0;
                                    v5 |= (__int64)a2;
                                    if (!((v5 != 0))) {
                                        a2 = (arg_2 != 110) ? 1 : 0;
                                        v5 = (result < 3) ? 1 : 0;
                                        v5 |= (__int64)a2;
                                        if ((v5 != 0)) {
                                            _mm_storeu_si128((__m128i *)&v_c8, xmm0);
                                            v_b0 = 1;
                                            v_b8 = 0;
                                            v_c0 = 8;
                                            a1 = rsp + 40;
                                            a2 = rsp + 120;
                                            v5 = rsp + 176;
                                            sub_140055430(a1, a2, v5);
                                            src = (__int64 *)v_28;
                                            xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                                            i2 = v_40;
                                            v2 = v_48;
                                            v12 = v_50;
                                            if (src != 1) {
                                                v11 = v_38;
                                                v8 = _mm_cvtsi128_si64(xmm0);
                                                a1 = rsp + 424;
                                                sub_14004F470(a1);
                                                if (src != 3) {
                                                    if (src != 0) {
                                                        v_28 = v8;
                                                        v_30 = v11;
                                                        v_38 = i2;
                                                        v_40 = v2;
                                                        v_48 = v12;
                                                        if (i2 == v8) {
                                                            a1 = rsp + 40;
                                                            sub_1400F8440(a1, 8, 48, 40);
                                                            v8 = v_28;
                                                            v11 = v_30;
                                                        }
                                                        a2 = rsp + 48;
                                                        result =  + i2*2;
                                                        result += i2;
                                                        v_0[(__int64)result] = 3;
                                                        a1 = &off_140116BB0;
                                                        v_8[(__int64)result] = a1;
                                                        v_10[(__int64)result] = 21;
                                                        ++i2;
                                                        v_38 = i2;
                                                        a1 = (size_t *)arg_8;
                                                        result = a2[2];
                                                        v7 = a2[3];
                                                    }
                                                    ptr->field_10 = v8;
                                                    ptr->field_18 = v11;
                                                    v8 = v7;
                                                } else {
                                                    a2 = 4;
                                                    v5 = 80;
                                                    result = 0x8000000000000003;
                                                    v6 = 56;
                                                    src = (__int64 *)result;
                                                    a1 = (size_t *)result;
                                                }
                                                *(__int64 *)(ptr + v6) = (__int64)(result);
                                                *(__int64 *)(ptr + v5) = (__int64)(v8);
                                                *(__int64 *)ptr = (__int64)(a2);
                                                ptr->field_8 = src;
                                                ptr->field_20 = a1;
                                                return (__int64)a1;
                                            } else {
                                                v_208 = 1;
                                                _mm_storeu_si128((__m128i *)&v_210, xmm0);
                                                v_220 = i2;
                                                v_228 = v2;
                                                v_230 = v12;
                                                a1 = rsp + 472;
                                                a2 = rsp + 424;
                                                v5 = rsp + 520;
                                                sub_140055430(a1, a2, v5);
                                                src = (__int64 *)v_1d8;
                                                v8 = v_1e0;
                                                v11 = v_1e8;
                                                i2 = v_1f0;
                                                v2 = v_1f8;
                                                v12 = v_200;
                                            }
                                            return v12;
                                        } else {
                                            a1 += 3;
                                            result -= 3;
                                            arg_10 = (__int64)a1;
                                            arg_18 = (__int64)result;
                                            a1 = rsp + 120;
                                            sub_14004F470(a1, a2, v5);
                                            xmm0 = _mm_loadl_epi64((__m128i *)&off_1401085D8);
                                            src = 3;
                                            if (v12 != 0) {
                                                return (__int64)src;
                                            } else {
                                            }
                                        }
                                        return (__int64)src;
                                    }
                                }
                                return (__int64)src;
                            }
                            return (__int64)src;
                        }
                    }
                    return (__int64)src;
                }
                return (__int64)src;
            }
            return (__int64)src;
        } else {
        }
        return (__int64)src;
    } else {
        v2 = arg_10;
        v11 = arg_18;
        v12 = rsp + 40;
        sub_140068B20(v12, i);
        src = (__int64 *)v_28;
        v_60 = i;
        if (src != 3) {
            v5 = v12;
            v_68 = v11;
            a2 = (int *)v2;
            v_70 = v8;
            i = v_30;
            result = (struct Struct_1_t *)v_37;
            result = (struct Struct_1_t *)((__int64)(__int64)result << 16);
            a1 = (size_t *)v_35;
            a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
            a1 = (size_t *)((__int64)(__int64)a1 << 32);
            v8 = v_31;
            v8 |= (__int64)a1;
            v11 = v_38;
            i2 = v_40;
            v2 = v_48;
            v12 = v_50;
            if (src == 1) {
                v_148 = 1;
                v_150 = i;
                v_151 = v8;
                result = (struct Struct_1_t *)v8;
                result = (struct Struct_1_t *)((__int64)(__int64)result >> 48);
                v_157 = (__int64)result;
                v8 >>= 32;
                v_155 = v8;
                v_158 = v11;
                v_160 = i2;
                v_168 = v2;
                v_170 = v12;
                result = (struct Struct_1_t *)v_60;
                result->field_10 = a2;
                a1 = (size_t *)v_68;
                result->field_18 = a1;
                src = 1;
                v11 = 8;
                if (a1 != 0) {
                    v12 = (__int64)a2;
                    if (*a2 != 46) {
                        v2 = 0;
                        i2 = 0;
                        i = 0;
                    } else {
                        i = v12 + 1;
                        v2 = v_68;
                        v_28 = 0;
                        v_38 = 0;
                        v_40 = 95;
                        v_48 = 2;
                        src = &off_140116BA8;
                        v_50 = (__int64)src;
                        v_58 = 5;
                        --v2;
                        v11 = v_60;
                        arg_10 = i;
                        arg_18 = v2;
                        v8 = v_70;
                        i2 = v_a8;
                        if (!((v2 == 0))) {
                            result = (struct Struct_1_t *)arg_1;
                            a1 = (size_t *)v_68;
                            a1 -= 2;
                            a2 = v12 + 2;
                            arg_10 = (__int64)a2;
                            arg_18 = (__int64)a1;
                            result += 208;
                            if (result >= 10) {
                                arg_10 = i;
                                arg_18 = v2;
                                v_80 = 0;
                                v_88 = 8;
                                xmm0 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&v_90, xmm0);
                                result = 0;
                            } else {
                                v_238 = 0;
                                v_248 = v5;
                                v_250 = 0;
                                a1 = rsp + 176;
                                a2 = rsp + 568;
                                sub_1400685B0(a1, a2, v11);
                                a1 = (size_t *)v_b0;
                                if (a1 != 3) {
                                    result = (struct Struct_1_t *)v_b8;
                                    a2 = (int *)v_c0;
                                    xmm0 = _mm_loadu_si128((__m128i *)&v_c8);
                                    _mm_storeu_si128((__m128i *)&v_90, xmm0);
                                    v5 = v_d8;
                                    v_80 = (__int64)result;
                                    v_88 = (int)a2;
                                    v_a0 = v5;
                                    if (a1 == 1) {
                                        v_78 = 2;
                                        v2 = rsp + 136;
                                        a1 = (size_t *)v_88;
                                        a2 = (int *)v_90;
                                        v5 = v_98;
                                        v6 = v_a0;
                                        v_f0 = (int)a1;
                                        v_f8 = (int)a2;
                                        v_100 = v5;
                                        v_108 = v6;
                                    } else {
                                        v2 = rsp + 136;
                                        v_78 = (int)a1;
                                        xmm0 = _mm_loadu_si128((__m128i *)v2);
                                        xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
                                        _mm_store_si128((__m128i *)&v_f0, xmm0);
                                        _mm_store_si128((__m128i *)&v_100, xmm1);
                                        if (a1 != 0) {
                                            v_28 = (__int64)result;
                                            v11 = rsp + 48;
                                            a1 = (size_t *)v_f0;
                                            a2 = (int *)v_f8;
                                            v5 = v_100;
                                            v6 = v_108;
                                            v_30 = (int)a1;
                                            v_38 = (int)a2;
                                            v_40 = v5;
                                            v_48 = v6;
                                            i = v_38;
                                            if (i == result) {
                                                a1 = rsp + 40;
                                                sub_1400F8440(a1, a2, v5);
                                                result = (struct Struct_1_t *)v_28;
                                            }
                                            a1 = (size_t *)v_30;
                                            a2 = i + i*2;
                                            v_0[(__int64)a2] = 2;
                                            v_8[(__int64)a2] = src;
                                            v_10[(__int64)a2] = 5;
                                            ++i;
                                            v_38 = i;
                                            xmm0 = _mm_loadu_si128((__m128i *)v11);
                                            xmm1 = _mm_loadu_si128((__m128i *)(v11 + 16));
                                            _mm_store_si128((__m128i *)&v_b0, xmm0);
                                            _mm_store_si128((__m128i *)&v_c0, xmm1);
                                        } else {
                                        }
                                        v_80 = (__int64)result;
                                        xmm0 = _mm_load_si128((__m128i *)&v_b0);
                                        xmm1 = _mm_load_si128((__m128i *)&v_c0);
                                        _mm_storeu_si128((__m128i *)(v2 + 16), xmm1);
                                        _mm_storeu_si128((__m128i *)v2, xmm0);
                                        src = (__int64 *)v_78;
                                        if (src != 3) {
                                            i = v_80;
                                            v11 = v_88;
                                            i2 = v_90;
                                            v2 = v_98;
                                            v12 = v_a0;
                                            v8 = i;
                                            v8 >>= 8;
                                        } else {
                                            i = v_60;
                                            result = (struct Struct_1_t *)arg_10;
                                            a1 = (size_t *)v_68;
                                            result -= v12;
                                            a1 = (size_t *)((__int64)a1 - (__int64)result);
                                            if (!((a1 < 0))) {
                                                v12 += (__int64)result;
                                                arg_10 = v12;
                                                arg_18 = (__int64)a1;
                                                a1 = rsp + 40;
                                                sub_140068B20(a1, i, v5, v6);
                                                src = (__int64 *)v_28;
                                                if (src != 3) {
                                                    i = v_30;
                                                    result = (struct Struct_1_t *)v_37;
                                                    result = (struct Struct_1_t *)((__int64)(__int64)result << 16);
                                                    a1 = (size_t *)v_35;
                                                    a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                    a1 = (size_t *)((__int64)(__int64)a1 << 32);
                                                    v8 = v_31;
                                                    v8 |= (__int64)a1;
                                                    v11 = v_38;
                                                    i2 = v_40;
                                                    v2 = v_48;
                                                    v12 = v_50;
                                                    if (src != 1) {
                                                        if (src != 1) {
                                                            a1 = rsp + 328;
                                                            sub_14004F470(a1);
                                                        } else {
                                                            v_178 = 1;
                                                            v_180 = i;
                                                            v_181 = v8;
                                                            result = (struct Struct_1_t *)v8;
                                                            result = (struct Struct_1_t *)((__int64)(__int64)result >> 48);
                                                            v_187 = (__int64)result;
                                                            v8 >>= 32;
                                                            v_185 = v8;
                                                            v_188 = v11;
                                                            v_190 = i2;
                                                            v_198 = v2;
                                                            v_1a0 = v12;
                                                            a1 = rsp + 272;
                                                            a2 = rsp + 328;
                                                            v5 = rsp + 376;
                                                            sub_140055430(a1, a2, v5);
                                                            src = (__int64 *)v_110;
                                                            i = v_118;
                                                            result = (struct Struct_1_t *)v_11f;
                                                            result = (struct Struct_1_t *)((__int64)(__int64)result << 16);
                                                            a1 = (size_t *)v_11d;
                                                            a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                            a1 = (size_t *)((__int64)(__int64)a1 << 32);
                                                            v8 = v_119;
                                                            v8 |= (__int64)a1;
                                                            v11 = v_120;
                                                            i2 = v_128;
                                                            v2 = v_130;
                                                            v12 = v_138;
                                                        }
                                                        result = (struct Struct_1_t *)i;
                                                        v8 <<= 8;
                                                        v8 |= (__int64)result;
                                                        i = v_60;
                                                        if (src == 1) {
                                                            return i;
                                                        }
                                                    } else {
                                                        v_28 = 1;
                                                        v_30 = i;
                                                        v_31 = v8;
                                                        result = (struct Struct_1_t *)v8;
                                                        result = (struct Struct_1_t *)((__int64)(__int64)result >> 48);
                                                        v_37 = (__int64)result;
                                                        v8 >>= 32;
                                                        v_35 = v8;
                                                        v_38 = v11;
                                                        v_40 = i2;
                                                        v_48 = v2;
                                                        v_50 = v12;
                                                        i = v_60;
                                                        arg_10 = (__int64)a2;
                                                        a1 = rsp + 40;
                                                        sub_14004F470(a1, v12);
                                                        v8 = v_70;
                                                        i2 = v_a8;
                                                        a1 = rsp + 328;
                                                        sub_14004F470(a1);
                                                        a2 = (int *)arg_10;
                                                        a2 -= v8;
                                                        result = (struct Struct_1_t *)i2;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                        if ((result < 0)) {
                                                            result = &off_14011AF40;
                                                            v_28 = (__int64)result;
                                                            v_30 = 1;
                                                            v_38 = 8;
                                                            xmm0 = _mm_setzero_pd();
                                                            _mm_storeu_si128((__m128i *)&v_40, xmm0);
                                                            a2 = &off_1401162A8;
                                                            a1 = rsp + 40;
                                                            sub_1400F37A0(a1, a2);
                                                        } else {
                                                            v_70 = (__int64)ptr;
                                                            a1 = v8 + a2;
                                                            arg_10 = (__int64)a1;
                                                            arg_18 = (__int64)result;
                                                            v_78 = 0;
                                                            v_80 = 1;
                                                            v_88 = 0;
                                                            v2 = v8;
                                                            v_28 = v8;
                                                            v_30 = (int)a2;
                                                            v_38 = 0;
                                                            v_68 = (int)a2;
                                                            v_40 = (int)a2;
                                                            result = 0x5F0000005F;
                                                            v_48 = (__int64)result;
                                                            v_50 = 1;
                                                            i = 1;
                                                            v11 = 0;
                                                            i2 = rsp + 176;
                                                            v12 = rsp + 40;
                                                            v8 = 0;
                                                            sub_1400679E0(i2, v12);
                                                            while (v_b0 == 1) {
                                                                src = (__int64 *)v_b8;
                                                                ptr = (struct Struct_2_t *)v_c0;
                                                                src -= v8;
                                                                result = (struct Struct_1_t *)v_78;
                                                                result -= v11;
                                                                if (src > result) {
                                                                    a1 = rsp + 120;
                                                                    sub_1400F5F90(a1, v11, src);
                                                                    i = v_80;
                                                                    v11 = v_88;
                                                                }
                                                                v8 += v2;
                                                                a1 = i + v11;
                                                                sub_1400F27F0(a1, v8, src);
                                                                v11 += (__int64)src;
                                                                v_88 = v11;
                                                                v8 = (__int64)ptr;
                                                            }
                                                            ptr = (struct Struct_2_t *)v_68;
                                                            ptr -= v8;
                                                            src = (__int64 *)v_78;
                                                            result = (struct Struct_1_t *)src;
                                                            result -= v11;
                                                            if (ptr > result) {
                                                                a1 = rsp + 120;
                                                                sub_1400F5F90(a1, v11, ptr);
                                                                v11 = v_88;
                                                                src = (__int64 *)v_78;
                                                                i = v_80;
                                                            }
                                                            i2 = v2;
                                                            v8 += v2;
                                                            a1 = i + v11;
                                                            sub_1400F27F0(a1, v8, ptr);
                                                            v11 += (__int64)ptr;
                                                            a1 = rsp + 272;
                                                            sub_1400196A0(a1, i, v11);
                                                            if (src != 0) {
                                                                off_140108030();
                                                                off_140108038(result, 0, i);
                                                            }
                                                            if (v_110 != 1) {
                                                                xmm0 = _mm_cvtsi64_si128((__int64)(v_118));
                                                                ptr = (struct Struct_2_t *)v_70;
                                                                a2 = (int *)v_60;
                                                                if (_mm_cvtsi128_si64(xmm0) >= off_1401085D0) {
                                                                    result = 8;
                                                                    a1 = rsp + 232;
                                                                    v2 = 0;
                                                                    *a1 = result;
                                                                    a2[2] = i2;
                                                                    result = (struct Struct_1_t *)v_a8;
                                                                    a2[3] = result;
                                                                    v11 = v_e8;
                                                                    src = 2;
                                                                    v8 = 0;
                                                                    v12 = v_140;
                                                                    i2 = 0;
                                                                    if (src == 3) {
                                                                        return i2;
                                                                    } else {
                                                                        return i2;
                                                                    }
                                                                    return i2;
                                                                } else {
                                                                    v8 = _mm_cvtsi128_si64(xmm0);
                                                                    src = 3;
                                                                    i2 = 0;
                                                                    if (src != 3) {
                                                                        return i2;
                                                                    } else {
                                                                        return i2;
                                                                    }
                                                                    return i2;
                                                                }
                                                                return i2;
                                                            } else {
                                                                src = (__int64 *)v_111;
                                                                sub_14002EDF0(0, 1);
                                                                ptr = (struct Struct_2_t *)v_70;
                                                                a2 = (int *)v_60;
                                                                if (result == 0) JUMPOUT(0x140065ee1);
                                                                v2 = (__int64)result;
                                                                *(__int64 *)result = (__int64)(src);
                                                                v_e8 = 8;
                                                                result = &off_140115A48;
                                                                a1 = rsp + 320;
                                                            }
                                                            return (__int64)a1;
                                                        }
                                                        return (__int64)a1;
                                                    }
                                                    return (__int64)a1;
                                                }
                                                return (__int64)a1;
                                            }
                                            return (__int64)a1;
                                        }
                                        return (__int64)a1;
                                    }
                                    return (__int64)a1;
                                } else {
                                    result = (struct Struct_1_t *)arg_10;
                                    a1 = (size_t *)result;
                                    a1 -= i;
                                    if (a1 > v2) JUMPOUT(0x140065f29);
                                    i = v_60;
                                }
                                return i;
                            }
                            return i;
                        }
                        return i;
                    }
                    return i;
                }
                return i;
            }
            return i;
        }
        return i;
    }
    return (__int64)result;
}