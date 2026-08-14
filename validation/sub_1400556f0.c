// inferred from 5 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[64];
    __int64 field_58; // offset 88
    char _pad_58[72];
    __int64 field_A8; // offset 168
};

// inferred from 21 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[96];
    __int64 field_A0; // offset 160
    char _pad_A0[24];
    __int64 field_C0; // offset 192
    char _pad_C0[8];
    __int64 field_D0; // offset 208
    char _pad_D0[16];
    __int64 field_E8; // offset 232
    __int64 field_F0; // offset 240
    __int64 field_F8; // offset 248
    char _pad_F8[48];
    __int64 field_130; // offset 304
    char _pad_130[16];
    __int64 field_148; // offset 328
    char _pad_148[16];
    __int64 field_160; // offset 352
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
    __int64 field_178; // offset 376
    char _pad_178[8];
    __int64 field_188; // offset 392
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F27F0();
__int64 sub_140056810();
__int64 sub_140056CD0();
__int64 sub_140057260();
__int64 sub_1400575F0();
__int64 sub_140046190();
__int64 sub_1400578F0();
__int64 sub_140053730();
__int64 sub_140058230();
__int64 sub_1400F84B0();
__int64 sub_1400583C0();
__int64 sub_140053180();
__int64 off_140108360();
__int64 off_140108030();
extern __int64 off_14012D270;
extern __int64 off_14011D5D0;
extern __int64 off_14011D5E0;
extern __int64 off_140108038;

__int64 __fastcall sub_1400556F0(__int64 *a1, int *a2) {
    __int64 rsp;
    int v_100;
    __int64 v_110;
    int v_118;
    int v_120;
    int v_130;
    int v_140;
    int v_150;
    int v_160;
    int v_170;
    int v_180;
    int v_190;
    int v_198;
    int v_1a8;
    int v_1b8;
    int v_1c8;
    int v_1d0;
    __int64 v_1d8;
    int v_20;
    int v_250;
    int v_258;
    int v_260;
    __int64 v_268;
    int v_270;
    int v_278;
    int v_280;
    int v_290;
    int v_2a0;
    int v_2b0;
    int v_2c0;
    int v_2d0;
    int v_2e0;
    int v_2f0;
    int v_2f8;
    int v_30;
    int v_300;
    int v_38;
    int v_3b0;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_70;
    int v_80;
    int v_90;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_e0;
    int v_f0;
    __int64 *v_0;
    char *str;
    struct Struct_2_t *ptr;
    __int64 *dst;
    struct Struct_1_t *result;
    struct Struct_3_t *ptr2;
    __m128i xmm0;
    __m128i xmm6;
    __int64 v11;
    __int64 v8;
    __int64 v2;
    __int64 i;
    __int64 v6;
    __int64 v7;
    __m128i xmm1;
    __int64 i2;

    _mm_store_si128((__m128i *)&v_3b0, xmm6);
    ptr = (struct Struct_2_t *)a2;
    dst = a1;
    result = off_14012D270;
    a1 = __readgsqword(88);
    result = v_0[(__int64)result];
    ptr2 = result + 72;
    if (result->field_58 != 1) {
        xmm0 = _mm_setzero_si128();
        _mm_store_si128((__m128i *)&v_30, xmm0);
        a1 = rsp + 48;
        off_140108360(a1, 16);
        result = (struct Struct_1_t *)v_38;
        xmm6 = _mm_load_si128((__m128i *)&v_30);
        ptr2->field_8 = result;
        ptr2->field_10 = 1;
    } else {
        xmm6 = _mm_loadu_si128((__m128i *)ptr2);
    }
    result = _mm_cvtsi128_si64(xmm6);
    ++result;
    *(__int64 *)ptr2 = (__int64)(result);
    a2 = ptr + 192;
    a1 = rsp + 224;
    sub_1400F27F0(a1, a2, 168);
    ptr->field_C0 = 0;
    ptr->field_D0 = 0;
    ptr->field_E8 = 0;
    ptr->field_F0 = 8;
    ptr->field_F8 = 0;
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
    _mm_storeu_si128((__m128i *)(ptr + 256), xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
    _mm_storeu_si128((__m128i *)(ptr + 272), xmm0);
    _mm_storeu_si128((__m128i *)(ptr + 288), xmm6);
    v11 = 0x8000000000000003;
    ptr->field_130 = v11;
    ptr->field_148 = v11;
    ptr->field_160 = 0;
    v8 = ptr->field_168;
    ptr2 = ptr->field_170;
    v2 = ptr->field_178;
    ptr->field_168 = 0;
    ptr->field_170 = 8;
    ptr->field_178 = 0;
    if (v2 == 0) {
        result = ptr->field_30;
        a1 = ptr->field_38;
        a2 = (__int64)(__int64)a1 * 328;
        a2 = (int *)((__int64)a2 + (__int64)result);
        i = 0;
        v6 = (__int64)result;
        do {
            v7 = v6;
            while (v7 != a2) {
                v6 = v7 + 328;
                /* cmp *v7 , 8 */;
                v7 = v6;
                ++i;
            }
            if (i != 0) JUMPOUT(0x140055f79);
            xmm0 = _mm_loadu_si128((__m128i *)ptr);
            xmm1 = _mm_load_si128((__m128i *)&v_e0);
            _mm_store_si128((__m128i *)&v_e0, xmm0);
            _mm_storeu_si128((__m128i *)ptr, xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 16));
            xmm1 = _mm_load_si128((__m128i *)&v_f0);
            _mm_store_si128((__m128i *)&v_f0, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 32));
            xmm1 = _mm_load_si128((__m128i *)&v_100);
            _mm_store_si128((__m128i *)&v_100, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 32), xmm1);
            xmm0 = _mm_load_si128((__m128i *)&v_110);
            v_110 = (__int64)result;
            v_118 = (int)a1;
            _mm_storeu_si128((__m128i *)(ptr + 48), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 64));
            xmm1 = _mm_load_si128((__m128i *)&v_120);
            _mm_store_si128((__m128i *)&v_120, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 64), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 80));
            xmm1 = _mm_load_si128((__m128i *)&v_130);
            _mm_store_si128((__m128i *)&v_130, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 80), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 96));
            xmm1 = _mm_load_si128((__m128i *)&v_140);
            _mm_store_si128((__m128i *)&v_140, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 96), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 112));
            xmm1 = _mm_load_si128((__m128i *)&v_150);
            _mm_store_si128((__m128i *)&v_150, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 112), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 128));
            xmm1 = _mm_load_si128((__m128i *)&v_160);
            _mm_store_si128((__m128i *)&v_160, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 128), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 144));
            xmm1 = _mm_load_si128((__m128i *)&v_170);
            _mm_store_si128((__m128i *)&v_170, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 144), xmm1);
            result = (struct Struct_1_t *)v_180;
            a1 = ptr->field_A0;
            v_180 = (int)a1;
            ptr->field_A0 = result;
            *dst = v11;
        } while (true);
    } else {
        i2 = v2 - 1;
        if (ptr->field_188 == 0) {
            v_20 = 0;
            a1 = rsp + 48;
            sub_140056810(a1, ptr, ptr2, i2);
            result = (struct Struct_1_t *)v_30;
            ptr = (struct Struct_2_t *)v_38;
            if (result != v11) {
                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                _mm_storeu_si128((__m128i *)(dst + 32), xmm1);
                _mm_storeu_si128((__m128i *)(dst + 16), xmm0);
                *dst = result;
                *(dst + 8) = ptr;
            } else {
                a2 = i2 + i2*8;
                a2 = (int *)((__int64)(__int64)a2 << 4);
                a2 = (int *)((__int64)a2 + (__int64)ptr2);
                ptr += 40;
                sub_140056CD0(str, a2);
                a1 = rsp + 48;
                sub_140057260(a1, ptr, str);
                a2 = (int *)v_30;
                result = (struct Struct_1_t *)v_38;
                a1 = (__int64 *)a2;
                a1 = (__int64 *)(-(__int64)a1);
                a1 = (__int64 *)v_40;
                if ((0 /* unresolved: flags !OF */)) {
                    i = v_48;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_50);
                    _mm_storeu_si128((__m128i *)&v_280, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_60);
                    _mm_storeu_si128((__m128i *)&v_290, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_70);
                    _mm_storeu_si128((__m128i *)&v_2a0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_80);
                    _mm_storeu_si128((__m128i *)&v_2b0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_90);
                    _mm_storeu_si128((__m128i *)&v_2c0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                    _mm_storeu_si128((__m128i *)&v_2d0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_b0);
                    _mm_storeu_si128((__m128i *)&v_2e0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_c0);
                    _mm_storeu_si128((__m128i *)&v_2f0, xmm0);
                    v_260 = (int)a2;
                    v_268 = (__int64)result;
                    v_270 = (int)a1;
                    v_278 = i;
                    a1 = rsp + 776;
                    a2 = rsp + 224;
                    sub_1400F27F0(a1, a2, 168);
                    v_300 = 10;
                    a1 = (__int64 *)v_2f0;
                    a2 = (int *)v_2f8;
                    i = rsp + 608;
                    v6 = rsp + 768;
                    sub_1400575F0(a1, a2, i, v6);
                    *dst = v11;
                    dst = (__int64 *)ptr2;
                    do {
                        sub_140046190(dst);
                        dst += 144;
                        --v2;
                    } while ((v2 != 0));
                    if (v8 != 0) {
                        off_140108030();
                        a1 = (__int64 *)result;
                        a2 = 0;
                        i = (__int64)ptr2;
                        xmm6 = _mm_load_si128((__m128i *)&v_3b0);
                        JUMPOUT(off_140108038);
                        sub_1400578F0(dst, ptr2, v2, i2);
                        dst = (__int64 *)ptr2;
                        do {
                            sub_140046190(dst);
                            dst += 144;
                            --v2;
                        } while ((v2 != 0));
                        if (v8 != 0) {
                            off_140108030();
                            ((__int64 (*)())off_140108038)(result, 0, ptr2);
                        }
                        a1 = rsp + 224;
                        sub_140053730(a1);
                    }
                } else {
                    a2 = result->field_10;
                    if (a1 >= a2) JUMPOUT(0x140055f91);
                    result = result->field_8;
                    a1 = (__int64 *)((__int64)(__int64)(__int64)a1 * 328);
                    if (*(__int64 *)((__int64)result + (__int64)a1) == 10) {
                        result = (struct Struct_1_t *)((__int64)result + (__int64)a1);
                        if (result->field_A8 == 0) {
                            return (__int64)result;
                        } else {
                            result += 8;
                            a2 = rsp + 224;
                            sub_140058230(result, a2);
                            *dst = v11;
                            dst = (__int64 *)ptr2;
                            do {
                                sub_140046190(dst);
                                dst += 144;
                                --v2;
                            } while ((v2 != 0));
                        }
                        return v2;
                    }
                    return v2;
                }
                xmm6 = _mm_load_si128((__m128i *)&v_3b0);
                return _mm_cvtsi128_si64(xmm6);
            }
            return _mm_cvtsi128_si64(xmm6);
        } else {
            v_20 = 0;
            a1 = rsp + 48;
            sub_140056810(a1, ptr, ptr2, i2);
            result = (struct Struct_1_t *)v_30;
            ptr = (struct Struct_2_t *)v_38;
            if (result != v11) {
                return (__int64)ptr;
            } else {
                a2 = i2 + i2*8;
                a2 = (int *)((__int64)(__int64)a2 << 4);
                a2 = (int *)((__int64)a2 + (__int64)ptr2);
                ptr += 40;
                sub_140056CD0(str, a2);
                a1 = rsp + 48;
                sub_140057260(a1, ptr, str);
                result = 0;
                if (!__OFSUB(result, v_30)) {
                    a1 = rsp + 448;
                    a2 = rsp + 48;
                    sub_1400F27F0(a1, a2, 160);
                    result = 0;
                    /* cmp result , str */;
                    v_38 = 0;
                    v_50 = 0;
                    v_58 = 8;
                    v_60 = 0;
                    v_30 = 11;
                    if ((0 /* unresolved: flags !OF */)) {
                        a1 = (__int64 *)v_250;
                        a2 = (int *)v_258;
                        i = rsp + 448;
                        v6 = rsp + 48;
                        sub_1400575F0(a1, a2, i, v6);
                        ptr = (struct Struct_2_t *)result;
                        if (result->field_0 == 11) {
                            ptr += 8;
                        } else {
                            a1 = rsp + 48;
                            sub_1400578F0(a1, ptr2, v2, i2);
                            result = (struct Struct_1_t *)v_30;
                            ptr = (struct Struct_2_t *)v_38;
                            xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                            _mm_store_si128((__m128i *)&str, xmm0);
                            xmm0 = _mm_loadu_si128((__m128i *)&v_50);
                            _mm_store_si128((__m128i *)&v_1d0, xmm0);
                            if (result != v11) {
                                xmm0 = _mm_load_si128((__m128i *)&str);
                                xmm1 = _mm_load_si128((__m128i *)&v_1d0);
                                return _mm_cvtsi128_si64(xmm1);
                            } else {
                                a1 = rsp + 48;
                                a2 = rsp + 224;
                                sub_1400F27F0(a1, a2, 168);
                                i2 = ptr->field_28;
                                if (i2 == ptr->field_18) {
                                    a1 = ptr + 24;
                                    sub_1400F84B0(a1);
                                }
                                result = ptr->field_20;
                                a1 = i2 * 176;
                                *(__int64 *)((__int64)result + (__int64)a1) = 10;
                                a1 = (__int64 *)((__int64)a1 + (__int64)result);
                                a1 += 8;
                                a2 = rsp + 48;
                                sub_1400F27F0(a1, a2, 168);
                                ++i2;
                                ptr->field_28 = i2;
                                if (ptr->field_28 == 0) {
                                    v_190 = 0;
                                } else {
                                    a2 = ptr->field_20;
                                    a1 = rsp + 400;
                                    sub_1400583C0(a1, a2);
                                    result = ptr->field_28;
                                    if (result != 0) {
                                        a2 = (__int64)(__int64)result * 176;
                                        a2 += ptr->field_20;
                                        a2 -= 176;
                                        if ((a2 == 0)) {
                                            result = 0;
                                        } else {
                                            a1 = rsp + 424;
                                            sub_1400583C0(a1, a2);
                                            result = (struct Struct_1_t *)v_1a8;
                                        }
                                        result = (struct Struct_1_t *)((__int64)(__int64)result & v_190);
                                        a1 = (__int64 *)v_198;
                                        a2 = (int *)v_1b8;
                                        *(__int64 *)ptr = (__int64)(result);
                                        ptr->field_8 = a1;
                                        ptr->field_10 = a2;
                                        *dst = v11;
                                        dst = (__int64 *)ptr2;
                                        do {
                                            sub_140046190(dst, a2);
                                            dst += 144;
                                            --v2;
                                        } while ((v2 != 0));
                                        if (v8 != 0) {
                                            off_140108030();
                                            ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                        }
                                        return v2;
                                    }
                                }
                                return v2;
                            }
                            return v2;
                        }
                        return v2;
                    } else {
                        result = (struct Struct_1_t *)v_1c8;
                        a1 = (__int64 *)v_1d0;
                        a2 = result->field_10;
                        if (a1 >= a2) JUMPOUT(0x140055f91);
                        ptr = (__int64)(__int64)a1 * 328;
                        ptr += result->field_8;
                        a1 = rsp + 48;
                        sub_140053180(a1, a2);
                        if (ptr->field_0 != 11) {
                            return (__int64)a1;
                        } else {
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                } else {
                    result = (struct Struct_1_t *)v_48;
                    v_1d8 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_38);
                    _mm_storeu_si128((__m128i *)&v_1c8, xmm0);
                    v_38 = 0;
                    v_50 = 0;
                    v_58 = 8;
                    v_60 = 0;
                    v_30 = 11;
                }
                return v_30;
            }
            return v_30;
        }
        return v_30;
    }
    return (__int64)result;
}