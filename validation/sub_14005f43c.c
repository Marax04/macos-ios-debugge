// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 6 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[16];
    __int64 field_38; // offset 56
    char _pad_38[16];
    __int64 field_50; // offset 80
};

__int64 sub_14004F470();
__int64 sub_1400F37A0();
__int64 sub_1400F8440();
__int64 sub_14005CE67();
__int64 sub_140017B60();
__int64 sub_14001A580();
__int64 sub_140061731();
__int64 sub_1400F27F0();
__int64 sub_1400F5F90();
__int64 sub_140061725();
__int64 sub_14006172C();
__int64 sub_14005B1B0();
__int64 sub_140058520();
__int64 sub_14005B1B7();
__int64 sub_1400617AC();
__int64 sub_1400F8590();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400615EC();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011AF40;
extern __int64 off_1401162A8;
extern __int64 off_140116D40;
extern __int64 off_140116C87;
extern __int64 off_140116C6F;
extern __int64 off_140116C88;
extern __int64 off_1401086C0;
extern __int64 off_1401086D0;
extern __int64 off_140115B38;

__int64 __fastcall sub_14005F43C() {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    __int64 arg_18;
    int arg_2;
    __int64 arg_8;
    __int64 v_1d8;
    int v_1f0;
    int v_20;
    int v_28;
    __int64 v_298;
    __int64 v_2a8;
    __int64 v_2b0;
    __int64 v_2c0;
    __int64 v_2d0;
    int v_2d8;
    int v_2e0;
    int v_2e8;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v_430;
    int v_434;
    __int64 v_48;
    __int64 v_488;
    __int64 v_490;
    __int64 v_498;
    __int64 v_4a0;
    __int64 v_4a8;
    __int64 v_50;
    __int64 v_58;
    __int64 v_60;
    int v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    __int64 v_88;
    int v_880;
    __int64 v_8a;
    int v_8c;
    int v_90;
    int v_98;
    int v_a8;
    int v_b8;
    int v_c0;
    int v_c8;
    int v_d0;
    __int64 *i;
    __int64 i2;
    struct Struct_1_t *result;
    __m128i xmm0;
    __int64 v_cap;
    __int64 *src;
    __int64 *dst;
    __int64 i3;
    __int64 v15;
    __int64 *dst2;
    __int64 *src2;
    __int64 v8;
    __int64 v9;
    __int64 *src3;
    __int64 *src4;
    __int64 v11;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm1;
    __m128i xmm12;
    __m128i xmm13;
    __m128i xmm10;
    __m128i xmm11;
    __m128i xmm8;
    __m128i xmm9;
    struct Struct_2_t *ptr;

    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_1f0 = 8;
    i = rsp + 480;
    sub_14004F470(i);
    i2 -= v11;
    arg_10 = v11;
    arg_18 = i3;
    result = (struct Struct_1_t *)i3;
    result -= i2;
    if ((result < 0)) {
        result = &off_14011AF40;
        v_2d0 = (__int64)result;
        v_2d8 = 1;
        v_2e0 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_2e8, xmm0);
        v_cap = &off_1401162A8;
        i = rsp + 720;
        sub_1400F37A0(i);
        i = rsp + 112;
        sub_1400F8440(i);
        src = (__int64 *)v_70;
        dst = (__int64 *)v_78;
        result = i3 + i3*2;
        dst[(__int64)result] = 3;
        i = &off_140116D40;
        *(dst + (__int64)(__int64)result*8 + 8) = i;
        *(dst + (__int64)(__int64)result*8 + 16) = 11;
        ++i3;
        result = (struct Struct_1_t *)v_78;
        i = (__int64 *)i3;
        i = (__int64 *)((__int64)(__int64)i >> 16);
        v_cap = i3;
        v_cap >>= 32;
        xmm0 = _mm_loadu_si128((__m128i *)&v_88);
        v_70 = 1;
        v_78 = (__int64)src;
        v_80 = (__int64)result;
        v_88 = i3;
        v_8a = (__int64)i;
        v_8c = v_cap;
        _mm_storeu_si128((__m128i *)&v_90, xmm0);
        result = (struct Struct_1_t *)v_28;
        i = (__int64 *)v_298;
        result->field_10 = i;
        i = (__int64 *)v_2b0;
        result->field_18 = i;
        i = rsp + 112;
        sub_14004F470(i);
        i3 = 2;
        result = 1;
        v_48 = (__int64)result;
        src = 0;
        v15 = v_28;
        result = (struct Struct_1_t *)dst2;
        i = (__int64 *)i2;
        i = (__int64 *)((__int64)(__int64)i << 16);
        i = (__int64 *)((__int64)(__int64)i | (__int64)result);
        result = (struct Struct_1_t *)v_30;
        result = (struct Struct_1_t *)((__int64)(__int64)result << 24);
        result = (struct Struct_1_t *)((__int64)(__int64)result | (__int64)i);
        i = (__int64 *)v_48;
        v_430 = (__int64)i;
        v_434 = v11;
        v_2c0 = (__int64)result;
        dst = 3;
        dst2 = 1;
        return sub_14005CE67();
    } else {
        i = v11 + i2;
        arg_10 = (__int64)i;
        arg_18 = (__int64)result;
        i = rsp + 720;
        sub_140017B60(i, v11, i2);
        if (v_2d0 != 1) {
            src2 = (__int64 *)v_2d8;
            src = (__int64 *)v_2e0;
            v_48 = (__int64)src2;
            if (src <= 2) {
                if ((0 /* unresolved: flags != */)) {
                    i3 = (__int64)src;
                    src = 0x8000000000000000;
                } else {
                    if (*src2 == 0xA0D) {
                        v_28 = v15;
                        v_2d0 = 0;
                        v_2d8 = 1;
                        v_2e0 = 0;
                        v_20 = 2;
                        v8 = &off_140116C87;
                        i = rsp + 112;
                        sub_14001A580(i, src2, src, v8);
                        v9 = v_78;
                        result = (struct Struct_1_t *)v_88;
                        src3 = (__int64 *)v_b8;
                        dst = (__int64 *)v_c0;
                        v_50 = (__int64)src3;
                        v_30 = v9;
                        if (((v_70 & 1) == 0)) {
                            i = 1;
                            v_60 = (__int64)i;
                            if (((__int64)result & 0x10000) != 0) {
                                i3 = 0;
                                dst = 0;
                                v15 = v_28;
                                src2 = (__int64 *)v_48;
                            } else {
                                src3 = (__int64 *)result;
                                v_1d8 = (__int64)src;
                                if (v9 != 0) {
                                    if (v9 >= dst) {
                                        v9 = v_30;
                                        if ((0 /* unresolved: flags != */)) JUMPOUT(0x140061731);
                                    } else {
                                        result = (struct Struct_1_t *)v_50;
                                        v9 = v_30;
                                        if (*(__int64 *)(result + v9) < 192) {
                                            return sub_140061731();
                                        }
                                    }
                                }
                                if (v9 != dst) {
                                    result = (struct Struct_1_t *)v_50;
                                    i = (__int64 *)v_30;
                                    src2 = *(__int64 *)((__int64)result + (__int64)i);
                                    i = src2;
                                    if (i < 0) {
                                        result = (struct Struct_1_t *)i;
                                        result = (struct Struct_1_t *)((__int64)(__int64)result & 31);
                                        src4 = (__int64 *)v_50;
                                        v8 = v_30;
                                        src4 = *(src4 + v8 + 1);
                                        src4 = (__int64 *)((__int64)(__int64)src4 & 63);
                                        if (i < 224) {
                                            result = (struct Struct_1_t *)((__int64)(__int64)result << 6);
                                            result = (struct Struct_1_t *)((__int64)(__int64)result | (__int64)src4);
                                        } else {
                                            i = (__int64 *)v_50;
                                            v8 = v_30;
                                            i = *(i + v8 + 2);
                                            src4 = (__int64 *)((__int64)(__int64)src4 << 6);
                                            i = (__int64 *)((__int64)(__int64)i & 63);
                                            i = (__int64 *)((__int64)(__int64)i | (__int64)src4);
                                            if (src2 < 240) {
                                                result = (struct Struct_1_t *)((__int64)(__int64)result << 12);
                                                result = (struct Struct_1_t *)((__int64)(__int64)result | (__int64)i);
                                            } else {
                                                src2 = (__int64 *)v_50;
                                                src4 = (__int64 *)v_30;
                                                src2 = *(__int64 *)((__int64)src2 + (__int64)src4 + 3);
                                                result = (struct Struct_1_t *)((__int64)(__int64)result & 7);
                                                result = (struct Struct_1_t *)((__int64)(__int64)result << 18);
                                                i = (__int64 *)((__int64)(__int64)i << 6);
                                                src2 = (__int64 *)((__int64)(__int64)src2 & 63);
                                                src2 = (__int64 *)((__int64)(__int64)src2 | (__int64)i);
                                                result = (struct Struct_1_t *)((__int64)(__int64)result | (__int64)src2);
                                            }
                                        }
                                    } else {
                                        result = (struct Struct_1_t *)i;
                                    }
                                    if (((__int64)src3 & 1) == 0) {
                                        i = 1;
                                        if (result >= 128) {
                                            i = 2;
                                            if (result >= 0x800) {
                                                /* cmp result , 0x10000 */;
                                                i = 4;
                                                i -= 0;
                                            }
                                        }
                                        i += v_30;
                                        if (!((i == 0))) {
                                            if (i >= dst) {
                                                if (!((0 /* unresolved: flags != */))) {
                                                    v_30 = (__int64)dst;
                                                    if (i != dst) {
                                                        result = (struct Struct_1_t *)v_50;
                                                        result = *(__int64 *)((__int64)result + (__int64)i);
                                                        if (result < 0) {
                                                            /* cmp result , 224 */;
                                                        }
                                                        v_30 = (__int64)i;
                                                    }
                                                    if (v_30 != 0) JUMPOUT(0x14006162c);
                                                    dst2 = 1;
                                                    i2 = 0;
                                                    i3 = 0;
                                                    i = dst2 + i3;
                                                    v_cap = v_48;
                                                    src = (__int64 *)v_30;
                                                    sub_1400F27F0(v_cap, src2, src, v8);
                                                    i3 += (__int64)src;
                                                    v_2e0 = i3;
                                                    if (i2 == i3) JUMPOUT(0x14006165d);
                                                    i = dst2;
                                                    *(dst2 + i3) = 10;
                                                    i2 = rsp + 720;
                                                    v_cap = v_48;
                                                    src3 = (__int64 *)v_50;
                                                    dst2 = (__int64 *)v_30;
                                                    ++i3;
                                                    v_2e0 = i3;
                                                    if (dst2 == 0) {
                                                        while (dst2 != dst) {
                                                            src4 = *(__int64 *)((__int64)src3 + (__int64)dst2);
                                                            result = 1;
                                                            if (src4 >= 0) {
                                                                result = (struct Struct_1_t *)((__int64)result + (__int64)dst2);
                                                                if ((result == 0)) {
                                                                    src = dst;
                                                                    if (result == dst) {
                                                                        v11 = (__int64)src;
                                                                        v11 -= (__int64)dst2;
                                                                        result = (struct Struct_1_t *)v_2d0;
                                                                        result -= i3;
                                                                        if (v11 > result) {
                                                                            v_cap = i3;
                                                                            sub_1400F5F90(i2, src2, v11);
                                                                            v_cap = v_48;
                                                                            i = (__int64 *)v_2d8;
                                                                            i3 = v_2e0;
                                                                        }
                                                                        dst2 += v_cap;
                                                                        i += i3;
                                                                        v_cap = (__int64)dst2;
                                                                        sub_1400F27F0(v_cap, src2, v11, v8);
                                                                        i3 += v11;
                                                                        v_2e0 = i3;
                                                                        if (v_2d0 == i3) {
                                                                            v_cap = i3;
                                                                            sub_1400F5F90(i2, src2, 1);
                                                                            i3 = v_2e0;
                                                                        }
                                                                        src3 = (__int64 *)v_50;
                                                                        i = (__int64 *)v_2d8;
                                                                        *(i + i3) = 10;
                                                                        dst2 = src;
                                                                        v_cap = v_48;
                                                                        ++i3;
                                                                        v_2e0 = i3;
                                                                        if (src != 0) {
                                                                            if (dst2 >= dst) {
                                                                                if ((0 /* unresolved: flags != */)) JUMPOUT(0x140061725);
                                                                            }
                                                                            return sub_140061725();
                                                                        }
                                                                    }
                                                                    src4 = *(__int64 *)((__int64)src3 + (__int64)result);
                                                                    if (src4 >= 0) {
                                                                        src = (__int64 *)result;
                                                                        return (__int64)src;
                                                                    }
                                                                    /* cmp src4 , 224 */;
                                                                    return (__int64)src;
                                                                }
                                                                if (result >= dst) {
                                                                    if ((0 /* unresolved: flags != */)) JUMPOUT(0x14006172c);
                                                                    return (__int64)src;
                                                                }
                                                                if (*(__int64 *)((__int64)src3 + (__int64)result) >= 192) {
                                                                    return (__int64)src;
                                                                }
                                                                return sub_14006172C();
                                                            }
                                                            src = src4;
                                                            src = (__int64 *)((__int64)(__int64)src & 31);
                                                            v8 = *(__int64 *)((__int64)src3 + (__int64)dst2 + 1);
                                                            v8 &= 63;
                                                            if (src4 < 224) {
                                                                src = (__int64 *)((__int64)(__int64)src << 6);
                                                                src = (__int64 *)((__int64)(__int64)src | v8);
                                                                if (src < 128) {
                                                                    return (__int64)src;
                                                                }
                                                                result = 2;
                                                                if (src < 0x800) {
                                                                    return (__int64)result;
                                                                }
                                                                /* cmp src , 0x10000 */;
                                                                result = 4;
                                                                result -= 0;
                                                                return (__int64)result;
                                                            }
                                                            v9 = *(__int64 *)((__int64)src3 + (__int64)dst2 + 2);
                                                            v8 <<= 6;
                                                            v9 &= 63;
                                                            v9 |= v8;
                                                            if (src4 < 240) {
                                                                src = (__int64 *)((__int64)(__int64)src << 12);
                                                                src = (__int64 *)((__int64)(__int64)src | v9);
                                                                return (__int64)src;
                                                            }
                                                            src4 = *(__int64 *)((__int64)src3 + (__int64)dst2 + 3);
                                                            src = (__int64 *)((__int64)(__int64)src & 7);
                                                            src = (__int64 *)((__int64)(__int64)src << 18);
                                                            v9 <<= 6;
                                                            src4 = (__int64 *)((__int64)(__int64)src4 & 63);
                                                            src4 = (__int64 *)((__int64)(__int64)src4 | v9);
                                                            src = (__int64 *)((__int64)(__int64)src | (__int64)src4);
                                                            return (__int64)src;
                                                        }
                                                        v_60 = (__int64)i;
                                                        v15 = v_28;
                                                        src = (__int64 *)v_1d8;
                                                        src = (__int64 *)((__int64)src - (__int64)dst);
                                                        result = (struct Struct_1_t *)v_2d0;
                                                        result -= i3;
                                                        if (src > result) JUMPOUT(0x1400615b1);
                                                        v_cap += (__int64)dst;
                                                        i = (__int64 *)v_60;
                                                        i += i3;
                                                        sub_1400F27F0(i, src2, src);
                                                        i3 += (__int64)src;
                                                        src = (__int64 *)v_2d0;
                                                        v_cap = v_2d8;
                                                        result = (struct Struct_1_t *)arg_18;
                                                        if (result != 0) {
                                                            i = (__int64 *)arg_10;
                                                            if (*i == 39) {
                                                                if (result != 1) {
                                                                    if (arg_1 == 39) {
                                                                        if (result != 2) {
                                                                            if (arg_2 == 39) {
                                                                                if (result <= 2) {
                                                                                    i2 = (__int64)src2;
                                                                                    v_78 = 8;
                                                                                    xmm0 = _mm_setzero_si128();
                                                                                    _mm_storeu_si128((__m128i *)&v_80, xmm0);
                                                                                    v_70 = 0;
                                                                                    i = rsp + 112;
                                                                                    sub_1400F8440(i, src2, src4, v8);
                                                                                    v11 = v_70;
                                                                                    dst2 = (__int64 *)v_78;
                                                                                    *dst2 = 3;
                                                                                    result = &off_140116C6F;
                                                                                    arg_8 = (__int64)result;
                                                                                    arg_10 = 24;
                                                                                    xmm6 = _mm_loadu_si128((__m128i *)&v_88);
                                                                                    dst = 2;
                                                                                    i3 = 1;
                                                                                    src = (__int64 *)((__int64)(__int64)src << 1);
                                                                                    if (src != 0) {
                                                                                        off_140108030(i);
                                                                                        v15 = 0;
                                                                                        off_140108038(result, 0, i2);
                                                                                    } else {
                                                                                        v15 = 0;
                                                                                    }
                                                                                } else {
                                                                                    i += 3;
                                                                                    result -= 3;
                                                                                    arg_10 = (__int64)i;
                                                                                    arg_18 = (__int64)result;
                                                                                    v15 = i3;
                                                                                    v15 >>= 8;
                                                                                    dst = 3;
                                                                                    dst2 = src2;
                                                                                    v11 = (__int64)src;
                                                                                }
                                                                                v15 <<= 8;
                                                                                i2 = i3;
                                                                                i2 |= v15;
                                                                                i = rsp + 0x730;
                                                                                sub_14004F470(i);
                                                                                if (v_880 == 3) JUMPOUT(0x14005c050);
                                                                                if (dst != 3) {
                                                                                    ptr->field_8 = dst;
                                                                                    ptr->field_10 = v11;
                                                                                    ptr->field_18 = dst2;
                                                                                    ptr->field_20 = i2;
                                                                                    _mm_storeu_si128((__m128i *)(ptr + 40), xmm6);
                                                                                    return sub_14005B1B0();
                                                                                } else {
                                                                                    result = (struct Struct_1_t *)v11;
                                                                                    result = (struct Struct_1_t *)(-(__int64)result);
                                                                                    if (!((0 /* overflow check on (-result) */))) {
                                                                                        i = rsp + 112;
                                                                                        sub_140058520(i, dst2, i2);
                                                                                        v11 = v_70;
                                                                                        dst2 = (__int64 *)v_78;
                                                                                        i2 = v_80;
                                                                                    }
                                                                                    *(__int64 *)ptr = (__int64)(2);
                                                                                    ptr->field_8 = v11;
                                                                                    ptr->field_10 = dst2;
                                                                                    ptr->field_18 = i2;
                                                                                    result = 0x8000000000000003;
                                                                                    ptr->field_20 = result;
                                                                                    ptr->field_38 = result;
                                                                                    ptr->field_50 = result;
                                                                                    return sub_14005B1B7();
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        return (__int64)result;
                                                    }
                                                    return (__int64)result;
                                                }
                                            } else {
                                                result = (struct Struct_1_t *)v_50;
                                                if (*(__int64 *)((__int64)result + (__int64)i) >= 192) {
                                                    return (__int64)result;
                                                }
                                            }
                                            v_30 = (__int64)i;
                                            return sub_140061731();
                                        }
                                        return v_30;
                                    }
                                } else {
                                    if (((__int64)src3 & 1) != 0) {
                                        return v_30;
                                    } else {
                                        i3 = 0;
                                        dst = 0;
                                        v15 = v_28;
                                        src2 = (__int64 *)v_48;
                                    }
                                    return (__int64)src2;
                                }
                                return (__int64)src2;
                            }
                        } else {
                            v_1d8 = (__int64)src;
                            i = (__int64 *)v_90;
                            v_40 = (__int64)i;
                            i2 = v_98;
                            v11 = v_a8;
                            src = (__int64 *)v_c8;
                            v15 = v_d0;
                            i = v15 - 1;
                            v_38 = (__int64)i;
                            i = (__int64 *)v15;
                            v_58 = (__int64)result;
                            i = (__int64 *)((__int64)i - (__int64)result);
                            v_2a8 = (__int64)i;
                            result = v9 - 1;
                            v_298 = (__int64)result;
                            v_68 = (result < v15) ? 1 : 0;
                            result = src + v9 - 1;
                            v_2b0 = (__int64)result;
                            result = 1;
                            v_60 = (__int64)result;
                            i3 = 0;
                            dst2 = 0;
                            src2 = (__int64 *)v_48;
                            result = (struct Struct_1_t *)v_38;
                            result += i2;
                            if (v11 == -1) {
                                while (result < dst) {
                                    result = *(__int64 *)((__int64)src3 + (__int64)result);
                                    i = (__int64 *)v_40;
                                    if ((!(((__int64)i >> (__int64)result) & 1))) {
                                        i2 += v15;
                                        result = (struct Struct_1_t *)v_38;
                                        result += i2;
                                    }
                                    i = src3 + i2;
                                    v8 = v9;
                                    while (v8 < v15) {
                                        result = (struct Struct_1_t *)v8;
                                        src4 = i2 + v8;
                                        if (src4 >= dst) JUMPOUT(0x1400616ac);
                                        v8 = result + 1;
                                        src4 = *(__int64 *)((__int64)src + (__int64)result);
                                        i2 -= v9;
                                        i2 += (__int64)result;
                                        ++i2;
                                        return i2;
                                    }
                                    if (v_68 == 0) {
                                        v11 = -1;
                                        if (v9 == 0) {
                                            do {
                                                src4 = (__int64 *)i2;
                                                src4 = (__int64 *)((__int64)src4 - (__int64)dst2);
                                                result = (struct Struct_1_t *)v_2d0;
                                                result -= i3;
                                                i = rsp + 720;
                                                i3 = (__int64)src4;
                                                sub_1400F5F90(i, i3);
                                                src4 = (__int64 *)i3;
                                                src2 = (__int64 *)v_48;
                                                result = (struct Struct_1_t *)v_2d8;
                                                v_60 = (__int64)result;
                                                i3 = v_2e0;
                                                v8 += (__int64)src2;
                                                i = (__int64 *)v_60;
                                                i += i3;
                                                dst2 = src4;
                                                sub_1400F27F0(i, v8, src4, v8);
                                                i3 += (__int64)src4;
                                                v_2e0 = i3;
                                                if (v_2d0 == i3) {
                                                    i = rsp + 720;
                                                    sub_1400F5F90(i, i3, 1, dst2);
                                                    i3 = v_2e0;
                                                }
                                                src3 = (__int64 *)v_50;
                                                i2 += v15;
                                                result = (struct Struct_1_t *)v_2d8;
                                                v_60 = (__int64)result;
                                                *(__int64 *)(result + i3) = (__int64)(10);
                                                ++i3;
                                                v_2e0 = i3;
                                                dst2 = (__int64 *)i2;
                                                src2 = (__int64 *)v_48;
                                                v9 = v_30;
                                                result = (struct Struct_1_t *)v_38;
                                                result += i2;
                                                if (v11 != -1) {
                                                    if (result < dst) {
                                                        do {
                                                            result = *(__int64 *)((__int64)src3 + (__int64)result);
                                                            i = (__int64 *)v_40;
                                                            i2 += v15;
                                                            v11 = 0;
                                                            result = (struct Struct_1_t *)v_38;
                                                            result += i2;
                                                            dst = dst2;
                                                            return (__int64)dst;
                                                        } while (result < dst);
                                                    }
                                                    return (__int64)dst;
                                                }
                                            } while (true);
                                        }
                                        return sub_1400617AC();
                                    }
                                    result = (struct Struct_1_t *)v_298;
                                    i = result + i2;
                                    result = (struct Struct_1_t *)v_2b0;
                                    v8 = v9;
                                    --v8;
                                    while (!((v8 < 0))) {
                                        if (i >= dst) JUMPOUT(0x1400616e9);
                                        src4 = result->field_0;
                                        --result;
                                        /* cmp src4 , *(__int64 *)((__int64)src3 + (__int64)i) */;
                                        --i;
                                        i2 += v_58;
                                        return i2;
                                    }
                                    v11 = -1;
                                    return v11;
                                }
                                return v11;
                            }
                            return v11;
                        }
                        return v11;
                    } else {
                        src = 0x8000000000000000;
                        i3 = 2;
                    }
                }
                return i3;
            } else {
                if (src > 16) {
                    v_70 = (__int64)src2;
                    v_78 = (__int64)src;
                    result = &off_140116C88;
                    v_80 = (__int64)result;
                    v_88 = 1;
                    if (src >= 66) {
                        xmm6 = _mm_load_si128((__m128i *)&off_1401086C0);
                        xmm7 = _mm_load_si128((__m128i *)&off_1401086D0);
                        i3 = rsp + 112;
                        v11 = 0;
                        do {
                            xmm0 = _mm_loadu_si128((__m128i *)(src2 + v11));
                            xmm1 = _mm_loadu_si128((__m128i *)(src2 + v11 + 1));
                            xmm12 = _mm_loadu_si128((__m128i *)(src2 + v11 + 16));
                            xmm13 = _mm_loadu_si128((__m128i *)(src2 + v11 + 17));
                            xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                            xmm1 = _mm_cmpeq_epi8(xmm1, xmm7);
                            xmm1 = _mm_and_si128(xmm1, xmm0);
                            src4 = _mm_movemask_epi8(xmm1);
                            xmm10 = _mm_loadu_si128((__m128i *)(src2 + v11 + 32));
                            xmm11 = _mm_loadu_si128((__m128i *)(src2 + v11 + 33));
                            xmm8 = _mm_loadu_si128((__m128i *)(src2 + v11 + 48));
                            xmm9 = _mm_loadu_si128((__m128i *)(src2 + v11 + 49));
                            sub_1400F8590(i3, v11, src4, 0);
                            src2 = (__int64 *)v_48;
                            i2 = (__int64)result;
                            xmm12 = _mm_cmpeq_epi8(xmm12, xmm6);
                            xmm13 = _mm_cmpeq_epi8(xmm13, xmm7);
                            xmm13 = _mm_and_si128(xmm13, xmm12);
                            src4 = _mm_movemask_epi8(xmm13);
                            if (src4 != 0) {
                                src2 = v11 + 16;
                                sub_1400F8590(i3, src2, src4, i2);
                                src2 = (__int64 *)v_48;
                                result = (struct Struct_1_t *)((__int64)(__int64)result | i2);
                                i2 = (__int64)result;
                            }
                            xmm10 = _mm_cmpeq_epi8(xmm10, xmm6);
                            xmm11 = _mm_cmpeq_epi8(xmm11, xmm7);
                            xmm11 = _mm_and_si128(xmm11, xmm10);
                            src4 = _mm_movemask_epi8(xmm11);
                            if (src4 != 0) {
                                src2 = v11 + 32;
                                sub_1400F8590(i3, src2, src4, i2);
                                src2 = (__int64 *)v_48;
                                result = (struct Struct_1_t *)((__int64)(__int64)result | i2);
                                i2 = (__int64)result;
                            }
                            xmm8 = _mm_cmpeq_epi8(xmm8, xmm6);
                            xmm9 = _mm_cmpeq_epi8(xmm9, xmm7);
                            xmm9 = _mm_and_si128(xmm9, xmm8);
                            src4 = _mm_movemask_epi8(xmm9);
                            if (src4 != 0) {
                                src2 = v11 + 48;
                                sub_1400F8590(i3, src2, src4, i2);
                                src2 = (__int64 *)v_48;
                                result = (struct Struct_1_t *)((__int64)(__int64)result | i2);
                                i2 = (__int64)result;
                                dst = v11 + 64;
                                v11 += 129;
                                if (v11 < src) {
                                    v11 = (__int64)dst;
                                    result = dst + 17;
                                    if (result < src) {
                                        if (i2 == 0) {
                                            xmm6 = _mm_load_si128((__m128i *)&off_1401086C0);
                                            xmm7 = _mm_load_si128((__m128i *)&off_1401086D0);
                                            i3 = rsp + 112;
                                            do {
                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)dst));
                                                xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)dst + 1));
                                                xmm1 = _mm_cmpeq_epi8(xmm1, xmm7);
                                                xmm1 = _mm_and_si128(xmm1, xmm0);
                                                src4 = _mm_movemask_epi8(xmm1);
                                                sub_1400F8590(i3, dst, src4, 0);
                                                src2 = (__int64 *)v_48;
                                                i2 = (__int64)result;
                                                result = dst + 33;
                                                if (result < src) {
                                                    dst += 16;
                                                }
                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)src - 17));
                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)src - 16));
                                                xmm0 = _mm_cmpeq_epi8(xmm0, _mm_load_si128((__m128i *)&off_1401086C0));
                                                xmm1 = _mm_cmpeq_epi8(xmm1, _mm_load_si128((__m128i *)&off_1401086D0));
                                                xmm1 = _mm_and_si128(xmm1, xmm0);
                                                src4 = _mm_movemask_epi8(xmm1);
                                                if (src4 != 0) {
                                                    src2 = src - 17;
                                                    i = rsp + 112;
                                                    sub_1400F8590(i, src2, src4, i2);
                                                    src2 = (__int64 *)v_48;
                                                    result = (struct Struct_1_t *)((__int64)(__int64)result | i2);
                                                    i2 = (__int64)result;
                                                    if (i2 != 0) {
                                                        return i2;
                                                    } else {
                                                        return i2;
                                                    }
                                                    return i2;
                                                } else {
                                                    if (i2 == 0) {
                                                        return i2;
                                                    } else {
                                                        return i2;
                                                    }
                                                    return i2;
                                                }
                                                return i2;
                                            } while (i2 == 0);
                                            return i2;
                                        }
                                    }
                                    return i2;
                                }
                                return i2;
                            }
                            dst = v11 + 64;
                            v11 += 129;
                            if (v11 < src) {
                                return v11;
                            }
                            return v11;
                        } while (i2 == 0);
                        return v11;
                    } else {
                        i2 = 0;
                        dst = 0;
                    }
                    return (__int64)dst;
                } else {
                    result = src + 1;
                    i = src2;
                    while (*i != 0xA0D) {
                        ++i;
                        --result;
                        return (__int64)result;
                    }
                }
                return (__int64)result;
            }
            return (__int64)result;
        } else {
            arg_10 = v11;
            arg_18 = i3;
            sub_14002EDF0(0, 16);
            if (result == 0) {
                v_cap = 16;
                sub_1400F3340(8);
                i = 1;
                return sub_1400615EC();
            } else {
                i = rsp + 728;
                xmm0 = _mm_loadu_si128((__m128i *)i);
                _mm_storeu_si128((__m128i *)result, xmm0);
                v8 = &off_140115B38;
                src2 = 8;
                i = 0;
                src4 = 0;
                i2 = v_40;
                v_490 = (__int64)i;
                v_498 = (__int64)src2;
                v_4a0 = (__int64)src4;
                v_4a8 = (__int64)result;
                i3 = i2;
                v_488 = 2;
                src = rsp + 0x498;
                result = (struct Struct_1_t *)v_498;
                src2 = (__int64 *)v_4a0;
                src4 = (__int64 *)v_4a8;
                v_70 = (__int64)i;
                dst2 = rsp + 120;
                v_78 = (__int64)result;
                v_80 = (__int64)src2;
                v_88 = (__int64)src4;
                v_90 = v8;
                i2 = v_80;
                if (i2 == i) {
                    i = rsp + 112;
                    sub_1400F8440(i);
                    i = (__int64 *)v_70;
                }
                result = (struct Struct_1_t *)v_78;
                src2 = i2 + i2*2;
                ((__int64 *)result)[(__int64)src2] = (__int64)(3);
                src4 = &off_140116C6F;
                *(__int64 *)(result + (__int64)(__int64)src2*8 + 8) = (__int64)(src4);
                *(__int64 *)(result + (__int64)(__int64)src2*8 + 16) = (__int64)(24);
                ++i2;
                v_80 = i2;
                xmm0 = _mm_loadu_si128((__m128i *)dst2);
                xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                _mm_store_si128((__m128i *)&v_2d0, xmm0);
                _mm_store_si128((__m128i *)&v_2e0, xmm1);
                result = 2;
                i2 = i3;
                v_488 = (__int64)result;
                v_490 = (__int64)i;
                xmm0 = _mm_load_si128((__m128i *)&v_2d0);
                xmm1 = _mm_load_si128((__m128i *)&v_2e0);
                _mm_storeu_si128((__m128i *)(src + 16), xmm1);
                _mm_storeu_si128((__m128i *)src, xmm0);
                dst = (__int64 *)v_488;
                v11 = v_490;
                src2 = (__int64 *)v_498;
                i3 = v_4a0;
                if (dst != 3) {
                    src = (__int64 *)v15;
                    xmm6 = _mm_loadu_si128((__m128i *)&v_4a8);
                    v15 = i3;
                    v15 >>= 8;
                    dst2 = src2;
                    if (dst == 1) JUMPOUT(0x14005ab3d);
                } else {
                    src = (__int64 *)v11;
                    return (__int64)src;
                }
                return (__int64)src;
            }
        }
        return (__int64)result;
    }
}