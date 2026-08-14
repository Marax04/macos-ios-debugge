// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
    char _pad_4[4];
    __int64 field_10; // offset 16
};

__int64 sub_1400F1D90();
__int64 sub_1400F6840();
__int64 sub_1400F2808();
__int64 sub_1400F68D0();
__int64 sub_1400F37D0();
__int64 sub_1400F3869();
__int64 off_140108128();
__int64 off_140108130();
__int64 off_140108048();
__int64 off_140108100();
__int64 off_140108108();
__int64 off_140108110();
__int64 off_140108118();
__int64 off_140108030();
__int64 off_140108038();
__int64 off_140108140();
__int64 off_140108120();
extern __int64 off_140112320;
extern __int64 off_140112310;
extern __int64 off_14012D198;
extern __int64 off_14012D1A0;
extern __int64 off_140112350;
extern __int64 off_14012D190;
extern __int64 off_14012D1A8;
extern __int64 off_14011235C;
extern __int64 off_14012D1B0;
extern __int64 off_14011236A;
extern __int64 off_14012D1B8;
extern __int64 off_140112378;
extern __int64 off_14012D1C0;
extern __int64 off_140112387;
extern __int64 off_14012D1D8;
extern __int64 off_1401123BF;
extern __int64 off_14012D1E0;
extern __int64 off_140112409;
extern __int64 off_14012D1E8;
extern __int64 off_1401123EF;
extern __int64 off_14012D1F0;
extern __int64 off_1401123AB;
extern __int64 off_1401122C4;
extern __int64 off_1401122E0;
extern __int64 off_140112338;
extern __int64 off_14012D1D0;
extern __int64 off_1401123D5;
extern __int64 off_14002B630;
extern __int64 off_14012D1C8;
extern __int64 off_140112399;

__int64 __fastcall sub_14002A420(size_t *a1, size_t a2, int a3) {
    __int64 rsp;
    int arg_10;
    int arg_10f0;
    int arg_10f8;
    __int64 arg_1100;
    int arg_1108;
    int arg_1110;
    int arg_1118;
    int arg_1120;
    int arg_1148;
    int arg_1157;
    int arg_1158;
    int arg_1160;
    int arg_fc0;
    int arg_fc8;
    int arg_fd0;
    int v_10;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    __int64 *dst;
    __int64 *src;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __int64 v5;
    __int64 result;
    __int64 *dst2;
    __int64 v8;
    __int64 v9;
    __int64 i;
    __int64 i2;
    __m128i xmm6;

    sub_1400F1D90(0x11F8);
    dst = rsp + 128;
    _mm_store_si128((__m128i *)&arg_1160, xmm6);
    arg_1158 = -2;
    src = (__int64 *)a3;
    arg_10f0 = a2;
    ptr = (struct Struct_1_t *)a1;
    if (a1 == 0) {
        xmm0 = _mm_loadu_si128((__m128i *)&off_140112320);
        _mm_store_si128((__m128i *)&v_30, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&off_140112310);
        _mm_store_si128((__m128i *)&v_40, xmm0);
        v_20 = 0;
        off_140108128();
        if (result != 0) {
            a1 = 31;
            while (a1 <= 32) {
                a2 = result;
                a2 &= 15;
                a3 = a2 + 48;
                v5 = a2 + 55;
                a2 = a3;
                a3 = v5;
                if (a2 < 10) v5 = a2;
                *(__int64 *)((__int64)dst + (__int64)a1 - 64) = a3;
                if (result >= 16) {
                    a2 = result;
                    a2 >>= 4;
                    a3 = a2 + 48;
                    a2 += 55;
                    if (result < 160) a2 = a3;
                    *(__int64 *)((__int64)dst + (__int64)a1 - 65) = a2;
                    a2 = result;
                    a2 >>= 8;
                    a1 -= 2;
                    /* cmp result , 256 */;
                    result = a2;
                }
                a3 = dst - 64;
                off_140108130(0, 0, a3, v5);
                if (result != 0) {
                    result = 0;
                    /* cmpxchg %(__int64)a1, off_14012D198 */;
                    if (!((0 /* unresolved: flags == */))) {
                        dst2 = (__int64 *)result;
                        off_140108048(result);
                        a1 = (size_t *)result;
                    }
                    arg_1148 = (int)a1;
                    off_140108100(off_14012D198, 0xFFFFFFFF, 0);
                    result = off_14012D1A0;
                    if (result == 0) {
                        a1 = &off_140112350;
                        off_140108108(a1);
                        off_14012D1A0 = result;
                        if (result != 0) {
                            if (off_14012D190 == 0) {
                                a1 = off_14012D1A8;
                                if (a1 == 0) {
                                    a2 = &off_14011235C;
                                    off_140108110(result, a2);
                                    if (result != 0) {
                                        off_14012D1A8 = result;
                                        ((__int64 (*)())a1)(result);
                                        a1 = (size_t *)result;
                                        result = off_14012D1B0;
                                        if (result == 0) {
                                            dst2 = (__int64 *)a1;
                                            a2 = &off_14011236A;
                                            off_140108110(off_14012D1A0, a2);
                                            if (result != 0) {
                                                off_14012D1B0 = result;
                                                a1 = (size_t *)dst2;
                                                a1 = (size_t *)((__int64)(__int64)a1 | 4);
                                                ((__int64 (*)())result)(a1);
                                                dst2 = off_14012D1B8;
                                                if (dst2 == 0) {
                                                    a2 = &off_140112378;
                                                    off_140108110(off_14012D1A0, a2);
                                                    if (result != 0) {
                                                        dst2 = (__int64 *)result;
                                                        off_14012D1B8 = result;
                                                        off_140108118();
                                                        ((__int64 (*)())dst2)(result, 0, 1);
                                                        arg_1110 = 0;
                                                        arg_1118 = 2;
                                                        arg_1120 = 0;
                                                        arg_1157 = 0;
                                                        v_20 = 2;
                                                        a1 = dst + 0x1110;
                                                        sub_1400F6840(a1, 0, 0x400, 2);
                                                        dst2 = (__int64 *)arg_1118;
                                                        v8 = arg_1120;
                                                        a1 = dst2 + v8*2;
                                                        sub_1400F2808(a1, 0, 0x7FE);
                                                        *(dst2 + v8*2 + 0x7FE) = 0;
                                                        v8 += 0x400;
                                                        arg_1120 = v8;
                                                        v9 = off_14012D1C0;
                                                        if (v9 == 0) {
                                                            a2 = &off_140112387;
                                                            off_140108110(off_14012D1A0, a2);
                                                            if (result == 0) {
                                                                if (arg_1110 != 0) {
                                                                    off_140108030();
                                                                    off_140108038(result, 0, dst2);
                                                                } else {
                                                                }
                                                                off_14012D190 = 1;
                                                                dst2 = ptr->field_10;
                                                                v8 = ptr->field_0;
                                                                i = ptr->field_4;
                                                                result = *(src + 32);
                                                                arg_10f8 = result;
                                                                off_140108118();
                                                                src = (__int64 *)result;
                                                                ptr = off_14012D1D8;
                                                                if (ptr == 0) {
                                                                    a2 = &off_1401123BF;
                                                                    off_140108110(off_14012D1A0, a2);
                                                                    if (result != 0) {
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        off_14012D1D8 = result;
                                                                        result = off_14012D1E0;
                                                                        arg_1108 = result;
                                                                        if (result == 0) {
                                                                            a2 = &off_140112409;
                                                                            off_140108110(off_14012D1A0, a2);
                                                                            arg_1108 = result;
                                                                            if (result != 0) {
                                                                                result = arg_1108;
                                                                                off_14012D1E0 = result;
                                                                                v9 = dst2 - 1;
                                                                                if (dst2 == 0) v9 = dst2;
                                                                                dst2 = 1;
                                                                                if (v8 == 0) {
                                                                                    dst2 = off_14012D1E8;
                                                                                    if (dst2 == 0) {
                                                                                        a2 = &off_1401123EF;
                                                                                        off_140108110(off_14012D1A0, a2);
                                                                                        if (result != 0) {
                                                                                            dst2 = (__int64 *)result;
                                                                                            off_14012D1E8 = result;
                                                                                            v8 = off_14012D1F0;
                                                                                            if (v8 == 0) {
                                                                                                a2 = &off_1401123AB;
                                                                                                off_140108110(off_14012D1A0, a2);
                                                                                                if (result != 0) {
                                                                                                    v8 = result;
                                                                                                    off_14012D1F0 = result;
                                                                                                    ((__int64 (*)())dst2)(src, v9);
                                                                                                    arg_fc0 = 0;
                                                                                                    dst2 = 1;
                                                                                                    if (result == 0) {
                                                                                                        i = 0;
                                                                                                        dst2 += i;
                                                                                                        if (i < dst2) {
                                                                                                            i2 = dst - 60;
                                                                                                            v8 = dst + 0xFC0;
                                                                                                            xmm6 = _mm_setzero_si128();
                                                                                                            arg_1100 = (__int64)ptr;
                                                                                                            do {
                                                                                                                sub_1400F2808(i2, 0, 0xFF4);
                                                                                                                arg_10 = 0x7D0;
                                                                                                                v_40 = 88;
                                                                                                                arg_fc0 = 0;
                                                                                                                result = dst - 64;
                                                                                                                v_20 = result;
                                                                                                                ((__int64 (*)())ptr)(src, v9, i, v8);
                                                                                                                ++i;
                                                                                                            } while (i != dst2);
                                                                                                        }
                                                                                                        a1 = (size_t *)arg_1148;
                                                                                                        off_140108140(a1, a2, a3, 1);
                                                                                                        xmm6 = _mm_load_si128((__m128i *)&arg_1160);
                                                                                                        return _mm_cvtsi128_si64(xmm6);
                                                                                                    } else {
                                                                                                        i2 = result;
                                                                                                        v_40 = 0;
                                                                                                        result = dst - 64;
                                                                                                        v_30 = result;
                                                                                                        result = dst + 0xFC0;
                                                                                                        v_28 = result;
                                                                                                        v_20 = v9;
                                                                                                        i = 0;
                                                                                                        ((__int64 (*)())v8)(src, v9, 0, v9);
                                                                                                        if (result == 1) {
                                                                                                            ++i2;
                                                                                                            i = arg_fc0;
                                                                                                            dst2 = (__int64 *)i2;
                                                                                                        }
                                                                                                        dst2 += i;
                                                                                                        if (i < dst2) {
                                                                                                            return (__int64)dst2;
                                                                                                        }
                                                                                                        return (__int64)dst2;
                                                                                                    }
                                                                                                    return (__int64)dst2;
                                                                                                }
                                                                                                return (__int64)dst2;
                                                                                            }
                                                                                            return (__int64)dst2;
                                                                                        }
                                                                                    } else {
                                                                                        v8 = off_14012D1F0;
                                                                                        if (v8 == 0) {
                                                                                            return v8;
                                                                                        }
                                                                                        return v8;
                                                                                    }
                                                                                    return v8;
                                                                                }
                                                                                return v8;
                                                                            }
                                                                            return v8;
                                                                        }
                                                                        return v8;
                                                                    }
                                                                } else {
                                                                    result = off_14012D1E0;
                                                                    arg_1108 = result;
                                                                    if (result == 0) {
                                                                        return arg_1108;
                                                                    }
                                                                    return arg_1108;
                                                                }
                                                                return arg_1108;
                                                            } else {
                                                                v9 = result;
                                                                off_14012D1C0 = result;
                                                                off_140108118();
                                                                ((__int64 (*)())v9)(result, dst2, v8);
                                                                if (result != 1) {
                                                                    arg_1120 = 0;
                                                                    result = arg_1110;
                                                                    if (result == 0) {
                                                                        arg_1157 = 0;
                                                                        a1 = dst + 0x1110;
                                                                        sub_1400F68D0(a1);
                                                                        result = arg_1110;
                                                                        dst2 = (__int64 *)arg_1118;
                                                                        *dst2 = 46;
                                                                        arg_1120 = 1;
                                                                        if (result == 1) {
                                                                            arg_1157 = 0;
                                                                            a1 = dst + 0x1110;
                                                                            sub_1400F68D0(a1);
                                                                            dst2 = (__int64 *)arg_1118;
                                                                        }
                                                                    } else {
                                                                        *dst2 = 46;
                                                                        arg_1120 = 1;
                                                                        if (result == 1) {
                                                                            return arg_1120;
                                                                        } else {
                                                                        }
                                                                    }
                                                                    *(dst2 + 2) = 59;
                                                                    result = 2;
                                                                } else {
                                                                    off_140108120(dst2);
                                                                    if (result < 0) {
                                                                        arg_1157 = 0;
                                                                        a1 = &off_1401122C4;
                                                                        a3 = &off_1401122E0;
                                                                        sub_1400F37D0(a1, 26, a3);
                                                                        a3 = &off_140112338;
                                                                        sub_1400F3869(-1, 33, a3);
                                                                        v_10 = a2;
                                                                        dst = a2 + 128;
                                                                        _mm_store_si128((__m128i *)&v_40, xmm6);
                                                                        if (arg_1157 == 0) {
                                                                            if (arg_1110 != 0) {
                                                                                dst2 = (__int64 *)arg_1118;
                                                                                off_140108030();
                                                                                off_140108038(result, 0, dst2);
                                                                            }
                                                                        }
                                                                        a1 = (size_t *)arg_1148;
                                                                        off_140108140(a1);
                                                                        xmm6 = _mm_load_si128((__m128i *)&v_40);
                                                                        return _mm_cvtsi128_si64(xmm6);
                                                                    } else {
                                                                        if (v8 >= result) {
                                                                            arg_1120 = result;
                                                                        } else {
                                                                        }
                                                                        result = arg_1120;
                                                                        arg_fd0 = result;
                                                                        xmm0 = _mm_loadu_si128((__m128i *)&arg_1110);
                                                                        _mm_store_si128((__m128i *)&arg_fc0, xmm0);
                                                                        dst2 = off_14012D1D0;
                                                                        if (dst2 == 0) {
                                                                            a2 = &off_1401123D5;
                                                                            off_140108110(off_14012D1A0, a2);
                                                                            if (result == 0) {
                                                                                if (arg_fc0 != 0) {
                                                                                    dst2 = (__int64 *)arg_fc8;
                                                                                    return (__int64)dst2;
                                                                                }
                                                                            } else {
                                                                                dst2 = (__int64 *)result;
                                                                                off_14012D1D0 = result;
                                                                                off_140108118();
                                                                                a2 = &off_14002B630;
                                                                                a3 = dst + 0xFC0;
                                                                                ((__int64 (*)())dst2)(result, a2, a3);
                                                                                xmm0 = _mm_load_si128((__m128i *)&arg_fc0);
                                                                                _mm_store_si128((__m128i *)&v_40, xmm0);
                                                                                v8 = arg_fd0;
                                                                                v_30 = v8;
                                                                                v9 = v_40;
                                                                                if (v8 == v9) {
                                                                                    a1 = dst - 64;
                                                                                    sub_1400F68D0(a1);
                                                                                    v9 = v_40;
                                                                                }
                                                                                dst2 = (__int64 *)v_38;
                                                                                *(dst2 + v8*2) = 0;
                                                                                v8 = off_14012D1C8;
                                                                                if (v8 == 0) {
                                                                                    a2 = &off_140112399;
                                                                                    off_140108110(off_14012D1A0, a2);
                                                                                    if (result != 0) {
                                                                                        v8 = result;
                                                                                        off_14012D1C8 = result;
                                                                                        off_140108118();
                                                                                        ((__int64 (*)())v8)(result, dst2);
                                                                                    }
                                                                                    if (v9 != 0) {
                                                                                        return off_14012D1C8;
                                                                                    }
                                                                                    return off_14012D1C8;
                                                                                }
                                                                                return off_14012D1C8;
                                                                            }
                                                                            return off_14012D1C8;
                                                                        }
                                                                        return off_14012D1C8;
                                                                    }
                                                                }
                                                                return off_14012D1C8;
                                                            }
                                                            return off_14012D1C8;
                                                        }
                                                        return off_14012D1C8;
                                                    }
                                                    return off_14012D1C8;
                                                }
                                                return off_14012D1C8;
                                            }
                                            return off_14012D1C8;
                                        }
                                        return off_14012D1C8;
                                    }
                                    return off_14012D1C8;
                                }
                                return off_14012D1C8;
                            }
                            return off_14012D1C8;
                        }
                        return off_14012D1C8;
                    }
                    return off_14012D1C8;
                }
                return off_14012D1C8;
            }
            return off_14012D1C8;
        }
        return off_14012D1C8;
    }
    return result;
}