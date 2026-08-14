// inferred from 4 accesses on `i`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    int field_8; // offset 8
    __int64 field_C; // offset 12
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    int field_0; // offset 0
    int field_4; // offset 4
    int field_8; // offset 8
    __int64 field_C; // offset 12
};

__int64 sub_1400F3600();
__int64 sub_1400F3869();
__int64 sub_1400141B0();
__int64 sub_140013B30();
extern __int64 off_14010EE10;
extern __int64 off_14010B4D8;
extern __int64 off_14010EE40;
extern __int64 off_14010EE60;
extern __int64 off_14010EE88;
extern __int64 off_14010EE4C;
extern __int64 off_14010EE38;

__int64 __fastcall sub_140013D30(size_t *a1, size_t *a2) {
    __int64 rsp;
    int arg_10;
    int arg_20;
    int arg_30;
    int arg_48;
    int arg_50;
    int v_10;
    int v_20;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    __int64 *dst;
    __int64 v4;
    __int64 *dst2;
    __int64 *result;
    struct Struct_1_t *i;
    __int64 i2;
    __int64 v7;
    struct Struct_2_t *ptr;
    __m128i xmm0;
    __int64 i3;
    __int64 v11;
    __int64 v12;
    __int64 v10;
    __int64 v9;

    dst = rsp + 32;
    v4 = (__int64)a2;
    dst2 = (__int64 *)a1;
    if (a2 >= 8) {
        a1 = (size_t *)v4;
        a1 = (size_t *)((__int64)(__int64)a1 & 7);
        if (!((a1 == 0))) {
            result = &off_14010EE10;
            result = *(result + (__int64)(__int64)a1*4);
            result = (__int64 *)((__int64)(__int64)result >> (__int64)a1);
            a2 = *(dst2 + 160);
            if (a2 < 41) {
                if (a2 == 0) {
                    a2 = 0;
                    *(dst2 + 160) = a2;
                    if ((v4 & 8) != 0) {
                        a2 = *(dst2 + 160);
                        if (a2 >= 41) {
                            i = &off_14010B4D8;
                            sub_1400F3600(0, a2, 40, i);
                        } else {
                            if (a2 == 0) {
                                a2 = 0;
                            } else {
                                a1 =  + (__int64)(__int64)a2*4;
                                a1 -= 4;
                                i2 = (__int64)a1;
                                i2 >>= 2;
                                ++i2;
                                result = (__int64 *)i2;
                                result = (__int64 *)((__int64)(__int64)result & 3);
                                if (a1 >= 12) {
                                    i2 &= -4;
                                    a1 = 0;
                                    i = (struct Struct_1_t *)dst2;
                                    do {
                                        v7 = i->field_0;
                                        ptr = i->field_4;
                                        v7 *= 0x5F5E1;
                                        v7 += (__int64)a1;
                                        *(__int64 *)i = (__int64)(v7);
                                        v7 >>= 32;
                                        a1 = (__int64)(__int64)ptr * 0x5F5E1;
                                        a1 += v7;
                                        i->field_4 = a1;
                                        a1 = (size_t *)((__int64)(__int64)a1 >> 32);
                                        v7 = i->field_8;
                                        v7 *= 0x5F5E1;
                                        v7 += (__int64)a1;
                                        i->field_8 = v7;
                                        a1 = (size_t *)v7;
                                        a1 = (size_t *)((__int64)(__int64)a1 >> 32);
                                        v7 = i->field_C;
                                        v7 *= 0x5F5E1;
                                        v7 += (__int64)a1;
                                        i->field_C = v7;
                                        i += 16;
                                        a1 = (size_t *)v7;
                                        a1 = (size_t *)((__int64)(__int64)a1 >> 32);
                                        i2 -= 4;
                                    } while ((i2 != 0));
                                } else {
                                    a1 = 0;
                                    i = (struct Struct_1_t *)dst2;
                                }
                                if (result != 0) {
                                    for (i2 = 0; result != i2; ++i2) {
                                        v7 = *(__int64 *)(i + i2*4);
                                        v7 *= 0x5F5E1;
                                        v7 += (__int64)a1;
                                        a1 = (size_t *)v7;
                                        a1 = (size_t *)((__int64)(__int64)a1 >> 32);
                                        *(__int64 *)(i + i2*4) = (__int64)(v7);
                                    }
                                }
                                v7 >>= 32;
                                if (!((v7 == 0))) {
                                    if (a2 == 40) {
                                        i2 = &off_14010B4D8;
                                        sub_1400F3869(40, 40, i2);
                                        dst = rsp + 128;
                                        dst2 = (__int64 *)a1;
                                        xmm0 = _mm_setzero_si128();
                                        _mm_store_si128((__m128i *)&arg_30, xmm0);
                                        _mm_store_si128((__m128i *)&arg_20, xmm0);
                                        _mm_store_si128((__m128i *)&arg_10, xmm0);
                                        _mm_store_si128((__m128i *)&*dst, xmm0);
                                        _mm_store_si128((__m128i *)&v_10, xmm0);
                                        _mm_store_si128((__m128i *)&v_20, xmm0);
                                        _mm_store_si128((__m128i *)&v_30, xmm0);
                                        _mm_store_si128((__m128i *)&v_40, xmm0);
                                        _mm_store_si128((__m128i *)&v_50, xmm0);
                                        _mm_store_si128((__m128i *)&v_60, xmm0);
                                        result = a1[20];
                                        if (result >= i2) JUMPOUT(0x1400142c6);
                                        result = dst2 + (__int64)(__int64)result*4;
                                        i =  + i2*4;
                                        a1 = i2 + 1;
                                        arg_48 = (int)a1;
                                        i3 = 0;
                                        ptr = (struct Struct_2_t *)dst2;
                                        v4 = 0;
                                        do {
                                            if (ptr == result) JUMPOUT(0x14001436c);
                                            v11 = i3;
                                            ++i3;
                                            v12 = ptr->field_0;
                                            ptr += 4;
                                            arg_50 = v4;
                                            v10 = 0;
                                            a1 = (size_t *)v11;
                                            v9 = 0;
                                            for (; i != v10; v10 += 4) {
                                                if (a1 >= 40) JUMPOUT(0x1400143b3);
                                                v7 = *(a2 + v10);
                                                v4 = *(dst + (__int64)(__int64)a1*4 - 96);
                                                v9 += v4;
                                                v7 *= v12;
                                                v7 += v9;
                                                v9 = v7;
                                                v9 >>= 32;
                                                *(dst + (__int64)(__int64)a1*4 - 96) = v7;
                                                ++a1;
                                            }
                                            a1 = (size_t *)i2;
                                            v4 = arg_50;
                                            if (v9 == 0) {
                                                a1 += v11;
                                                if (v4 <= a1) v4 = a1;
                                            }
                                            a1 = v11 + i2;
                                            if (a1 >= 40) JUMPOUT(0x1400143b3);
                                            *(dst + (__int64)(__int64)a1*4 - 96) = v9;
                                            a1 = (size_t *)arg_48;
                                            return (__int64)a1;
                                        } while (v12 == 0);
                                    } else {
                                        *(dst2 + (__int64)(__int64)a2*4) = a1;
                                        ++a2;
                                    }
                                }
                            }
                            *(dst2 + 160) = a2;
                            if ((v4 & 16) == 0) {
                                if ((v4 & 32) != 0) {
                                    a2 = &off_14010EE40;
                                    sub_1400141B0(dst2, a2, 3);
                                    if ((v4 & 64) == 0) {
                                        if (v4 < 0) {
                                            a2 = &off_14010EE60;
                                            sub_1400141B0(dst2, a2, 10);
                                            if ((v4 & 256) != 0) {
                                                a2 = &off_14010EE88;
                                                sub_1400141B0(dst2, a2, 19, i);
                                            } else {
                                            }
                                            sub_140013B30(dst2, v4);
                                            result = dst2;
                                            return (__int64)result;
                                        } else {
                                            if ((v4 & 256) != 0) {
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    } else {
                                        a2 = &off_14010EE4C;
                                        sub_1400141B0(dst2, a2, 5);
                                        if (v4 >= 0) {
                                            return (__int64)a2;
                                        } else {
                                            return (__int64)a2;
                                        }
                                        return (__int64)a2;
                                    }
                                    return (__int64)a2;
                                } else {
                                    if ((v4 & 64) != 0) {
                                        return (__int64)a2;
                                    } else {
                                        return (__int64)a2;
                                    }
                                    return (__int64)a2;
                                }
                                return (__int64)a2;
                            } else {
                                a2 = &off_14010EE38;
                                sub_1400141B0(dst2, a2, 2, i);
                                if ((v4 & 32) == 0) {
                                    return (__int64)a2;
                                } else {
                                    return (__int64)a2;
                                }
                                return (__int64)a2;
                            }
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    } else {
                        if ((v4 & 16) != 0) {
                            return (__int64)a2;
                        } else {
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                } else {
                    i2 =  + (__int64)(__int64)a2*4;
                    i2 -= 4;
                    i = (struct Struct_1_t *)i2;
                    i = (struct Struct_1_t *)((__int64)(__int64)i >> 2);
                    ++i;
                    a1 = (size_t *)i;
                    a1 = (size_t *)((__int64)(__int64)a1 & 3);
                    if (i2 >= 12) {
                        i = (struct Struct_1_t *)((__int64)(__int64)i & -4);
                        i2 = 0;
                        ptr = (struct Struct_2_t *)dst2;
                        do {
                            v7 = ptr->field_0;
                            i3 = ptr->field_4;
                            v7 *= (__int64)result;
                            v7 += i2;
                            *(__int64 *)ptr = (__int64)(v7);
                            v7 >>= 32;
                            i3 *= (__int64)result;
                            i3 += v7;
                            ptr->field_4 = i3;
                            i3 >>= 32;
                            i2 = ptr->field_8;
                            i2 *= (__int64)result;
                            i2 += i3;
                            ptr->field_8 = i2;
                            i2 >>= 32;
                            v7 = ptr->field_C;
                            v7 *= (__int64)result;
                            v7 += i2;
                            ptr->field_C = v7;
                            ptr += 16;
                            i2 = v7;
                            i2 >>= 32;
                            i -= 4;
                        } while ((i != 0));
                    } else {
                        i2 = 0;
                        ptr = (struct Struct_2_t *)dst2;
                    }
                    if (a1 != 0) {
                        for (i = 0; a1 != i; ++i) {
                            v7 = *(__int64 *)(ptr + (__int64)(__int64)i*4);
                            v7 *= (__int64)result;
                            v7 += i2;
                            i2 = v7;
                            i2 >>= 32;
                            *(__int64 *)(ptr + (__int64)(__int64)i*4) = (__int64)(v7);
                        }
                    }
                    v7 >>= 32;
                    if (!((v7 == 0))) {
                        if (a2 != 40) {
                            *(dst2 + (__int64)(__int64)a2*4) = i2;
                            ++a2;
                            *(dst2 + 160) = a2;
                            if ((v4 & 8) == 0) {
                                return (__int64)a2;
                            } else {
                                return (__int64)a2;
                            }
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                }
                return (__int64)a2;
            }
            return (__int64)a2;
        }
        return (__int64)a2;
    } else {
        a2 = *(dst2 + 160);
        if (a2 >= 41) {
            return (__int64)a2;
        } else {
            if (a2 == 0) {
                a2 = 0;
                *(dst2 + 160) = a2;
            } else {
                result = &off_14010EE10;
                result = *(result + v4*4);
                i2 =  + (__int64)(__int64)a2*4;
                i2 -= 4;
                i = (struct Struct_1_t *)i2;
                i = (struct Struct_1_t *)((__int64)(__int64)i >> 2);
                ++i;
                a1 = (size_t *)i;
                a1 = (size_t *)((__int64)(__int64)a1 & 3);
                if (i2 >= 12) {
                    i = (struct Struct_1_t *)((__int64)(__int64)i & -4);
                    i2 = 0;
                    ptr = (struct Struct_2_t *)dst2;
                    do {
                        v7 = ptr->field_0;
                        v4 = ptr->field_4;
                        v7 *= (__int64)result;
                        v7 += i2;
                        *(__int64 *)ptr = (__int64)(v7);
                        v7 >>= 32;
                        v4 *= (__int64)result;
                        v4 += v7;
                        ptr->field_4 = v4;
                        v4 >>= 32;
                        i2 = ptr->field_8;
                        i2 *= (__int64)result;
                        i2 += v4;
                        ptr->field_8 = i2;
                        i2 >>= 32;
                        v7 = ptr->field_C;
                        v7 *= (__int64)result;
                        v7 += i2;
                        ptr->field_C = v7;
                        ptr += 16;
                        i2 = v7;
                        i2 >>= 32;
                        i -= 4;
                    } while ((i != 0));
                } else {
                    i2 = 0;
                    ptr = (struct Struct_2_t *)dst2;
                }
                if (a1 != 0) {
                    for (i = 0; a1 != i; ++i) {
                        v7 = *(__int64 *)(ptr + (__int64)(__int64)i*4);
                        v7 *= (__int64)result;
                        v7 += i2;
                        i2 = v7;
                        i2 >>= 32;
                        *(__int64 *)(ptr + (__int64)(__int64)i*4) = (__int64)(v7);
                    }
                }
                v7 >>= 32;
                if (!((v7 == 0))) {
                    if (a2 == 40) {
                        return v7;
                    } else {
                        *(dst2 + (__int64)(__int64)a2*4) = i2;
                        ++a2;
                    }
                }
                *(dst2 + 160) = a2;
            }
            return (__int64)a2;
        }
        return (__int64)a2;
    }
    return (__int64)result;
}