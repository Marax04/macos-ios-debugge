// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a3`
struct Struct_2_t {
    char _pad_start[7];
    char field_7; // offset 7
    char field_8; // offset 8
    __int64 field_9; // offset 9
};

// inferred from 5 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int64 field_2; // offset 2
    char _pad_2[30];
    __int64 field_28; // offset 40
    char _pad_28[48];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
};

// inferred from 3 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140083930();
__int64 sub_1400898F0();
__int64 sub_1400831AD();
__int64 sub_140083196();
extern __int64 off_140123764;
extern __int64 off_140123544;

__int64 __fastcall sub_1400828B0(size_t *a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    __int64 rsp;
    int v_20;
    __int64 v_28;
    int v_30;
    int v_44;
    int v_48;
    int v_54;
    int v_58;
    int v_64;
    int v_68;
    int v_74;
    int v_78;
    int v_80;
    __int64 v_88;
    int v_a0;
    int v_b0;
    int v_c0;
    int i;
    int v_d8;
    int v_d9;
    int v_da;
    int v_e8;
    int v_e9;
    int v_ea;
    char *str;
    __int64 i2;
    struct Struct_3_t *ptr;
    __int64 v2;
    int v8;
    __int64 v7;
    int v9;
    __int64 *result;
    __int64 v6;
    int v10;
    int v11;
    struct Struct_4_t *ptr2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    if ((a3->field_7 & 1) == 0) {
        *a1 = 5;
    } else {
        i2 = ((__int64 *)a2)[2];
        if (i2 >= a2->field_8) {
            *a1 = 2;
            *(a1 + 2) = 0;
        } else {
            ptr = (struct Struct_3_t *)a1;
            v2 = a3->field_8;
            v8 = ((__int64 *)a3)[1];
            a1 = ((__int64 *)a3)[1];
            v7 = a3->field_9;
            v9 = v7;
            v9 >>= 8;
            result = a2->field_0;
            result = *(result + i2);
            v6 = (__int64)result;
            ++i2;
            ((__int64 *)a2)[2] = (__int64)(i2);
            str = 4;
            v_a0 = 4;
            v_b0 = 4;
            v_c0 = 4;
            i = 0;
            v10 = (a1 != 0) ? 1 : 0;
            i2 = (a1 == 0) ? 1 : 0;
            i2 ^= 5;
            a1 = (size_t *)v8;
            a1 = (size_t *)((__int64)(__int64)a1 & 7);
            v11 = 4;
            v11 >>= (__int64)a1;
            ptr2 = (v8 < 3) ? 1 : 0;
            a1 = (size_t *)v8;
            v8 = 3;
            if (v11 < 0) v8 = a1;
            v9 &= 15;
            v10 <<= 4;
            v10 |= v9;
            v10 += 16;
            v2 >>= 4;
            a1 = (size_t *)v2;
            a1 = (size_t *)((__int64)(__int64)a1 & 1);
            v_ea = (int)a1;
            v_e9 = v8;
            v_d8 = 0;
            v_d9 = i2;
            v_da = v10;
            v_e8 = i2;
            if (v7 == 1) {
                a1 = v6 - 90;
                if (a1 <= 37) {
                    ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 & v11);
                    v2 = &off_140123764;
                    a1 = (size_t *)ptr;
                    switch ((__int64)a1) {
                        case 1:
                            return (__int64)a1;
                        case 21:
                            v_20 = 0;
                            return v_20;
                        case 28:
                            result = rsp + 216;
                            v_28 = (__int64)result;
                            v_20 = i2;
                            v_30 = 310;
                            return v_30;
                        case 37:
                            v_20 = 1;
                            result = rsp + 144;
                            sub_140083930(a2, a3, result);
                            if (result != 6) {
                                a1 = (size_t *)result;
                                a1 = (size_t *)((__int64)(__int64)a1 >> 8);
                                *(__int64 *)ptr = (__int64)(result);
                                ptr->field_1 = a1;
                                ptr->field_28 = 5;
                            } else {
                                result = (__int64 *)v2;
                                result = (__int64 *)((__int64)(__int64)result & 1);
                                ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ 1);
                                a1 = (size_t *)ptr2;
                                result += (__int64)(__int64)a1*2;
                                result += 301;
                                a1 = (size_t *)i;
                                v_88 = (__int64)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&str);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_c0);
                                _mm_storeu_si128((__m128i *)&v_78, xmm3);
                                _mm_storeu_si128((__m128i *)&v_68, xmm2);
                                _mm_storeu_si128((__m128i *)&v_58, xmm1);
                                _mm_storeu_si128((__m128i *)&v_48, xmm0);
                                *(__int64 *)ptr = (__int64)(186);
                                ptr->field_2 = result;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_44);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_54);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_64);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_74);
                                _mm_storeu_si128((__m128i *)(ptr + 36), xmm0);
                                _mm_storeu_si128((__m128i *)(ptr + 52), xmm1);
                                _mm_storeu_si128((__m128i *)(ptr + 68), xmm2);
                                _mm_storeu_si128((__m128i *)(ptr + 84), xmm3);
                                result = (__int64 *)v_80;
                                ptr->field_60 = result;
                                result = (__int64 *)v_88;
                                ptr->field_68 = result;
                            }
                            break;
                        default:
                            a1 = (size_t *)ptr;
                            if (v6 == 250) {
                                result = rsp + 216;
                                v_28 = (__int64)result;
                                v_20 = i2;
                                v_30 = 306;
                            } else {
                                if (v6 != 254) {
                                    *a1 = 0x6201;
                                    *(a1 + 2) = result;
                                    a1[5] = 5;
                                } else {
                                    result = rsp + 216;
                                    v_28 = (__int64)result;
                                    v_20 = i2;
                                    v_30 = 305;
                                    sub_1400898F0(a1, a2, a3, str);
                                }
                                return v_30;
                            }
                            return v_30;
                    }
                    return v_30;
                }
                return v_30;
            } else {
                a1 = (size_t *)v7;
                if (v7 == 2) {
                    a1 = v6 - 49;
                    if (a1 <= 135) {
                        v7 = &off_140123544;
                        switch ((__int64)a1) {
                            case 5:
                                break;
                            case 15:
                                result = rsp + 216;
                                v_28 = (__int64)result;
                                v_20 = i2;
                                v_30 = 307;
                                return sub_1400831AD();
                            case 95:
                                result = rsp + 216;
                                v_28 = (__int64)result;
                                v_20 = i2;
                                v_30 = 203;
                                return sub_1400831AD();
                            case 103:
                                if (v6 == 152) JUMPOUT(0x140083186);
                                if (v6 == 168) JUMPOUT(0x140083174);
                                if (v6 != 184) JUMPOUT(0x1400831c2);
                                result = 0;
                                result = ((v2 & 1) != 0) ? 1 : 0;
                                result += (__int64)(__int64)result*2;
                                result += 273;
                                return sub_140083196();
                            default:
                                v_20 = 1;
                                result = rsp + 144;
                                sub_140083930(a2, a3, result);
                                if (result != 6) {
                                    return (__int64)result;
                                } else {
                                    result = (__int64 *)i;
                                    v_88 = (__int64)result;
                                    xmm0 = _mm_loadu_si128((__m128i *)&str);
                                    xmm1 = _mm_loadu_si128((__m128i *)&v_a0);
                                    xmm2 = _mm_loadu_si128((__m128i *)&v_b0);
                                    xmm3 = _mm_loadu_si128((__m128i *)&v_c0);
                                    _mm_storeu_si128((__m128i *)&v_78, xmm3);
                                    _mm_storeu_si128((__m128i *)&v_68, xmm2);
                                    _mm_storeu_si128((__m128i *)&v_58, xmm1);
                                    _mm_storeu_si128((__m128i *)&v_48, xmm0);
                                    *(__int64 *)ptr = (__int64)(186);
                                    ptr->field_2 = 315;
                                    return _mm_cvtsi128_si64(xmm3);
                                }
                                return _mm_cvtsi128_si64(xmm3);
                        }
                    }
                } else {
                    if (a1 != 3) {
                        *(__int64 *)ptr = (__int64)(0x6201);
                        ptr->field_2 = result;
                        ptr->field_28 = 5;
                    } else {
                        if (v6 == 30) {
                            v_20 = 0;
                            result = rsp + 144;
                            ptr2 = (struct Struct_4_t *)a2;
                            sub_140083930(a2, a3, result);
                            if (result != 6) {
                                return (__int64)ptr2;
                            } else {
                                a1 = ptr2->field_10;
                                if (a1 >= ptr2->field_8) {
                                    *(__int64 *)ptr = (__int64)(2);
                                    ptr->field_2 = 0;
                                    ptr->field_28 = 5;
                                } else {
                                    result = ptr2->field_0;
                                    result = *(__int64 *)((__int64)result + (__int64)a1);
                                    ++a1;
                                    ptr2->field_10 = a1;
                                    a1 = (size_t *)i;
                                    if (a1 <= 3) {
                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                        *(__int64 *)(rsp + a1 + 144) = 2;
                                        *(__int64 *)(rsp + a1 + 152) = result;
                                        ++i;
                                    }
                                    result = (__int64 *)v2;
                                    result = (__int64 *)((__int64)(__int64)result & 1);
                                    result += 313;
                                    return (__int64)result;
                                }
                            }
                            return (__int64)result;
                        } else {
                            if (v6 == 31) {
                                v_20 = 0;
                                result = rsp + 144;
                                ptr2 = (struct Struct_4_t *)a2;
                                sub_140083930(a2, a3, result);
                                if (result != 6) {
                                    return (__int64)ptr2;
                                } else {
                                    a1 = ptr2->field_10;
                                    if (a1 >= ptr2->field_8) {
                                        return (__int64)a1;
                                    } else {
                                        result = ptr2->field_0;
                                        result = *(__int64 *)((__int64)result + (__int64)a1);
                                        ++a1;
                                        ptr2->field_10 = a1;
                                        a1 = (size_t *)i;
                                        if (a1 <= 3) {
                                            a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                            *(__int64 *)(rsp + a1 + 144) = 2;
                                            *(__int64 *)(rsp + a1 + 152) = result;
                                            ++i;
                                        }
                                        result = (__int64 *)v2;
                                        result = (__int64 *)((__int64)(__int64)result & 1);
                                        result += 311;
                                        return (__int64)result;
                                    }
                                }
                                return (__int64)result;
                            } else {
                                if (v6 != 37) {
                                    a1 = (size_t *)ptr;
                                    return (__int64)a1;
                                } else {
                                    v_20 = 0;
                                    result = rsp + 144;
                                    ptr2 = (struct Struct_4_t *)a2;
                                    sub_140083930(a2, a3, result, i2);
                                    if (result != 6) {
                                        return (__int64)ptr2;
                                    } else {
                                        a1 = ptr2->field_10;
                                        if (a1 >= ptr2->field_8) {
                                            return (__int64)a1;
                                        } else {
                                            result = ptr2->field_0;
                                            result = *(__int64 *)((__int64)result + (__int64)a1);
                                            ++a1;
                                            ptr2->field_10 = a1;
                                            a1 = (size_t *)i;
                                            if (a1 <= 3) {
                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                *(__int64 *)(rsp + a1 + 144) = 2;
                                                *(__int64 *)(rsp + a1 + 152) = result;
                                                ++i;
                                            }
                                            result = (__int64 *)v2;
                                            result = (__int64 *)((__int64)(__int64)result & 1);
                                            result = (__int64 *)((__int64)(__int64)result | 308);
                                            return (__int64)result;
                                        }
                                    }
                                }
                                return (__int64)result;
                            }
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
    return (__int64)result;
}