// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400BA3B0();
__int64 sub_1400F27F0();
__int64 sub_1400BA0E0();
__int64 sub_1400B91D0();

__int64 __fastcall sub_1400B97F0(size_t *a1, size_t *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    int v_100;
    int v_108;
    int v_20;
    __int64 v_28;
    int v_34;
    int v_38;
    __int64 v_40;
    __int64 v_48;
    __int64 v_50;
    __int64 v_58;
    int v_60;
    __int64 *v_0;
    struct Struct_1_t *ptr;
    __int64 v2;
    struct Struct_2_t *ptr2;
    __int64 *result;
    int v11;
    __int64 v10;
    __int64 v8;
    __int64 v9;
    __int64 i;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *src;
    __int64 v6;

    v_38 = (int)a4;
    ptr = (struct Struct_1_t *)a3;
    v2 = (__int64)a2;
    ptr2 = (struct Struct_2_t *)a1;
    if (a2 >= 33) {
        result = (__int64 *)v_108;
        v_40 = (__int64)result;
        v11 = v_100;
        result = ptr - 16;
        v_48 = (__int64)result;
        result = ptr - 8;
        v_50 = (__int64)result;
        do {
            result = ptr2 + 16;
            v_58 = (__int64)result;
            v10 = v2;
            --v11;
            while (!((v11 < 0))) {
                a4 = (size_t *)v10;
                a4 = (size_t *)((__int64)(__int64)a4 >> 3);
                result = (__int64 *)a4;
                result = (__int64 *)((__int64)(__int64)result << 5);
                result = (__int64 *)((__int64)result + (__int64)ptr2);
                a3 = (__int64)(__int64)a4 * 56;
                a3 = (size_t *)((__int64)a3 + (__int64)ptr2);
                v_34 = v11;
                if (v10 >= 64) {
                    sub_1400BA3B0(ptr2, result, a3, a4);
                    v8 = (__int64)result;
                    v8 -= (__int64)ptr2;
                    v9 = v8;
                    v9 >>= 3;
                    a1 = *result;
                    result = *result;
                    v_60 = (int)a1;
                    if (v_40 == 0) {
                        if (v_38 < v10) JUMPOUT(0x1400ba079);
                        result = ptr + v10*8;
                        v2 = 0;
                        a1 = (size_t *)ptr2;
                        a2 = (size_t *)v9;
                        do {
                            a3 = a2;
                            a3 -= 3;
                            a4 = 0;
                            if (a3 >= 0) a4 = a3;
                            a3 = ptr2 + (__int64)(__int64)a4*8;
                            a3 = ptr2 + (__int64)(__int64)a2*8;
                            if (a1 >= a3) {
                                if (a2 == v10) {
                                    a3 =  + v2*8;
                                    sub_1400F27F0(ptr2, ptr, a3, a4);
                                    a2 = (size_t *)v10;
                                    a2 -= v2;
                                    if ((a2 == 0)) {
                                        if (v2 == 0) {
                                            if (v_38 < v10) JUMPOUT(0x1400ba079);
                                            result = ptr + v10*8;
                                            i = 0;
                                            a1 = (size_t *)ptr2;
                                            do {
                                                a2 = (size_t *)v9;
                                                a2 -= 3;
                                                a3 = 0;
                                                if (a2 >= 0) a3 = a2;
                                                a2 = ptr2 + (__int64)(__int64)a3*8;
                                                a2 = ptr2 + v9*8;
                                                if (a1 >= a2) {
                                                    if (v9 == v10) {
                                                        a3 =  + i*8;
                                                        sub_1400F27F0(ptr2, ptr, a3, result);
                                                        v2 = v10;
                                                        v2 -= i;
                                                        if (!((v2 == 0))) {
                                                            if (v2 >= 4) {
                                                                result = (__int64 *)v2;
                                                                result = (__int64 *)((__int64)(__int64)result & -4);
                                                                a1 = (size_t *)result;
                                                                a1 = (size_t *)(-(__int64)a1);
                                                                a2 = ptr2 + i*8;
                                                                a2 += 16;
                                                                a3 = (size_t *)v_48;
                                                                a3 += v10*8;
                                                                a4 = 0;
                                                                v11 = v_34;
                                                                do {
                                                                    xmm0 = _mm_loadu_si128((__m128i *)(a3 + (__int64)(__int64)a4*8 - 16));
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + (__int64)(__int64)a4*8));
                                                                    xmm1 = _mm_shuffle_epi32(xmm1, 78);
                                                                    xmm0 = _mm_shuffle_epi32(xmm0, 78);
                                                                    _mm_storeu_si128((__m128i *)(a2 - 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)a2, xmm0);
                                                                    a4 -= 4;
                                                                    a2 += 32;
                                                                } while (a1 != a4);
                                                                if (v2 == result) {
                                                                    if (v10 < i) JUMPOUT(0x1400ba0bc);
                                                                    ptr2 += i*8;
                                                                    result = 0;
                                                                    v_40 = (__int64)result;
                                                                    if (v2 >= 2) {
                                                                        v9 = v2;
                                                                        v9 >>= 1;
                                                                        if (v2 <= 15) {
                                                                            if (v2 <= 7) {
                                                                                result = ptr2->field_0;
                                                                                *(__int64 *)ptr = (__int64)(result);
                                                                                result = ((__int64 *)ptr2)[v9];
                                                                                ((__int64 *)ptr)[v9] = (__int64)(result);
                                                                                a1 = 1;
                                                                                a2 = (size_t *)v2;
                                                                                a2 -= v9;
                                                                                if (a1 < v9) {
                                                                                    src = a1 + 1;
                                                                                    result =  + (__int64)(__int64)a1*8;
                                                                                    a3 = a1;
                                                                                    do {
                                                                                        a4 = ((__int64 *)ptr2)[(__int64)a3];
                                                                                        ((__int64 *)ptr)[(__int64)a3] = (__int64)(a4);
                                                                                        /* cmp *(ptr + (__int64)(__int64)a3*8 - 8) , a4 */;
                                                                                        a3 = (size_t *)src;
                                                                                        /* cmp a3 , v9 */;
                                                                                        src = (__int64 *)a3;
                                                                                        src += 0;
                                                                                        result += 8;
                                                                                    } while (a3 < v9);
                                                                                }
                                                                            } else {
                                                                                result = ptr2->field_8;
                                                                                a2 = 0;
                                                                                a1 = 0;
                                                                                a3 = ptr2->field_18;
                                                                                a2 = (result >= ptr2->field_0) ? 1 : 0;
                                                                                a1 = (result < ptr2->field_0) ? 1 : 0;
                                                                                result = 0;
                                                                                result = (a3 < ptr2->field_10) ? 1 : 0;
                                                                                a3 = result + 2;
                                                                                result = (__int64 *)((__int64)(__int64)result ^ 3);
                                                                                a4 = ((__int64 *)ptr2)[(__int64)a3];
                                                                                src = ((__int64 *)ptr2)[(__int64)a1];
                                                                                v6 = ((__int64 *)ptr2)[(__int64)result];
                                                                                v10 = (__int64)a3;
                                                                                if (a4 < src) v10 = a2;
                                                                                if (v6 < ((__int64 *)ptr2)[(__int64)a2]) v10 = result;
                                                                                if (v6 < ((__int64 *)ptr2)[(__int64)a2]) result = a2;
                                                                                if (v6 < ((__int64 *)ptr2)[(__int64)a2]) a2 = a3;
                                                                                a4 = ((__int64 *)ptr2)[v10];
                                                                                if (a4 < src) a2 = a1;
                                                                                if (0 /* unresolved: flags < */) a1 = a3;
                                                                                /* cmp a4 , ptr2[(__int64)a2] */;
                                                                                a1 = ((__int64 *)ptr2)[(__int64)a1];
                                                                                *(__int64 *)ptr = (__int64)(a1);
                                                                                a1 = a2;
                                                                                if (a1 < 0) a1 = v10;
                                                                                a1 = ((__int64 *)ptr2)[(__int64)a1];
                                                                                ptr->field_8 = a1;
                                                                                if (a1 >= 0) a2 = v10;
                                                                                a1 = ptr2 + v9*8;
                                                                                a3 = *(__int64 *)(ptr2 + v9*8 + 8);
                                                                                v6 = *(__int64 *)(ptr2 + v9*8 + 24);
                                                                                src = 0;
                                                                                a4 = 0;
                                                                                src = (a3 >= ((__int64 *)ptr2)[v9]) ? 1 : 0;
                                                                                a4 = (a3 < ((__int64 *)ptr2)[v9]) ? 1 : 0;
                                                                                a3 = 0;
                                                                                a3 = (v6 < *(__int64 *)(ptr2 + v9*8 + 16)) ? 1 : 0;
                                                                                v10 = a3 + 2;
                                                                                a3 = (size_t *)((__int64)(__int64)a3 ^ 3);
                                                                                v11 = a1[v10];
                                                                                i = a1[(__int64)a4];
                                                                                v6 = v10;
                                                                                if (v11 < i) v10 = src;
                                                                                v8 = a1[(__int64)a3];
                                                                                /* cmp v8 , a1[(__int64)src] */;
                                                                                a2 = ((__int64 *)ptr2)[(__int64)a2];
                                                                                ptr->field_10 = a2;
                                                                                result = ((__int64 *)ptr2)[(__int64)result];
                                                                                if (result < 0) v10 = a3;
                                                                                ptr->field_18 = result;
                                                                                if (result < 0) a3 = src;
                                                                                if (result < 0) src = v10;
                                                                                result = a1[v6];
                                                                                if (v11 < i) src = a4;
                                                                                if (v11 < i) a4 = v10;
                                                                                result = a1[(__int64)a4];
                                                                                ((__int64 *)ptr)[v9] = (__int64)(result);
                                                                                result = src;
                                                                                if (result < a1[(__int64)src]) result = v10;
                                                                                result = a1[(__int64)result];
                                                                                *(__int64 *)(ptr + v9*8 + 8) = (__int64)(result);
                                                                                if (result >= 0) src = v10;
                                                                                result = a1[(__int64)src];
                                                                                *(__int64 *)(ptr + v9*8 + 16) = (__int64)(result);
                                                                                result = a1[(__int64)a3];
                                                                                *(__int64 *)(ptr + v9*8 + 24) = (__int64)(result);
                                                                                a1 = 4;
                                                                                a2 = (size_t *)v2;
                                                                                a2 -= v9;
                                                                                if (a1 < v9) {
                                                                                    return (__int64)a2;
                                                                                } else {
                                                                                }
                                                                            }
                                                                        } else {
                                                                            a3 = ptr + v2*8;
                                                                            sub_1400BA0E0(ptr2, ptr, a3);
                                                                            a1 = ptr2 + v9*8;
                                                                            a2 = ptr + v9*8;
                                                                            a3 = ptr + v2*8;
                                                                            a3 += 64;
                                                                            sub_1400BA0E0(a1, a2, a3);
                                                                            a1 = 8;
                                                                            a2 = (size_t *)v2;
                                                                            a2 -= v9;
                                                                            if (a1 < v9) {
                                                                                return (__int64)a2;
                                                                            } else {
                                                                            }
                                                                        }
                                                                        result = ptr + v9*8;
                                                                        if (a1 < a2) {
                                                                            a3 = ptr2 + v9*8;
                                                                            v6 = a1 + 1;
                                                                            a4 =  + (__int64)(__int64)a1*8;
                                                                            do {
                                                                                src = a3[(__int64)a1];
                                                                                v_0[(__int64)a1] = src;
                                                                                /* cmp *(result + (__int64)(__int64)a1*8 - 8) , src */;
                                                                                a1 = (size_t *)v6;
                                                                                /* cmp a1 , a2 */;
                                                                                v6 = (__int64)a1;
                                                                                v6 += 0;
                                                                                a4 += 8;
                                                                            } while (a1 < a2);
                                                                        }
                                                                        a3 = ptr2 + v2*8;
                                                                        a3 -= 8;
                                                                        a2 = ptr + v2*8;
                                                                        a2 -= 8;
                                                                        a1 = result - 8;
                                                                        v9 = -v9;
                                                                        a4 = 0;
                                                                        do {
                                                                            src = (__int64 *)a2;
                                                                            a2 = *result;
                                                                            v6 = 0;
                                                                            v10 = 0;
                                                                            v6 = (a2 >= ptr->field_0) ? 1 : 0;
                                                                            a2 = (size_t *)ptr;
                                                                            if (v9 < 0) a2 = result;
                                                                            v10 = (v9 < 0) ? 1 : 0;
                                                                            a2 = *a2;
                                                                            v11 = *src;
                                                                            i = *a1;
                                                                            /* cmp v11 , i */;
                                                                            v8 = 0;
                                                                            v8 -= 1;
                                                                            *(__int64 *)ptr2 = (__int64)(a2);
                                                                            /* cmp v11 , i */;
                                                                            result += v10*8;
                                                                            ptr += v6*8;
                                                                            a2 = src + v8*8;
                                                                            if (ptr < 0) src = a1;
                                                                            v6 = 0;
                                                                            v6 = 0;
                                                                            ptr2 += 8;
                                                                            src = *src;
                                                                            a3[(__int64)a4] = src;
                                                                            a1 += v6*8;
                                                                            --a4;
                                                                        } while (v9 != a4);
                                                                        a1 += 8;
                                                                        if ((v2 & 1) != 0) {
                                                                            a3 = 0;
                                                                            a4 = 0;
                                                                            a3 = (ptr >= a1) ? 1 : 0;
                                                                            a4 = (ptr < a1) ? 1 : 0;
                                                                            src = result;
                                                                            if (ptr < a1) src = ptr;
                                                                            src = *src;
                                                                            *(__int64 *)ptr2 = (__int64)(src);
                                                                            ptr += (__int64)(__int64)a4*8;
                                                                            result += (__int64)(__int64)a3*8;
                                                                        }
                                                                        if (ptr != a1) JUMPOUT(0x1400ba0b7);
                                                                        a2 += 8;
                                                                        if (result != a2) JUMPOUT(0x1400ba0b7);
                                                                    }
                                                                    return (__int64)a2;
                                                                }
                                                                a1 = result + i;
                                                                result = (__int64 *)((__int64)(__int64)result << 3);
                                                                a2 = (size_t *)v_50;
                                                                a2 = (size_t *)((__int64)a2 - (__int64)result);
                                                                result = a2 + v10*8;
                                                                do {
                                                                    a2 = *result;
                                                                    ((__int64 *)ptr2)[(__int64)a1] = (__int64)(a2);
                                                                    ++a1;
                                                                    result -= 8;
                                                                } while (v10 != a1);
                                                                return (__int64)result;
                                                            }
                                                            result = 0;
                                                            v11 = v_34;
                                                            return v11;
                                                        }
                                                        return v11;
                                                    }
                                                    result -= 8;
                                                    a2 = *a1;
                                                    ((__int64 *)ptr)[i] = (__int64)(a2);
                                                    ++i;
                                                    a1 += 8;
                                                    v9 = v10;
                                                }
                                                a3 = *(__int64 *)(ptr2 + v8);
                                                do {
                                                    result -= 8;
                                                    if (a3 >= *a1) result = ptr;
                                                    src = *a1;
                                                    v_0[i] = src;
                                                    i += 1;
                                                    a1 += 8;
                                                } while (a1 < a2);
                                                return (__int64)a1;
                                            } while (true);
                                        }
                                        if (v10 < v2) JUMPOUT(0x1400ba07b);
                                        a1 = ptr2 + v2*8;
                                        result = rsp + 96;
                                        v_28 = (__int64)result;
                                        v_20 = v_34;
                                        a4 = (size_t *)v_38;
                                        sub_1400B97F0(a1, a2, ptr, a4);
                                        v10 = v2;
                                        return v10;
                                    }
                                    if (a2 >= 4) {
                                        result = (__int64 *)a2;
                                        result = (__int64 *)((__int64)(__int64)result & -4);
                                        a1 = (size_t *)result;
                                        a1 = (size_t *)(-(__int64)a1);
                                        a3 = (size_t *)v_58;
                                        a3 += v2*8;
                                        a4 = (size_t *)v_48;
                                        a4 += v10*8;
                                        src = 0;
                                        do {
                                            xmm0 = _mm_loadu_si128((__m128i *)(a4 + (__int64)(__int64)src*8 - 16));
                                            xmm1 = _mm_loadu_si128((__m128i *)(a4 + (__int64)(__int64)src*8));
                                            xmm1 = _mm_shuffle_epi32(xmm1, 78);
                                            xmm0 = _mm_shuffle_epi32(xmm0, 78);
                                            _mm_storeu_si128((__m128i *)(a3 - 16), xmm1);
                                            _mm_storeu_si128((__m128i *)a3, xmm0);
                                            src -= 4;
                                            a3 += 32;
                                        } while (a1 != src);
                                        if (a2 == result) {
                                            return (__int64)a3;
                                        }
                                        a1 = result + v2;
                                        result = (__int64 *)((__int64)(__int64)result << 3);
                                        a3 = (size_t *)v_50;
                                        a3 += v10*8;
                                        a3 = (size_t *)((__int64)a3 - (__int64)result);
                                        do {
                                            result = *a3;
                                            ((__int64 *)ptr2)[(__int64)a1] = (__int64)(result);
                                            ++a1;
                                            a3 -= 8;
                                        } while (v10 != a1);
                                        return (__int64)a3;
                                    }
                                    result = 0;
                                    return (__int64)result;
                                }
                                a2 = *a1;
                                *(result + v2*8 - 8) = a2;
                                result -= 8;
                                a1 += 8;
                                a2 = (size_t *)v10;
                            }
                            a4 = *(__int64 *)(ptr2 + v8);
                            do {
                                result -= 8;
                                src = result;
                                if (*a1 < a4) result = ptr;
                                v6 = *a1;
                                v_0[v2] = v6;
                                v2 += 0;
                                a1 += 8;
                            } while (a1 < a3);
                            return (__int64)a1;
                        } while (true);
                    }
                    a1 = (size_t *)v_40;
                    if (*a1 >= result) {
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                a1 = ptr2->field_0;
                a2 = *result;
                a4 = (a1 < a2) ? 1 : 0;
                src = *a3;
                a1 = (a1 < src) ? 1 : 0;
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
                a2 = (a2 < src) ? 1 : 0;
                a2 = (size_t *)((__int64)(__int64)a2 ^ (__int64)a4);
                if (a2 != 0) result = a3;
                if (a1 != 0) result = ptr2;
                return (__int64)a2;
            }
            v_20 = 1;
            a4 = (size_t *)v_38;
            sub_1400B91D0(ptr2, v10, ptr, a4);
            return (__int64)a4;
        } while (v2 >= 33);
        return (__int64)a4;
    }
    return (__int64)result;
}