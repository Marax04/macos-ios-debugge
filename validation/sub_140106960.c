// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 sub_1400F37A0();
__int64 sub_1400F27F6();
__int64 sub_1400F1570();
__int64 sub_1400F16D0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401101D0;
extern __int64 off_140110210;
extern __int64 off_1401086B0;

__int64 __fastcall sub_140106960(size_t *a1) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    int v_60;
    __int64 v2;
    struct Struct_1_t *result;
    __m128i xmm0;
    __int64 v3;
    struct Struct_2_t *ptr;
    __int64 v10;
    __int64 v11;
    __int64 i;
    __int64 *v5;
    __m128i xmm1;
    __int64 v13;
    __int64 v12;
    __int64 v8;
    __int64 *dst;
    __int64 v7;
    __m128i xmm2;

    v2 = a1[3];
    result = (struct Struct_1_t *)v2;
    ++result;
    if ((result == 0)) {
        result = &off_1401101D0;
        v_48 = (__int64)result;
        v_50 = 1;
        v_58 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_60, xmm0);
        v3 = &off_140110210;
        a1 = rsp + 72;
        sub_1400F37A0(a1, v3, i, v7);
    } else {
        ptr = (struct Struct_2_t *)a1;
        v3 = arg_8;
        v_20 = v3;
        v10 = v3 + 1;
        a1 = (size_t *)v10;
        a1 = (size_t *)((__int64)(__int64)a1 >> 3);
        v11 = v10;
        v11 &= -8;
        v11 -= (__int64)a1;
        i = v11;
        if (v3 < 8) v11 = v3;
        a1 = (size_t *)v11;
        a1 = (size_t *)((__int64)(__int64)a1 >> 1);
        if (result <= a1) {
            if (v10 == 0) {
                v11 = 0;
            } else {
                v5 = ptr->field_0;
                result = (struct Struct_1_t *)v10;
                result = (struct Struct_1_t *)((__int64)(__int64)result >> 4);
                a1 = (size_t *)v10;
                a1 = (size_t *)((__int64)(__int64)a1 & 15);
                result += 1;
                if (result != 1) {
                    v3 = 0x1FFFFFFFFFFFFFFE;
                    v3 &= (__int64)result;
                    a1 = 0;
                    xmm0 = _mm_load_si128((__m128i *)&off_1401086B0);
                    do {
                        xmm1 = _mm_setzero_si128();
                        xmm1 = _mm_cmpgt_epi8(xmm1, *(__int64 *)((__int64)v5 + (__int64)a1));
                        xmm1 = _mm_or_si128(xmm1, xmm0);
                        _mm_store_si128((__m128i *)((__int64)v5 + (__int64)a1), xmm1);
                        xmm1 = _mm_setzero_si128();
                        xmm1 = _mm_cmpgt_epi8(xmm1, *(__int64 *)((__int64)v5 + (__int64)a1 + 16));
                        xmm1 = _mm_or_si128(xmm1, xmm0);
                        _mm_store_si128((__m128i *)((__int64)v5 + (__int64)a1 + 16), xmm1);
                        a1 += 32;
                        v3 -= 2;
                    } while ((v3 != 0));
                    if (((__int64)result & 1) != 0) {
                        xmm0 = _mm_setzero_si128();
                        xmm0 = _mm_cmpgt_epi8(xmm0, *(__int64 *)((__int64)v5 + (__int64)a1));
                        xmm0 = _mm_or_si128(xmm0, _mm_load_si128((__m128i *)&off_1401086B0));
                        _mm_store_si128((__m128i *)((__int64)v5 + (__int64)a1), xmm0);
                    }
                } else {
                    a1 = 0;
                    return (__int64)a1;
                }
                v_28 = v2;
                v_30 = (__int64)ptr;
                a1 = (size_t *)v10;
                if (v10 < 16) {
                    a1 = 16;
                    i = v10;
                }
                a1 = (size_t *)((__int64)a1 + (__int64)v5);
                sub_1400F27F6(a1, v5, 16);
                v13 = v5 - 48;
                result = 1;
                a1 = 0;
                v12 = 0;
                v8 = v_20;
                do {
                    ptr = (struct Struct_2_t *)v12;
                    v12 = (__int64)result;
                    result = (struct Struct_1_t *)v12;
                    result += 0;
                } while (v12 < v10);
                if (v8 < 8) v11 = v8;
                ptr = (struct Struct_2_t *)v_30;
                v2 = v_28;
            }
            v11 -= v2;
            ptr->field_10 = v11;
            v5 = 0x8000000000000001;
        } else {
            ++i;
            if (i <= result) i = result;
            a1 = rsp + 72;
            sub_1400F1570(a1, 48, i);
            dst = (__int64 *)v_48;
            v5 = (__int64 *)v_50;
            if (dst != 0) {
                result = (struct Struct_1_t *)v_58;
                v_38 = (__int64)result;
                v_30 = (__int64)ptr;
                v10 = ptr->field_0;
                v_28 = v2;
                v7 = v_20;
                if (v2 != 0) {
                    xmm0 = _mm_load_si128((__m128i *)v10);
                    v12 = _mm_movemask_epi8(xmm0);
                    v12 = ~v12;
                    result = v10 - 48;
                    v_40 = (__int64)result;
                    ptr = 0;
                    v13 = v_28;
                    v2 = v10;
                    do {
                        v11 = __builtin_ctz(v12);
                        v11 += (__int64)ptr;
                        result = (struct Struct_1_t *)v11;
                        result = (struct Struct_1_t *)(-(__int64)result);
                        a1 = result + (__int64)(__int64)result*2;
                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                        a1 += v_40;
                        sub_1400F16D0(a1, v3, i, v7);
                        a1 = (size_t *)result;
                        a1 = (size_t *)((__int64)(__int64)a1 & (__int64)v5);
                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)a1));
                        v3 = _mm_movemask_epi8(xmm0);
                        if (v3 == 0) {
                            i = 16;
                            v7 = v_20;
                            a1 += i;
                            a1 = (size_t *)((__int64)(__int64)a1 & (__int64)v5);
                            xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst + (__int64)a1));
                            v3 = _mm_movemask_epi8(xmm0);
                            i += 16;
                            while (v3 == 0) {
                            }
                            v3 = __builtin_ctz(v3);
                            v3 += (__int64)a1;
                            v3 &= (__int64)v5;
                            if ((*(dst + v3) - 0) >= 0) {
                                xmm0 = _mm_load_si128((__m128i *)dst);
                                a1 = _mm_movemask_epi8(xmm0);
                                v3 = __builtin_ctz(a1);
                            }
                            a1 = v12 - 1;
                            a1 = (size_t *)((__int64)(__int64)a1 & v12);
                            --v13;
                            result = (struct Struct_1_t *)((__int64)(__int64)result >> 57);
                            i = v3 - 16;
                            i &= (__int64)v5;
                            *(dst + v3) = result;
                            *(dst + i + 16) = result;
                            v11 = ~v11;
                            result = v11 + v11*2;
                            result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                            v3 = ~v3;
                            v3 += v3*2;
                            v3 <<= 4;
                            xmm0 = _mm_loadu_si128((__m128i *)(v10 + result));
                            xmm1 = _mm_loadu_si128((__m128i *)(v10 + result + 16));
                            xmm2 = _mm_loadu_si128((__m128i *)(v10 + result + 32));
                            _mm_storeu_si128((__m128i *)(dst + v3 + 32), xmm2);
                            _mm_storeu_si128((__m128i *)(dst + v3 + 16), xmm1);
                            _mm_storeu_si128((__m128i *)(dst + v3), xmm0);
                            v12 = (__int64)a1;
                            a1 = (size_t *)v_38;
                            a1 -= v_28;
                            result = (struct Struct_1_t *)v_30;
                            *(__int64 *)result = (__int64)(dst);
                            result->field_8 = v5;
                            result->field_10 = a1;
                            v5 = 0x8000000000000001;
                            if (v7 != 0) {
                                result = v7 + v7*2;
                                result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                                result += 63;
                                result = (struct Struct_1_t *)((__int64)(__int64)result & -16);
                                v7 += (__int64)result;
                                if (v7 != -17) {
                                    v10 -= (__int64)result;
                                    off_140108030(a1, v3, i, v7);
                                    off_140108038(result, 0, v10);
                                }
                            }
                            result = (struct Struct_1_t *)v5;
                            return (__int64)result;
                        }
                        v7 = v_20;
                        return v7;
                    } while (v13 != 0);
                    return v7;
                }
                return v7;
            }
        }
        return v7;
    }
    return (__int64)result;
}