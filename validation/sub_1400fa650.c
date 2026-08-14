// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 sub_1400F37A0();
__int64 sub_1400F27F6();
__int64 sub_14007BF40();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401101D0;
extern __int64 off_140110210;
extern __int64 off_1401086B0;

__int64 __fastcall sub_1400FA650(size_t *a1, int *a2, int *a3, __int64 a4) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    __int64 v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    __int64 *v4;
    __int64 result;
    __m128i xmm0;
    struct Struct_1_t *ptr;
    __int64 v9;
    __int64 v7;
    __int64 v10;
    __m128i xmm1;
    __int64 v5;
    __int64 v6;
    __int64 v8;
    __int64 v11;
    __int64 v2;

    v4 = a1[3];
    result = (__int64)v4;
    ++result;
    if ((result == 0)) {
        result = &off_1401101D0;
        v_38 = result;
        v_40 = 1;
        v_48 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_50, xmm0);
        a2 = &off_140110210;
        a1 = rsp + 56;
        sub_1400F37A0(a1, a2, v5, a3);
    } else {
        ptr = (struct Struct_1_t *)a1;
        v9 = arg_8;
        v7 = v9 + 1;
        a1 = (size_t *)v7;
        a1 = (size_t *)((__int64)(__int64)a1 >> 3);
        v10 = v7;
        v10 &= -8;
        v10 -= (__int64)a1;
        a3 = (int *)v10;
        if (v9 < 8) v10 = v9;
        a1 = (size_t *)v10;
        a1 = (size_t *)((__int64)(__int64)a1 >> 1);
        if (result <= a1) {
            if (v7 == 0) {
                v10 = 0;
            } else {
                v_20 = (__int64)v4;
                v_28 = (__int64)ptr;
                v4 = ptr->field_0;
                result = v7;
                result >>= 4;
                a1 = (size_t *)v7;
                a1 = (size_t *)((__int64)(__int64)a1 & 15);
                result += 1;
                if (result != 1) {
                    a2 = 0x1FFFFFFFFFFFFFFE;
                    a2 = (int *)((__int64)(__int64)a2 & result);
                    a1 = 0;
                    xmm0 = _mm_load_si128((__m128i *)&off_1401086B0);
                    do {
                        xmm1 = _mm_setzero_si128();
                        xmm1 = _mm_cmpgt_epi8(xmm1, *(__int64 *)((__int64)v4 + (__int64)a1));
                        xmm1 = _mm_or_si128(xmm1, xmm0);
                        _mm_store_si128((__m128i *)((__int64)v4 + (__int64)a1), xmm1);
                        xmm1 = _mm_setzero_si128();
                        xmm1 = _mm_cmpgt_epi8(xmm1, *(__int64 *)((__int64)v4 + (__int64)a1 + 16));
                        xmm1 = _mm_or_si128(xmm1, xmm0);
                        _mm_store_si128((__m128i *)((__int64)v4 + (__int64)a1 + 16), xmm1);
                        a1 += 32;
                        a2 -= 2;
                    } while ((a2 != 0));
                    if ((result & 1) != 0) {
                        xmm0 = _mm_setzero_si128();
                        xmm0 = _mm_cmpgt_epi8(xmm0, *(__int64 *)((__int64)v4 + (__int64)a1));
                        xmm0 = _mm_or_si128(xmm0, _mm_load_si128((__m128i *)&off_1401086B0));
                        _mm_store_si128((__m128i *)((__int64)v4 + (__int64)a1), xmm0);
                    }
                } else {
                    a1 = 0;
                    return (__int64)a1;
                }
                a1 = (size_t *)v7;
                if (v7 < 16) {
                    a1 = 16;
                    a3 = (int *)v7;
                }
                a1 = (size_t *)((__int64)a1 + (__int64)v4);
                sub_1400F27F6(a1, v4, 16);
                result = v4 - 16;
                v5 = 1;
                a1 = 0;
                a3 = 0;
                do {
                    v5 = (__int64)a3;
                    v5 += 0;
                } while (a3 < v7);
                if (v9 < 8) v10 = v9;
                ptr = (struct Struct_1_t *)v_28;
                v4 = (__int64 *)v_20;
            }
            v10 -= (__int64)v4;
            ptr->field_10 = v10;
            result = 0x8000000000000001;
        } else {
            ++a3;
            if (a3 <= result) a3 = result;
            a1 = rsp + 56;
            sub_14007BF40(a1, 16, a3);
            a1 = (size_t *)v_38;
            result = v_40;
            if (a1 != 0) {
                a2 = (int *)v_48;
                v_30 = (int)a2;
                v_28 = (__int64)ptr;
                a2 = (int *)v4;
                v4 = ptr->field_0;
                v_20 = (__int64)a2;
                if (a2 != 0) {
                    xmm0 = _mm_load_si128((__m128i *)v4);
                    v7 = _mm_movemask_epi8(xmm0);
                    v7 = ~v7;
                    a3 = v4 - 16;
                    a4 = 0;
                    v5 = 0xF1357AEA2E62A9C5;
                    v6 = v_20;
                    v10 = (__int64)v4;
                    do {
                        v8 = __builtin_ctz(v7);
                        v8 += a4;
                        a2 = (int *)v8;
                        a2 = (int *)((__int64)(__int64)a2 << 4);
                        ptr = (struct Struct_1_t *)a3;
                        ptr = (struct Struct_1_t *)((__int64)ptr - (__int64)a2);
                        v11 = ptr->field_0;
                        v11 *= v5;
                        v11 = __ROL8__(v11, 26);
                        a2 = (int *)v11;
                        a2 = (int *)((__int64)(__int64)a2 & result);
                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a2));
                        ptr = _mm_movemask_epi8(xmm0);
                        if (ptr == 0) {
                            v2 = 16;
                            a2 += v2;
                            a2 = (int *)((__int64)(__int64)a2 & result);
                            xmm0 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a2));
                            ptr = _mm_movemask_epi8(xmm0);
                            v2 += 16;
                            while (ptr == 0) {
                            }
                        }
                        v2 = __builtin_ctz(ptr);
                        v2 += (__int64)a2;
                        v2 &= result;
                        if ((*(a1 + v2) - 0) >= 0) {
                            xmm0 = _mm_load_si128((__m128i *)a1);
                            a2 = _mm_movemask_epi8(xmm0);
                            v2 = __builtin_ctz(a2);
                        }
                        a2 = v7 - 1;
                        a2 = (int *)((__int64)(__int64)a2 & v7);
                        --v6;
                        v11 >>= 57;
                        ptr = v2 - 16;
                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & result);
                        *(a1 + v2) = v11;
                        *(__int64 *)((__int64)a1 + (__int64)ptr + 16) = v11;
                        v8 = ~v8;
                        v8 <<= 4;
                        v2 = ~v2;
                        v2 <<= 4;
                        xmm0 = _mm_loadu_si128((__m128i *)(v4 + v8));
                        _mm_storeu_si128((__m128i *)(a1 + v2), xmm0);
                        v7 = (__int64)a2;
                    } while (v6 != 0);
                }
                a3 = (int *)v_30;
                a3 -= v_20;
                a2 = (int *)v_28;
                *a2 = a1;
                arg_8 = result;
                a2[2] = a3;
                result = 0x8000000000000001;
                if (v9 != 0) {
                    a1 = (size_t *)v9;
                    a1 = (size_t *)((__int64)(__int64)a1 << 4);
                    a1 += 31;
                    a1 = (size_t *)((__int64)(__int64)a1 & -16);
                    v9 += (__int64)a1;
                    if (v9 != -17) {
                        v4 = (__int64 *)((__int64)v4 - (__int64)a1);
                        ptr = (struct Struct_1_t *)result;
                        off_140108030(a1, a2, a3, a4);
                        off_140108038(result, 0, v4);
                        result = (__int64)ptr;
                    }
                }
            }
        }
        return result;
    }
    return result;
}