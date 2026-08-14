// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    char _pad_18[8];
    __int64 field_28; // offset 40
};

__int64 sub_14007BF40();
__int64 sub_1400F9C00();
__int64 sub_1400F3360();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140108850;

__int64 __fastcall sub_14007C250(__int64 *a1, int a2, int *a3, __int64 *a4) {
    __int64 rsp;
    __int64 arg_8;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    __int64 v_78;
    __int64 v_80;
    int v_88;
    int v_90;
    int v_a0;
    int v_b0;
    int v_c0;
    __int64 v3;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *result;
    __m128i xmm6;
    __m128i xmm7;
    __int64 v6;
    int v8;
    __int64 v9;
    __int64 v7;
    __int64 v5;
    __m128i xmm2;
    __int64 v2;

    _mm_store_si128((__m128i *)&v_c0, xmm7);
    _mm_store_si128((__m128i *)&v_b0, xmm6);
    v_28 = (int)a4;
    v3 = (__int64)a3;
    ptr = (struct Struct_1_t *)a2;
    v_88 = (int)a1;
    a1 = rsp + 144;
    sub_14007BF40(a1, 16);
    xmm0 = _mm_loadu_si128((__m128i *)&v_90);
    xmm1 = _mm_loadu_si128((__m128i *)&v_a0);
    _mm_store_si128((__m128i *)&v_60, xmm1);
    _mm_store_si128((__m128i *)&v_50, xmm0);
    if (a3 != 0) {
        v_48 = v3;
        result = v3 + v3*2;
        result = (__int64 *)((__int64)(__int64)result << 4);
        result = (__int64 *)((__int64)result + (__int64)ptr);
        v_80 = (__int64)result;
        result = ptr + 48;
        xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
        xmm7 = _mm_load_si128((__m128i *)&off_140108850);
        v_78 = (__int64)ptr;
        do {
            v6 = ptr->field_18;
            v8 = ptr->field_28;
            ptr = (struct Struct_1_t *)result;
            a1 = rsp + 80;
            a2 = rsp + 112;
            sub_1400F9C00(a1, a2, a3, a4);
            a4 = (__int64 *)v6;
            result = 0xF1357AEA2E62A9C5;
            a4 = (__int64 *)((__int64)(__int64)(__int64)a4 * (__int64)result);
            a4 = __ROL8__(a4, 26);
            result = (__int64 *)v_50;
            a2 = v_58;
            a1 = a4;
            a1 = (__int64 *)((__int64)(__int64)a1 >> 57);
            xmm0 = _mm_cvtsi32_si128(a1);
            xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
            xmm0 = _mm_shufflelo_epi16(xmm0, 0);
            xmm0 = _mm_shuffle_epi32(xmm0, 68);
            v9 = result - 16;
            v7 = 0;
            v5 = 0;
            do {
                a4 = (__int64 *)((__int64)(__int64)a4 & a2);
                xmm1 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a4));
                xmm2 = xmm1;
                xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                v3 = _mm_movemask_epi8(xmm2);
                if (v7 == 1) {
                    xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
                    a3 = _mm_movemask_epi8(xmm1);
                    if (a3 != 0) {
                        a3 = *(result + v2);
                        if (a3 >= 0) {
                            xmm0 = _mm_load_si128((__m128i *)result);
                            a3 = _mm_movemask_epi8(xmm0);
                            v2 = __builtin_ctz(a3);
                            a3 = *(result + v2);
                        }
                        a3 = (int *)((__int64)(__int64)a3 & 1);
                        a4 = v2 - 16;
                        a4 = (__int64 *)((__int64)(__int64)a4 & a2);
                        *(result + v2) = a1;
                        *(__int64 *)((__int64)result + (__int64)a4 + 16) = a1;
                        xmm0 = _mm_load_si128((__m128i *)&v_60);
                        a1 = (__int64 *)a3;
                        xmm1 = _mm_cvtsi32_si128(a1);
                        /* shufps $228, %xmm7, %xmm1 */;
                        xmm0 = _mm_sub_epi64(xmm0, xmm1);
                        _mm_store_si128((__m128i *)&v_60, xmm0);
                        a3 = (int *)v2;
                        a3 = (int *)(-(__int64)a3);
                        v2 <<= 4;
                        v2 = -v2;
                        *(result + v2 - 16) = v6;
                        a3 = (int *)((__int64)(__int64)a3 << 4);
                        *(__int64 *)((__int64)result + (__int64)a3 - 8) = v8;
                        result = ptr + 48;
                        if (ptr == v_80) result = ptr;
                        a1 = (__int64 *)v_48;
                        ptr = (__int64)a1 + (__int64)a1;
                        result = 0xAAAAAAAAAAAAAAB;
                        if (ptr < result) JUMPOUT(0x14007c545);
                        sub_1400F3360(a1, a2, a3);
                        v_30 = 0;
                        v_38 = 4;
                        v_40 = 0;
                        result = (__int64 *)v_40;
                        a1 = (__int64 *)v_88;
                        a1[2] = result;
                        result = (__int64 *)v_30;
                        *a1 = result;
                        result = (__int64 *)v_38;
                        arg_8 = (__int64)result;
                        a1 = (__int64 *)v_58;
                        if (a1 != 0) {
                            result = a1;
                            result = (__int64 *)((__int64)(__int64)result << 4);
                            a1 = (__int64 *)((__int64)a1 + (__int64)result);
                            if (a1 != -33) {
                                v3 = v_50;
                                v3 -= (__int64)result;
                                v3 -= 16;
                                off_140108030(a1);
                                off_140108038(result, 0, v3);
                            }
                        }
                        xmm6 = _mm_load_si128((__m128i *)&v_b0);
                        xmm7 = _mm_load_si128((__m128i *)&v_c0);
                        return _mm_cvtsi128_si64(xmm7);
                    }
                    v7 = 1;
                    a4 += v5;
                    a4 += 16;
                    v5 += 16;
                }
                a3 = _mm_movemask_epi8(xmm1);
                if (a3 == 0) {
                    v7 = 0;
                    return v7;
                }
                v2 = __builtin_ctz(a3);
                v2 += (__int64)a4;
                v2 &= a2;
                return v2;
            } while (true);
        } while (ptr != v_80);
        return v2;
    }
    return (__int64)result;
}