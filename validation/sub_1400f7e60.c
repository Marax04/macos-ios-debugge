__int64 sub_1400F8198();
__int64 sub_1400F37A0();
__int64 sub_14002EDF0();
__int64 sub_1400F2808();
__int64 sub_1400F834F();
extern __int64 off_1401101D0;
extern __int64 off_140110198;

__int64 __fastcall sub_1400F7E60(size_t *a1, __int64 a2, __int64 *a3, int a4) {
    __int64 rsp;
    int arg_8;
    int v_28;
    int v_30;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_70;
    int v_8;
    __int64 *src;
    __int64 v4;
    __int64 v7;
    __int64 result;
    __int64 *src2;
    __int64 *dst;
    __int64 i;
    __int64 v3;
    __m128i xmm0;
    __int64 *src3;
    __int64 v5;
    __int64 v6;

    v_30 = a4;
    a4 = a1[3];
    a2 += a4;
    if (!((a2 < 0))) {
        src = a3;
        v4 = arg_8;
        v7 = v4 + 1;
        result = v7;
        result >>= 3;
        src2 = (__int64 *)v7;
        src2 = (__int64 *)((__int64)(__int64)src2 & -8);
        src2 -= result;
        a1 = (size_t *)src2;
        if (v4 < 8) src2 = v4;
        result = (__int64)src2;
        result >>= 1;
        if (a2 <= result) {
            if (v7 == 0) JUMPOUT(0x1400f813f);
            v_28 = a4;
            dst = *a3;
            result = v7;
            result >>= 4;
            a1 = (size_t *)v7;
            a1 = (size_t *)((__int64)(__int64)a1 & 15);
            result += 1;
            v_70 = (int)a3;
            if (result != 1) JUMPOUT(0x1400f8147);
            a1 = 0;
            return sub_1400F8198();
        } else {
            ++a1;
            if (a1 <= a2) a1 = a2;
            if (a1 >= 15) {
                result = (__int64)a1;
                result >>= 61;
                if (!((result != 0))) {
                    a1 = (size_t *)((__int64)(__int64)a1 << 3);
                    a2 = 0x2492492492492493;
                    result = (__int64)a1;
                    result *= a2; /* unsigned; high half in a2 */;
                    a1 -= a2;
                    a1 = (size_t *)((__int64)(__int64)a1 >> 1);
                    a1 += a2;
                    a1 = (size_t *)((__int64)(__int64)a1 >> 2);
                    --a1;
                    a1 = 63 - __builtin_clzll(a1);
                    a1 = (size_t *)(~(__int64)a1);
                    i = -1;
                    i >>= (__int64)a1;
                    result = 0x1FFFFFFFFFFFFFFD;
                    if (i <= result) {
                        ++i;
                        v3 =  + i*8 + 15;
                        v3 &= -16;
                        src2 = i + 16;
                        v7 = v3;
                        v7 += (__int64)src2;
                        result = (v7 < 0) ? 1 : 0;
                        a1 = 0x7FFFFFFFFFFFFFF0;
                        a1 = (v7 > a1) ? 1 : 0;
                        a1 = (size_t *)((__int64)(__int64)a1 | result);
                        if (!((a1 == 0))) {
                            result = &off_1401101D0;
                            v_40 = result;
                            v_48 = 1;
                            v_50 = 8;
                            xmm0 = _mm_setzero_si128();
                            _mm_storeu_si128((__m128i *)&v_58, xmm0);
                            a2 = &off_140110198;
                            a1 = rsp + 64;
                            sub_1400F37A0(a1, a2, a1, a4);
                        }
                        v_28 = a4;
                        src3 = a3;
                        sub_14002EDF0(0, v7);
                        if (result == 0) JUMPOUT(0x1400f83b4);
                        dst = (__int64 *)result;
                        v7 = i - 1;
                        result = i;
                        result >>= 3;
                        i &= -8;
                        i -= result;
                        if (v7 < 8) i = v7;
                        dst += v3;
                        sub_1400F2808(dst, 255, src2);
                        a3 = (__int64 *)v_28;
                        if (a3 == 0) JUMPOUT(0x1400f834b);
                        src2 = *src3;
                        xmm0 = _mm_load_si128((__m128i *)src2);
                        a4 = _mm_movemask_epi8(xmm0);
                        a4 = ~a4;
                        result = 0;
                        a2 = (__int64)src2;
                        do {
                            v5 = __builtin_ctz(a4);
                            v5 += result;
                            v5 <<= 3;
                            a1 = (size_t *)src2;
                            a1 -= v5;
                            a1 = (size_t *)v_8;
                            if (a1 >= v_30) JUMPOUT(0x1400f83a3);
                            a1 = (size_t *)((__int64)(__int64)(__int64)a1 * 328);
                            a1 = *(__int64 *)((__int64)src + (__int64)a1 + 320);
                            v6 = (__int64)a1;
                            v6 &= v7;
                            xmm0 = _mm_loadu_si128((__m128i *)(dst + v6));
                            v3 = _mm_movemask_epi8(xmm0);
                            if (v3 == 0) JUMPOUT(0x1400f8106);
                            v3 = __builtin_ctz(v3);
                            v3 += v6;
                            v3 &= v7;
                            if ((*(dst + v3) - 0) >= 0) JUMPOUT(0x1400f812e);
                            v6 = a4 - 1;
                            v6 &= a4;
                            --a3;
                            a1 = (size_t *)((__int64)(__int64)a1 >> 57);
                            a4 = v3 - 16;
                            a4 &= v7;
                            *(dst + v3) = a1;
                            *(dst + a4 + 16) = a1;
                            v5 = -v5;
                            v3 <<= 3;
                            v3 = -v3;
                            a1 = *(src2 + v5 - 8);
                            *(dst + v3 - 8) = a1;
                            a4 = v6;
                        } while (a3 != 0);
                        return sub_1400F834F();
                    }
                }
            } else {
                result = (__int64)a1;
                result &= 8;
                result += 8;
                i = 4;
                if (a1 >= 4) i = result;
                return i;
            }
        }
    }
    return result;
}