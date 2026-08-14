__int64 sub_140011970();
extern __int64 off_140119AA8;
extern __int64 off_14010B3F0;
extern __int64 off_140117680;
extern __int64 off_14010B327;

__int64 __fastcall sub_140012F20(size_t *a1, size_t *a2) {
    int v_20;
    int v_28;
    char *dst;
    __int64 v7;
    __int64 result;
    __int64 v10;
    __int64 v9;
    __int64 v11;
    __int64 v5;
    __int64 v6;
    __int64 *src;
    __int64 v4;
    __int64 v3;
    __int64 v2;
    __m128i xmm0;

    v7 = (__int64)a2;
    result = a2[2];
    if ((result & 0x2000000) != 0) {
        a2 = 17;
        result = &off_140119AA8;
        v10 = (__int64)a1;
        do {
            v9 = (__int64)a2;
            a2 = a1;
            a2 = (size_t *)((__int64)(__int64)a2 & 15);
            v10 >>= 4;
            a2 = *(a2 + result);
            *(dst + v9 - 22) = a2;
            a2 = v9 - 1;
            a1 = (size_t *)v10;
        } while ((a1 > 15));
    } else {
        if ((result & 0x4000000) != 0) {
            a2 = 17;
            result = &off_14010B3F0;
            v11 = (__int64)a1;
            do {
                v9 = (__int64)a2;
                a2 = a1;
                a2 = (size_t *)((__int64)(__int64)a2 & 15);
                v11 >>= 4;
                a2 = *(a2 + result);
                *(dst + v9 - 22) = a2;
                a2 = v9 - 1;
                a1 = (size_t *)v11;
            } while ((a1 > 15));
            v9 -= 2;
            result = v9 + dst;
            result -= 20;
            a1 = 17;
            a1 = (size_t *)((__int64)a1 - (__int64)a2);
            v_28 = (int)a1;
            v_20 = result;
            v5 = &off_140117680;
        } else {
            v6 = 20;
            src = &off_14010B327;
            a2 = a1;
            if (a1 >= 1000) {
                v4 = 20;
                v3 = 0x346DC5D63886594B;
                v5 = (__int64)a1;
                do {
                    v6 = v4 - 4;
                    result = v5;
                    result *= v3; /* unsigned; high half in a2 */;
                    a2 = (size_t *)((__int64)(__int64)a2 >> 11);
                    result = (__int64)(__int64)a2 * 0x2710;
                    v2 = v5;
                    v2 -= result;
                    result = v2 * 0x147B;
                    result >>= 19;
                    v11 = result * 100;
                    v2 -= v11;
                    result = *(src + result*2);
                    xmm0 = _mm_cvtsi32_si128(result);
                    /* pinsrw $1, (%(__int64)src,%v2,2), %xmm0 */;
                    *(dst + v4 - 24) = _mm_cvtsi128_si64(xmm0);
                    v5 = (__int64)a2;
                } while ((v5 > 0x98967F));
            }
            if (a2 > 9) {
                result = (__int64)a2;
                result >>= 2;
                result *= 0x147B;
                result >>= 17;
                v5 = result * 100;
                a2 -= v5;
                a2 = *(src + (__int64)(__int64)a2*2);
                *(dst + v6 - 22) = a2;
                v6 -= 2;
                a2 = (size_t *)result;
            }
            if (a1 != 0) {
                if (a2 != 0) {
                    a2 = (size_t *)((__int64)(__int64)a2 & 15);
                    result = *(src + (__int64)(__int64)a2*2 + 1);
                    *(dst + v6 - 21) = result;
                    --v6;
                }
                result = 20;
                result -= v6;
                a1 = v6 + dst;
                a1 -= 20;
                v_28 = result;
                v_20 = (int)a1;
                v5 = 1;
                a1 = (size_t *)v7;
                a2 = 1;
                v6 = 0;
                return sub_140011970(v7, 1, v5, 2);
            }
            return v6;
        }
        return v6;
    }
    return result;
}