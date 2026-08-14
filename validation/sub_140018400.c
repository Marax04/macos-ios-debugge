__int64 sub_140011970();
extern __int64 off_14010B327;

__int64 __fastcall sub_140018400(int *a1, size_t *a2) {
    int v_20;
    int v_28;
    char *dst;
    __int64 v6;
    __int64 v8;
    __int64 v5;
    __int64 *src;
    __int64 v10;
    __int64 v4;
    __int64 v3;
    __int64 result;
    __int64 v2;
    int v11;
    __m128i xmm0;
    __int64 v9;

    v6 = (__int64)a2;
    v8 = *a1;
    v5 = 20;
    src = &off_14010B327;
    v10 = v8;
    if (v8 >= 1000) {
        v4 = 20;
        v3 = 0x346DC5D63886594B;
        a1 = (int *)v8;
        do {
            v5 = v4 - 4;
            result = (__int64)a1;
            result *= v3; /* unsigned; high half in v10 */;
            v10 >>= 11;
            result = (__int64)(__int64)a2 * 0x2710;
            v2 = (__int64)a1;
            v2 -= result;
            result = v2 * 0x147B;
            result >>= 19;
            v11 = result * 100;
            v2 -= v11;
            result = *(src + result*2);
            xmm0 = _mm_cvtsi32_si128(result);
            /* pinsrw $1, (%(__int64)src,%v2,2), %xmm0 */;
            *(dst + v4 - 24) = _mm_cvtsi128_si64(xmm0);
            a1 = (int *)v10;
        } while ((a1 > 0x98967F));
    }
    if (v10 > 9) {
        result = (__int64)a2;
        result >>= 2;
        result *= 0x147B;
        result >>= 17;
        a1 = result * 100;
        a2 = (size_t *)((__int64)a2 - (__int64)a1);
        a1 = (int *)a2;
        a1 = *(src + (__int64)(__int64)a1*2);
        *(dst + v5 - 22) = a1;
        v5 -= 2;
        v10 = result;
    }
    if (v8 != 0) {
        if (v10 != 0) {
            a2 = (size_t *)((__int64)(__int64)a2 & 15);
            result = *(src + v10*2 + 1);
            *(dst + v5 - 21) = result;
            --v5;
        }
        result = 20;
        result -= v5;
        v9 = v5 + dst;
        v9 -= 20;
        v_28 = result;
        v_20 = v9;
        return sub_140011970(v6, 1, 1, 0);
    }
    return result;
}