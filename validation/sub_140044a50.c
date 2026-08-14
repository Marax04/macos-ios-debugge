__int64 sub_1400F35E0();
__int64 sub_1400F7270();
__int64 sub_1400F6B50();
__int64 sub_14002A420();
__int64 sub_1400F6820();
__int64 off_140108258();
extern __int64 off_140113B48;
extern __int64 off_14012D21A;
extern __int64 off_14012D268;
extern __int64 off_14012D21B;
extern __int64 off_140112478;

__int64 __fastcall sub_140044A50(__int64 *a1, __int64 *a2) {
    int v_20;
    int v_28;
    int v_30;
    int v_4;
    int v_40;
    int v_50;
    char *dst;
    __int64 *dst2;
    __int64 v9;
    __m128i xmm0;
    __m128i xmm1;
    __int64 result;
    __int64 v8;
    __int64 v7;
    __int64 v3;
    __int64 v10;
    __int64 v4;
    __int64 v2;
    __int64 v6;

    *dst = -2;
    dst2 = *a1;
    v9 = *dst2;
    *dst2 = 0;
    if (v9 == 0) {
        a1 = &off_140113B48;
        sub_1400F35E0(a1);
    } else {
        if (*(a2 + 4) != 0) {
            sub_1400F7270();
        } else {
            xmm0 = _mm_loadu_si128((__m128i *)v9);
            xmm1 = _mm_loadu_si128((__m128i *)(v9 + 16));
            _mm_store_si128((__m128i *)&v_20, xmm1);
            _mm_store_si128((__m128i *)&v_30, xmm0);
            a1 = 1;
            result = 0;
            /* cmpxchg %(__int64)a1, off_14012D21A */;
            if ((0 /* unresolved: flags != */)) {
                a1 = &off_14012D21A;
                sub_1400F6B50(a1);
                v8 = off_14012D268;
                v8 <<= 1;
                if (v8 == 0) {
                    v_4 = 0;
                    result = off_14012D21B;
                    v7 = v_20;
                    if (v7 != 0) {
                        v3 = v_28;
                        v10 = v7 * 56;
                        v10 += v3;
                        v4 = &off_140112478;
                        v2 = dst - 80;
                        do {
                            v_50 = v3;
                            v3 += 24;
                            sub_14002A420(v3, v2);
                            v3 += 32;
                        } while (v3 != v10);
                    }
                } else {
                    sub_1400F6820();
                    result ^= 1;
                    v_4 = result;
                    result = off_14012D21B;
                    v7 = v_20;
                    if (v7 != 0) {
                        return v7;
                    } else {
                    }
                }
                xmm0 = _mm_load_si128((__m128i *)&v_30);
                xmm1 = _mm_load_si128((__m128i *)&v_20);
                _mm_store_si128((__m128i *)&v_40, xmm1);
                _mm_store_si128((__m128i *)&v_50, xmm0);
                if (v_4 == 0) {
                    v7 = off_14012D268;
                    v7 <<= 1;
                    if (v7 != 0) {
                        sub_1400F6820();
                        if (result == 0) {
                            off_14012D21B = 1;
                        }
                    }
                }
                result = 0;
                result = _InterlockedExchange64(&off_14012D21A, result);
                if (result == 2) {
                    a1 = &off_14012D21A;
                    off_140108258(a1);
                }
                xmm0 = _mm_load_si128((__m128i *)&v_50);
                xmm1 = _mm_load_si128((__m128i *)&v_40);
                _mm_storeu_si128((__m128i *)(v9 + 16), xmm1);
                _mm_storeu_si128((__m128i *)v9, xmm0);
                return _mm_cvtsi128_si64(xmm1);
            } else {
                v6 = off_14012D268;
                v6 <<= 1;
                if (v6 != 0) {
                    return v6;
                } else {
                    return v6;
                }
                return v6;
            }
            return v6;
        }
        return v6;
    }
    return result;
}