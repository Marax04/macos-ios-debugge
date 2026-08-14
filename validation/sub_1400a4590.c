__int64 sub_140097200();
__int64 sub_1400F27F0();
__int64 sub_140096E90();
__int64 sub_1400A3FB0();

__int64 __fastcall sub_1400A4590(size_t *a1, size_t *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    int arg_10;
    int arg_20;
    int arg_30;
    int v_110;
    int v_118;
    __int64 v_20;
    __int64 v_28;
    __int64 v_34;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    __int64 v_58;
    int v_90;
    __int64 *src;
    __int64 v2;
    __int64 *src2;
    __int64 *src3;
    __int64 *result;
    __int64 *src4;
    __int64 v9;
    __m128i xmm0;
    __int64 *src5;
    __int64 *i;
    __int64 *v5;
    __int64 *src6;

    src = (__int64 *)a3;
    v2 = (__int64)a2;
    src2 = (__int64 *)a1;
    if (a2 >= 33) {
        src3 = (__int64 *)a4;
        result = (__int64 *)v_118;
        v_38 = (__int64)result;
        src4 = (__int64 *)v_110;
        result = src - 16;
        v_48 = (__int64)result;
        v_50 = (int)a4;
        do {
            v9 = v2;
            --src4;
            while (!((src4 < 0))) {
                v_34 = (__int64)src4;
                a4 = (size_t *)v9;
                a4 = (size_t *)((__int64)(__int64)a4 >> 3);
                src4 = (__int64 *)a4;
                src4 = (__int64 *)((__int64)(__int64)src4 << 6);
                src4 = (__int64 *)((__int64)src4 + (__int64)src2);
                a3 = (__int64)(__int64)a4 * 112;
                a3 = (size_t *)((__int64)a3 + (__int64)src2);
                if (v9 >= 64) {
                    sub_140097200(src2, src4, a3, a4);
                    src4 = result;
                    result = src4;
                    result = (__int64 *)((__int64)result - (__int64)src2);
                    result = (__int64 *)((__int64)(__int64)result >> 4);
                    v_58 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)src4);
                    _mm_store_si128((__m128i *)&v_90, xmm0);
                    if (v_38 == 0) {
                        if (src3 < v9) JUMPOUT(0x1400a4fe1);
                        v_40 = v9;
                        src3 = (__int64 *)v9;
                        src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                        src5 = (__int64)src + (__int64)src3;
                        v2 = 0;
                        result = src2;
                        a1 = (size_t *)src5;
                        a2 = (size_t *)v_58;
                        do {
                            a4 = a2;
                            a4 -= 3;
                            a3 = 0;
                            if (a4 >= 0) a3 = a4;
                            a3 = (size_t *)((__int64)(__int64)a3 << 4);
                            v9 = (__int64)src2;
                            a3 = (size_t *)((__int64)a3 + (__int64)src2);
                            a3 = a2;
                            a3 = (size_t *)((__int64)(__int64)a3 << 4);
                            src2 = (__int64 *)v9;
                            a3 += v9;
                            if (result >= a3) {
                                v9 = v_40;
                                if (a2 == v9) {
                                    i = (__int64 *)v2;
                                    i = (__int64 *)((__int64)(__int64)i << 4);
                                    sub_1400F27F0(src2, src, i, a1);
                                    a2 = (size_t *)v9;
                                    a2 -= v2;
                                    if ((a2 == 0)) {
                                        src3 = (__int64 *)v_50;
                                        if (v2 == 0) {
                                            if (src3 < v9) JUMPOUT(0x1400a4fe1);
                                            src3 = (__int64 *)v9;
                                            src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                                            result = src2;
                                            src2 = (__int64)src + (__int64)src3;
                                            i = 0;
                                            src5 = result;
                                            a1 = (size_t *)src2;
                                            v2 = v_58;
                                            do {
                                                a3 = (size_t *)v2;
                                                a3 -= 3;
                                                a2 = 0;
                                                if (a3 >= 0) a2 = a3;
                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                a2 = (size_t *)((__int64)a2 + (__int64)src5);
                                                a2 = (size_t *)v2;
                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                a2 = (size_t *)((__int64)a2 + (__int64)src5);
                                                if (result >= a2) {
                                                    if (v2 == v9) {
                                                        src4 = i;
                                                        src4 = (__int64 *)((__int64)(__int64)src4 << 4);
                                                        sub_1400F27F0(src5, src, src4, a4);
                                                        v2 = v9;
                                                        v2 -= (__int64)i;
                                                        if (!((v2 == 0))) {
                                                            src5 = (__int64 *)((__int64)src5 + (__int64)src4);
                                                            result = i + 1;
                                                            if (v9 != result) {
                                                                a1 = (size_t *)v2;
                                                                a1 = (size_t *)((__int64)(__int64)a1 & -2);
                                                                v5 = src5;
                                                                a2 = src5 + 16;
                                                                src3 += v_48;
                                                                a3 = 0;
                                                                src4 = (__int64 *)v_34;
                                                                a4 = 0xFFFFFFFFFFFFFFE;
                                                                do {
                                                                    xmm0 = _mm_loadu_si128((__m128i *)src3);
                                                                    _mm_storeu_si128((__m128i *)(a2 - 16), xmm0);
                                                                    result = a3 + 2;
                                                                    a3 = (size_t *)((__int64)(__int64)a3 ^ (__int64)a4);
                                                                    a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)((__int64)src2 + (__int64)a3));
                                                                    _mm_storeu_si128((__m128i *)a2, xmm0);
                                                                    a2 += 32;
                                                                    src3 -= 32;
                                                                    a3 = (size_t *)result;
                                                                } while (a1 != result);
                                                                if ((v2 & 1) == 0) {
                                                                    src3 = (__int64 *)v_50;
                                                                    if (v9 < i) JUMPOUT(0x1400a501f);
                                                                    result = 0;
                                                                    v_38 = (__int64)result;
                                                                    src2 = v5;
                                                                    if (v2 >= 2) {
                                                                        v9 = v2;
                                                                        v9 >>= 1;
                                                                        src5 = src2;
                                                                        if (v2 <= 15) {
                                                                            if (v2 <= 7) {
                                                                                xmm0 = _mm_loadu_si128((__m128i *)&*src2);
                                                                                _mm_storeu_si128((__m128i *)src, xmm0);
                                                                                result = (__int64 *)v9;
                                                                                result = (__int64 *)((__int64)(__int64)result << 4);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)((__int64)src2 + (__int64)result));
                                                                                _mm_storeu_si128((__m128i *)((__int64)src + (__int64)result), xmm0);
                                                                                a1 = 1;
                                                                                a2 = (size_t *)v2;
                                                                                a2 -= v9;
                                                                                if (a1 < v9) {
                                                                                    a4 = a1 + 1;
                                                                                    result = (__int64 *)a1;
                                                                                    result = (__int64 *)((__int64)(__int64)result << 4);
                                                                                    a3 = a1;
                                                                                    do {
                                                                                        v5 = (__int64 *)a3;
                                                                                        a3 = a4;
                                                                                        v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)((__int64)src2 + (__int64)v5));
                                                                                        _mm_storeu_si128((__m128i *)((__int64)src + (__int64)v5), xmm0);
                                                                                        a4 = *(__int64 *)((__int64)src + (__int64)v5);
                                                                                        /* cmp a3 , v9 */;
                                                                                        a4 = a3;
                                                                                        a4 += 0;
                                                                                        result += 16;
                                                                                    } while (a3 < v9);
                                                                                }
                                                                            } else {
                                                                                result = (__int64 *)arg_10;
                                                                                a1 = (size_t *)arg_30;
                                                                                v5 = 0;
                                                                                a3 = 0;
                                                                                v5 = (result >= *src2) ? 1 : 0;
                                                                                a3 = (result < *src2) ? 1 : 0;
                                                                                a2 = 0;
                                                                                a2 = (a1 < arg_20) ? 1 : 0;
                                                                                a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                                a1 = (__int64)a3 + (__int64)src2;
                                                                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                result = (__int64)v5 + (__int64)src2;
                                                                                src6 = (__int64 *)a2;
                                                                                src6 = (__int64 *)((__int64)(__int64)src6 << 4);
                                                                                a4 = (__int64)src6 + (__int64)src2;
                                                                                a4 += 32;
                                                                                a2 = (size_t *)((__int64)(__int64)a2 ^ 3);
                                                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                src6 = *(__int64 *)((__int64)src2 + (__int64)src6 + 32);
                                                                                src2 = *(__int64 *)((__int64)src5 + (__int64)a2);
                                                                                v5 = *(__int64 *)((__int64)src5 + (__int64)v5);
                                                                                src3 = result;
                                                                                if (src2 < v5) src3 = a4;
                                                                                if (src6 < *(__int64 *)((__int64)src5 + (__int64)a3)) src3 = a1;
                                                                                if (src6 < *(__int64 *)((__int64)src5 + (__int64)a3)) a1 = a4;
                                                                                a2 = (__int64)src5 + (__int64)a2;
                                                                                if (a2 < 0) a4 = result;
                                                                                if (src2 >= v5) result = a2;
                                                                                if (src2 < v5) a4 = a2;
                                                                                a2 = *a4;
                                                                                a2 = (size_t *)src3;
                                                                                if (a2 < *src3) a2 = a4;
                                                                                if (0 /* unresolved: flags < */) a4 = src3;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a1);
                                                                                _mm_storeu_si128((__m128i *)src, xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a2);
                                                                                _mm_storeu_si128((__m128i *)(src + 16), xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a4);
                                                                                a1 = (size_t *)v9;
                                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                a2 = *(__int64 *)((__int64)src5 + (__int64)a1 + 16);
                                                                                a4 = *(__int64 *)((__int64)src5 + (__int64)a1 + 48);
                                                                                src3 = 0;
                                                                                v5 = 0;
                                                                                src3 = (a2 >= *(__int64 *)((__int64)src5 + (__int64)a1)) ? 1 : 0;
                                                                                v5 = (a2 < *(__int64 *)((__int64)src5 + (__int64)a1)) ? 1 : 0;
                                                                                a3 = 0;
                                                                                src6 = (__int64)src5 + (__int64)a1;
                                                                                a3 = (a4 < *(__int64 *)((__int64)src5 + (__int64)a1 + 32)) ? 1 : 0;
                                                                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                                                                                a2 = (__int64)src6 + (__int64)src3;
                                                                                src4 = (__int64 *)a3;
                                                                                src4 = (__int64 *)((__int64)(__int64)src4 << 4);
                                                                                a4 = (__int64)src4 + (__int64)src6;
                                                                                a4 += 32;
                                                                                a3 = (size_t *)((__int64)(__int64)a3 ^ 3);
                                                                                a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                                src2 = *(__int64 *)((__int64)a3 + (__int64)src6);
                                                                                src3 = *(__int64 *)((__int64)src3 + (__int64)src6);
                                                                                i = (__int64 *)a2;
                                                                                if (src2 < src3) i = a4;
                                                                                src4 = *(__int64 *)((__int64)src6 + (__int64)src4 + 32);
                                                                                /* cmp src4 , *(__int64 *)((__int64)v5 + (__int64)src6) */;
                                                                                v5 = (__int64)src6 + (__int64)v5;
                                                                                if (v5 < 0) i = v5;
                                                                                if (v5 < 0) v5 = a4;
                                                                                a3 = (__int64)src6 + (__int64)a3;
                                                                                if (a3 < 0) a4 = a2;
                                                                                src2 = src5;
                                                                                if (src2 >= src3) a2 = a3;
                                                                                if (0 /* unresolved: flags < */) a4 = a3;
                                                                                _mm_storeu_si128((__m128i *)(src + 32), xmm0);
                                                                                a3 = *a4;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                                result = i;
                                                                                if (a3 < *i) i = a4;
                                                                                _mm_storeu_si128((__m128i *)(src + 48), xmm0);
                                                                                if (0 /* unresolved: flags < */) a4 = i;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)v5);
                                                                                _mm_storeu_si128((__m128i *)((__int64)src + (__int64)a1), xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)i);
                                                                                _mm_storeu_si128((__m128i *)((__int64)src + (__int64)a1 + 16), xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a4);
                                                                                _mm_storeu_si128((__m128i *)((__int64)src + (__int64)a1 + 32), xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a2);
                                                                                _mm_storeu_si128((__m128i *)((__int64)src + (__int64)a1 + 48), xmm0);
                                                                                a1 = 4;
                                                                                a2 = (size_t *)v2;
                                                                                a2 -= v9;
                                                                                if (a1 < v9) {
                                                                                    return (__int64)a2;
                                                                                } else {
                                                                                }
                                                                            }
                                                                        } else {
                                                                            src3 = (__int64 *)v2;
                                                                            src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                                                                            a3 = (__int64)src + (__int64)src3;
                                                                            sub_140096E90(src2, src, a3);
                                                                            a2 = (size_t *)v9;
                                                                            a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                            a1 = (__int64)a2 + (__int64)src2;
                                                                            a2 = (size_t *)((__int64)a2 + (__int64)src);
                                                                            a3 = (__int64)src + (__int64)src3;
                                                                            a3 += 128;
                                                                            sub_140096E90(a1, a2, a3);
                                                                            a1 = 8;
                                                                            a2 = (size_t *)v2;
                                                                            a2 -= v9;
                                                                            if (a1 < v9) {
                                                                                return (__int64)a2;
                                                                            } else {
                                                                            }
                                                                        }
                                                                        a3 = (size_t *)v9;
                                                                        a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                        result = (__int64)src + (__int64)a3;
                                                                        if (a1 < a2) {
                                                                            a3 = (size_t *)((__int64)a3 + (__int64)src2);
                                                                            v5 = a1 + 1;
                                                                            a4 = a1;
                                                                            a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                                            do {
                                                                                src6 = (__int64 *)a1;
                                                                                a1 = (size_t *)v5;
                                                                                src6 = (__int64 *)((__int64)(__int64)src6 << 4);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)a3 + (__int64)src6));
                                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src6), xmm0);
                                                                                v5 = *(__int64 *)((__int64)result + (__int64)src6);
                                                                                /* cmp a1 , a2 */;
                                                                                v5 = (__int64 *)a1;
                                                                                v5 += 0;
                                                                                a4 += 16;
                                                                            } while (a1 < a2);
                                                                        }
                                                                        a1 = (size_t *)v2;
                                                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                        a3 = (__int64)a1 + (__int64)src2;
                                                                        a3 -= 16;
                                                                        a1 = (size_t *)((__int64)a1 + (__int64)src);
                                                                        a1 -= 16;
                                                                        a2 = result - 16;
                                                                        do {
                                                                            src5 = src2;
                                                                            v_40 = v9;
                                                                            src2 = *result;
                                                                            a4 = 0;
                                                                            v5 = 0;
                                                                            src6 = result;
                                                                            src2 = (src2 >= *src) ? 1 : 0;
                                                                            src4 = (0 /* unresolved: flags < */) ? 1 : 0;
                                                                            xmm0 = _mm_loadu_si128((__m128i *)src6);
                                                                            _mm_storeu_si128((__m128i *)src5, xmm0);
                                                                            i = *a1;
                                                                            v9 = *a2;
                                                                            /* cmp i , v9 */;
                                                                            src6 = 0;
                                                                            src6 -= 1;
                                                                            src3 = (__int64 *)a2;
                                                                            if (i < v9) {
                                                                                v5 = src4;
                                                                                v9 = 0;
                                                                                v9 = 0;
                                                                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                result = (__int64 *)((__int64)result + (__int64)v5);
                                                                                a4 = (size_t *)src2;
                                                                                a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                                                src = (__int64 *)((__int64)src + (__int64)a4);
                                                                                src2 = src5;
                                                                                src2 += 16;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)src3);
                                                                                _mm_storeu_si128((__m128i *)a3, xmm0);
                                                                                src6 = (__int64 *)((__int64)(__int64)src6 << 4);
                                                                                a1 = (size_t *)((__int64)a1 + (__int64)src6);
                                                                                v9 <<= 4;
                                                                                a2 += v9;
                                                                                a3 -= 16;
                                                                                v9 = v_40;
                                                                                --v9;
                                                                                a2 += 16;
                                                                                if ((v2 & 1) != 0) {
                                                                                    a3 = 0;
                                                                                    a4 = 0;
                                                                                    a3 = (src >= a2) ? 1 : 0;
                                                                                    a4 = (src < a2) ? 1 : 0;
                                                                                    v5 = result;
                                                                                    if (src < a2) v5 = src;
                                                                                    xmm0 = _mm_loadu_si128((__m128i *)v5);
                                                                                    _mm_storeu_si128((__m128i *)&*src2, xmm0);
                                                                                    a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                                                    src = (__int64 *)((__int64)src + (__int64)a4);
                                                                                    a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                                    result = (__int64 *)((__int64)result + (__int64)a3);
                                                                                }
                                                                                if (src != a2) JUMPOUT(0x1400a501a);
                                                                                a1 += 16;
                                                                                if (result != a1) JUMPOUT(0x1400a501a);
                                                                                return (__int64)a1;
                                                                            }
                                                                            src3 = (__int64 *)a1;
                                                                            return (__int64)src3;
                                                                        } while (!((v9 == 0)));
                                                                        return (__int64)src3;
                                                                    }
                                                                    return (__int64)src3;
                                                                }
                                                                a1 = (size_t *)result;
                                                                a1 = (size_t *)(~(__int64)a1);
                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                result = (__int64 *)((__int64)(__int64)result << 4);
                                                                xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)((__int64)src2 + (__int64)a1));
                                                                _mm_storeu_si128((__m128i *)((__int64)v5 + (__int64)result), xmm0);
                                                                return _mm_cvtsi128_si64(xmm0);
                                                            }
                                                            v5 = src5;
                                                            result = 0;
                                                            src4 = (__int64 *)v_34;
                                                            return (__int64)src4;
                                                        }
                                                        return (__int64)src4;
                                                    }
                                                    a1 -= 16;
                                                    a2 = (size_t *)i;
                                                    a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                                    _mm_storeu_si128((__m128i *)((__int64)src + (__int64)a2), xmm0);
                                                    ++i;
                                                    result += 16;
                                                    v2 = v9;
                                                }
                                                do {
                                                    a3 = *src4;
                                                    a1 -= 16;
                                                    a4 = (size_t *)i;
                                                    a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                    a3 = a1;
                                                    if (a3 >= *result) a1 = src;
                                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                                    _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a4), xmm0);
                                                    i += 1;
                                                    result += 16;
                                                } while (result < a2);
                                                return (__int64)result;
                                            } while (true);
                                        }
                                        if (v9 < v2) JUMPOUT(0x1400a4fe3);
                                        i = (__int64 *)((__int64)i + (__int64)src2);
                                        result = rsp + 144;
                                        v_28 = (__int64)result;
                                        src4 = (__int64 *)v_34;
                                        v_20 = (__int64)src4;
                                        sub_1400A4590(i, a2, src, src3);
                                        v9 = v2;
                                        return v9;
                                    }
                                    result = src2;
                                    result = (__int64 *)((__int64)result + (__int64)i);
                                    a1 = v2 + 1;
                                    if (v9 != a1) {
                                        a3 = a2;
                                        a3 = (size_t *)((__int64)(__int64)a3 & -2);
                                        a4 = result + 16;
                                        src3 += v_48;
                                        v5 = 0;
                                        src6 = 0xFFFFFFFFFFFFFFE;
                                        do {
                                            xmm0 = _mm_loadu_si128((__m128i *)src3);
                                            _mm_storeu_si128((__m128i *)(a4 - 16), xmm0);
                                            a1 = v5 + 2;
                                            v5 = (__int64 *)((__int64)(__int64)v5 ^ (__int64)src6);
                                            v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                            xmm0 = _mm_loadu_si128((__m128i *)((__int64)src5 + (__int64)v5));
                                            _mm_storeu_si128((__m128i *)a4, xmm0);
                                            a4 += 32;
                                            src3 -= 32;
                                            v5 = (__int64 *)a1;
                                        } while (a3 != a1);
                                        if (((__int64)a2 & 1) == 0) {
                                            return (__int64)v5;
                                        }
                                        a3 = a1;
                                        a3 = (size_t *)(~(__int64)a3);
                                        a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)src5 + (__int64)a3));
                                        _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1), xmm0);
                                        return _mm_cvtsi128_si64(xmm0);
                                    }
                                    a1 = 0;
                                    return (__int64)a1;
                                }
                                a2 = (size_t *)v2;
                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a2 - 16), xmm0);
                                a1 -= 16;
                                result += 16;
                                a2 = (size_t *)v9;
                            }
                            do {
                                a4 = *result;
                                a1 -= 16;
                                v5 = (__int64 *)v2;
                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                if (a4 < *src4) a1 = src;
                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)v5), xmm0);
                                v2 += 0;
                                result += 16;
                            } while (result < a3);
                            return (__int64)result;
                        } while (true);
                    }
                    result = (__int64 *)v_38;
                    result = *result;
                    if (result >= *src4) {
                        return (__int64)result;
                    }
                    return (__int64)result;
                }
                result = *src2;
                a1 = *src4;
                a2 = (result < a1) ? 1 : 0;
                a4 = *a3;
                result = (result < a4) ? 1 : 0;
                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a2);
                a1 = (a1 < a4) ? 1 : 0;
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                if (a1 != 0) src4 = a3;
                if (result != 0) src4 = src2;
                return (__int64)a1;
            }
            v_20 = 1;
            sub_1400A3FB0(src2, v9, src, src3);
            return v_20;
        } while (v2 >= 33);
        return v_20;
    }
    return (__int64)result;
}