// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
};

__int64 sub_1400BCA50();
__int64 sub_1400F27F0();
__int64 sub_1400BC6D0();
__int64 sub_1400BB5E0();

__int64 __fastcall sub_1400BBC50(size_t *a1, size_t *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    int v_110;
    int v_118;
    int v_20;
    __int64 v_28;
    int v_34;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    int v_60;
    __int64 *src;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 *src2;
    __int64 *result;
    __int64 v8;
    __int64 *v11;
    __m128i xmm0;
    __int64 v9;
    __int64 *i;
    __int64 *v5;
    __int64 *src3;

    src = (__int64 *)a3;
    v2 = (__int64)a2;
    ptr = (struct Struct_1_t *)a1;
    if (a2 >= 33) {
        src2 = (__int64 *)a4;
        result = (__int64 *)v_118;
        v_40 = (__int64)result;
        v8 = v_110;
        result = src - 16;
        v_48 = (__int64)result;
        v_50 = (int)a4;
        do {
            v11 = (__int64 *)v2;
            --v8;
            while (!((v8 < 0))) {
                a4 = (size_t *)v11;
                a4 = (size_t *)((__int64)(__int64)a4 >> 3);
                result = (__int64 *)a4;
                result = (__int64 *)((__int64)(__int64)result << 6);
                result = (__int64 *)((__int64)result + (__int64)ptr);
                a3 = (__int64)(__int64)a4 * 112;
                a3 = (size_t *)((__int64)a3 + (__int64)ptr);
                v_34 = v8;
                if (v11 >= 64) {
                    sub_1400BCA50(ptr, result, a3, a4);
                    v8 = (__int64)result;
                    v8 -= (__int64)ptr;
                    a1 = (size_t *)v8;
                    a1 = (size_t *)((__int64)(__int64)a1 >> 4);
                    v_58 = (int)a1;
                    xmm0 = _mm_loadu_si128((__m128i *)result);
                    result = *result;
                    _mm_store_si128((__m128i *)&v_60, xmm0);
                    v_38 = (__int64)v11;
                    if ((v_40 == 0)) {
                        if (src2 < v11) JUMPOUT(0x1400bc66c);
                        src2 = v11;
                        src2 = (__int64 *)((__int64)(__int64)src2 << 4);
                        v9 = (__int64)src + (__int64)src2;
                        v2 = 0;
                        result = (__int64 *)ptr;
                        a1 = (size_t *)v9;
                        a2 = (size_t *)v_58;
                        do {
                            a4 = a2;
                            a4 -= 3;
                            a3 = 0;
                            if (a4 >= 0) a3 = a4;
                            a3 = (size_t *)((__int64)(__int64)a3 << 4);
                            a3 = (size_t *)((__int64)a3 + (__int64)ptr);
                            a3 = a2;
                            a3 = (size_t *)((__int64)(__int64)a3 << 4);
                            a3 = (size_t *)((__int64)a3 + (__int64)ptr);
                            if (result >= a3) {
                                v11 = (__int64 *)v_38;
                                if (a2 == v11) {
                                    i = (__int64 *)v2;
                                    i = (__int64 *)((__int64)(__int64)i << 4);
                                    sub_1400F27F0(ptr, src, i, a1);
                                    a2 = (size_t *)v11;
                                    a2 -= v2;
                                    if ((a2 == 0)) {
                                        src2 = (__int64 *)v_50;
                                        if (v2 == 0) {
                                            if (src2 < v11) JUMPOUT(0x1400bc66c);
                                            src2 = v11;
                                            src2 = (__int64 *)((__int64)(__int64)src2 << 4);
                                            v11 = (__int64)src + (__int64)src2;
                                            i = 0;
                                            result = (__int64 *)ptr;
                                            a1 = (size_t *)v11;
                                            v2 = v_58;
                                            do {
                                                a3 = (size_t *)v2;
                                                a3 -= 3;
                                                a2 = 0;
                                                if (a3 >= 0) a2 = a3;
                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                a2 = (size_t *)((__int64)a2 + (__int64)ptr);
                                                a2 = (size_t *)v2;
                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                a2 = (size_t *)((__int64)a2 + (__int64)ptr);
                                                if (result >= a2) {
                                                    v9 = v_38;
                                                    if (v2 == v9) {
                                                        v8 = (__int64)i;
                                                        v8 <<= 4;
                                                        sub_1400F27F0(ptr, src, v8, a4);
                                                        v2 = v9;
                                                        v2 -= (__int64)i;
                                                        if (!((v2 == 0))) {
                                                            ptr += v8;
                                                            result = i + 1;
                                                            if (v9 != result) {
                                                                a1 = (size_t *)v2;
                                                                a1 = (size_t *)((__int64)(__int64)a1 & -2);
                                                                a2 = ptr + 16;
                                                                src2 += v_48;
                                                                a3 = 0;
                                                                v8 = v_34;
                                                                a4 = 0xFFFFFFFFFFFFFFE;
                                                                do {
                                                                    xmm0 = _mm_loadu_si128((__m128i *)src2);
                                                                    _mm_storeu_si128((__m128i *)(a2 - 16), xmm0);
                                                                    result = a3 + 2;
                                                                    a3 = (size_t *)((__int64)(__int64)a3 ^ (__int64)a4);
                                                                    a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)((__int64)v11 + (__int64)a3));
                                                                    _mm_storeu_si128((__m128i *)a2, xmm0);
                                                                    a2 += 32;
                                                                    src2 -= 32;
                                                                    a3 = (size_t *)result;
                                                                } while (a1 != result);
                                                                if ((v2 & 1) == 0) {
                                                                    a2 = (size_t *)v_38;
                                                                    src2 = (__int64 *)v_50;
                                                                    if (a2 < i) JUMPOUT(0x1400bc6b3);
                                                                    result = 0;
                                                                    v_40 = (__int64)result;
                                                                    if (v2 >= 2) {
                                                                        v9 = v2;
                                                                        v9 >>= 1;
                                                                        if (v2 <= 15) {
                                                                            if (v2 <= 7) {
                                                                                xmm0 = _mm_loadu_si128((__m128i *)ptr);
                                                                                _mm_storeu_si128((__m128i *)src, xmm0);
                                                                                result = (__int64 *)v9;
                                                                                result = (__int64 *)((__int64)(__int64)result << 4);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)result));
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
                                                                                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)v5));
                                                                                        _mm_storeu_si128((__m128i *)((__int64)src + (__int64)v5), xmm0);
                                                                                        a4 = *(__int64 *)((__int64)src + (__int64)v5);
                                                                                        /* cmp a3 , v9 */;
                                                                                        a4 = a3;
                                                                                        a4 += 0;
                                                                                        result += 16;
                                                                                    } while (a3 < v9);
                                                                                }
                                                                            } else {
                                                                                result = ptr->field_10;
                                                                                a1 = ptr->field_30;
                                                                                v5 = 0;
                                                                                a3 = 0;
                                                                                v5 = (result >= ptr->field_0) ? 1 : 0;
                                                                                a3 = (result < ptr->field_0) ? 1 : 0;
                                                                                a2 = 0;
                                                                                a2 = (a1 < ptr->field_20) ? 1 : 0;
                                                                                a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                                a1 = (__int64)ptr + (__int64)a3;
                                                                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                result = (__int64)ptr + (__int64)v5;
                                                                                src3 = (__int64 *)a2;
                                                                                src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                                                                                a4 = (__int64)ptr + (__int64)src3;
                                                                                a4 += 32;
                                                                                a2 = (size_t *)((__int64)(__int64)a2 ^ 3);
                                                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                src3 = *(__int64 *)((__int64)ptr + (__int64)src3 + 32);
                                                                                src2 = *(__int64 *)((__int64)ptr + (__int64)a2);
                                                                                v5 = *(__int64 *)((__int64)ptr + (__int64)v5);
                                                                                i = result;
                                                                                if (src2 < v5) i = a4;
                                                                                if (src3 < *(__int64 *)((__int64)ptr + (__int64)a3)) i = a1;
                                                                                if (src3 < *(__int64 *)((__int64)ptr + (__int64)a3)) a1 = a4;
                                                                                a2 = (__int64)ptr + (__int64)a2;
                                                                                if (a2 < 0) a4 = result;
                                                                                if (src2 >= v5) result = a2;
                                                                                if (src2 < v5) a4 = a2;
                                                                                a2 = *a4;
                                                                                a2 = (size_t *)i;
                                                                                if (a2 < *i) a2 = a4;
                                                                                if (0 /* unresolved: flags < */) a4 = i;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a1);
                                                                                _mm_storeu_si128((__m128i *)src, xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a2);
                                                                                _mm_storeu_si128((__m128i *)(src + 16), xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)a4);
                                                                                a1 = (size_t *)v9;
                                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                a2 = *(__int64 *)((__int64)ptr + (__int64)a1 + 16);
                                                                                a4 = *(__int64 *)((__int64)ptr + (__int64)a1 + 48);
                                                                                src2 = 0;
                                                                                v5 = 0;
                                                                                src2 = (a2 >= *(__int64 *)((__int64)ptr + (__int64)a1)) ? 1 : 0;
                                                                                v5 = (a2 < *(__int64 *)((__int64)ptr + (__int64)a1)) ? 1 : 0;
                                                                                a3 = 0;
                                                                                src3 = (__int64)ptr + (__int64)a1;
                                                                                a3 = (a4 < *(__int64 *)((__int64)ptr + (__int64)a1 + 32)) ? 1 : 0;
                                                                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                src2 = (__int64 *)((__int64)(__int64)src2 << 4);
                                                                                a2 = (__int64)src3 + (__int64)src2;
                                                                                i = (__int64 *)a3;
                                                                                i = (__int64 *)((__int64)(__int64)i << 4);
                                                                                a4 = (__int64)i + (__int64)src3;
                                                                                a4 += 32;
                                                                                a3 = (size_t *)((__int64)(__int64)a3 ^ 3);
                                                                                a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                                v8 = *(__int64 *)((__int64)a3 + (__int64)src3);
                                                                                src2 = *(__int64 *)((__int64)src2 + (__int64)src3);
                                                                                v11 = (__int64 *)a2;
                                                                                if (v8 < src2) v11 = a4;
                                                                                i = *(__int64 *)((__int64)src3 + (__int64)i + 32);
                                                                                /* cmp i , *(__int64 *)((__int64)v5 + (__int64)src3) */;
                                                                                v5 = (__int64)src3 + (__int64)v5;
                                                                                if (v5 < 0) v11 = v5;
                                                                                if (v5 < 0) v5 = a4;
                                                                                a3 = (__int64)src3 + (__int64)a3;
                                                                                if (a3 < 0) a4 = a2;
                                                                                if (v8 >= src2) a2 = a3;
                                                                                if (v8 < src2) a4 = a3;
                                                                                _mm_storeu_si128((__m128i *)(src + 32), xmm0);
                                                                                a3 = *a4;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                                result = v11;
                                                                                if (a3 < *v11) v11 = a4;
                                                                                _mm_storeu_si128((__m128i *)(src + 48), xmm0);
                                                                                if (0 /* unresolved: flags < */) a4 = v11;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)v5);
                                                                                _mm_storeu_si128((__m128i *)((__int64)src + (__int64)a1), xmm0);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)v11);
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
                                                                            src2 = (__int64 *)v2;
                                                                            src2 = (__int64 *)((__int64)(__int64)src2 << 4);
                                                                            a3 = (__int64)src + (__int64)src2;
                                                                            sub_1400BC6D0(ptr, src, a3);
                                                                            a2 = (size_t *)v9;
                                                                            a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                            a1 = (__int64)ptr + (__int64)a2;
                                                                            a2 = (size_t *)((__int64)a2 + (__int64)src);
                                                                            a3 = (__int64)src + (__int64)src2;
                                                                            a3 += 128;
                                                                            sub_1400BC6D0(a1, a2, a3);
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
                                                                            a3 = (size_t *)((__int64)a3 + (__int64)ptr);
                                                                            v5 = a1 + 1;
                                                                            a4 = a1;
                                                                            a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                                            do {
                                                                                src3 = (__int64 *)a1;
                                                                                a1 = (size_t *)v5;
                                                                                src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)a3 + (__int64)src3));
                                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src3), xmm0);
                                                                                v5 = *(__int64 *)((__int64)result + (__int64)src3);
                                                                                /* cmp a1 , a2 */;
                                                                                v5 = (__int64 *)a1;
                                                                                v5 += 0;
                                                                                a4 += 16;
                                                                            } while (a1 < a2);
                                                                        }
                                                                        a1 = (size_t *)v2;
                                                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                        a3 = (__int64)ptr + (__int64)a1;
                                                                        a3 -= 16;
                                                                        a1 = (size_t *)((__int64)a1 + (__int64)src);
                                                                        a1 -= 16;
                                                                        a2 = result - 16;
                                                                        do {
                                                                            v_38 = v9;
                                                                            src2 = *result;
                                                                            a4 = 0;
                                                                            v5 = 0;
                                                                            src3 = result;
                                                                            v11 = (src2 >= *src) ? 1 : 0;
                                                                            i = (src2 < *src) ? 1 : 0;
                                                                            xmm0 = _mm_loadu_si128((__m128i *)src3);
                                                                            _mm_storeu_si128((__m128i *)ptr, xmm0);
                                                                            v8 = *a1;
                                                                            v9 = *a2;
                                                                            /* cmp v8 , v9 */;
                                                                            src3 = 0;
                                                                            src3 -= 1;
                                                                            src2 = (__int64 *)a2;
                                                                            if (v8 < v9) {
                                                                                v5 = i;
                                                                                v9 = 0;
                                                                                v9 = 0;
                                                                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                                                                result = (__int64 *)((__int64)result + (__int64)v5);
                                                                                a4 = (size_t *)v11;
                                                                                a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                                                src = (__int64 *)((__int64)src + (__int64)a4);
                                                                                ptr += 16;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)src2);
                                                                                _mm_storeu_si128((__m128i *)a3, xmm0);
                                                                                src3 = (__int64 *)((__int64)(__int64)src3 << 4);
                                                                                a1 = (size_t *)((__int64)a1 + (__int64)src3);
                                                                                v9 <<= 4;
                                                                                a2 += v9;
                                                                                a3 -= 16;
                                                                                v9 = v_38;
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
                                                                                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                                                                                    a4 = (size_t *)((__int64)(__int64)a4 << 4);
                                                                                    src = (__int64 *)((__int64)src + (__int64)a4);
                                                                                    a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                                                                    result = (__int64 *)((__int64)result + (__int64)a3);
                                                                                }
                                                                                if (src != a2) JUMPOUT(0x1400bc6ae);
                                                                                a1 += 16;
                                                                                if (result != a1) JUMPOUT(0x1400bc6ae);
                                                                                return (__int64)a1;
                                                                            }
                                                                            src2 = (__int64 *)a1;
                                                                            return (__int64)src2;
                                                                        } while (!((v9 == 0)));
                                                                        return (__int64)src2;
                                                                    }
                                                                    return (__int64)src2;
                                                                }
                                                                a1 = (size_t *)result;
                                                                a1 = (size_t *)(~(__int64)a1);
                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                result = (__int64 *)((__int64)(__int64)result << 4);
                                                                xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)((__int64)v11 + (__int64)a1));
                                                                _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)result), xmm0);
                                                                return _mm_cvtsi128_si64(xmm0);
                                                            }
                                                            result = 0;
                                                            v8 = v_34;
                                                            return v8;
                                                        }
                                                        return v8;
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
                                                    a3 = *(__int64 *)(ptr + v8);
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
                                        if (v11 < v2) JUMPOUT(0x1400bc66e);
                                        i = (__int64 *)((__int64)i + (__int64)ptr);
                                        result = rsp + 96;
                                        v_28 = (__int64)result;
                                        v8 = v_34;
                                        v_20 = v8;
                                        sub_1400BBC50(i, a2, src, src2);
                                        v11 = (__int64 *)v2;
                                        return (__int64)v11;
                                    }
                                    result = (__int64)ptr + (__int64)i;
                                    a1 = v2 + 1;
                                    if (v11 != a1) {
                                        a3 = a2;
                                        a3 = (size_t *)((__int64)(__int64)a3 & -2);
                                        a4 = result + 16;
                                        src2 += v_48;
                                        v5 = 0;
                                        src3 = 0xFFFFFFFFFFFFFFE;
                                        do {
                                            xmm0 = _mm_loadu_si128((__m128i *)src2);
                                            _mm_storeu_si128((__m128i *)(a4 - 16), xmm0);
                                            a1 = v5 + 2;
                                            v5 = (__int64 *)((__int64)(__int64)v5 ^ (__int64)src3);
                                            v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                            xmm0 = _mm_loadu_si128((__m128i *)(v9 + v5));
                                            _mm_storeu_si128((__m128i *)a4, xmm0);
                                            a4 += 32;
                                            src2 -= 32;
                                            v5 = (__int64 *)a1;
                                        } while (a3 != a1);
                                        if (((__int64)a2 & 1) == 0) {
                                            return (__int64)v5;
                                        }
                                        a3 = a1;
                                        a3 = (size_t *)(~(__int64)a3);
                                        a3 = (size_t *)((__int64)(__int64)a3 << 4);
                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                        xmm0 = _mm_loadu_si128((__m128i *)(v9 + a3));
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
                                a2 = (size_t *)v11;
                            }
                            do {
                                a4 = *result;
                                a1 -= 16;
                                v5 = (__int64 *)v2;
                                v5 = (__int64 *)((__int64)(__int64)v5 << 4);
                                if (a4 < *(__int64 *)(ptr + v8)) a1 = src;
                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)v5), xmm0);
                                v2 += 0;
                                result += 16;
                            } while (result < a3);
                            return (__int64)result;
                        } while (true);
                    }
                    a1 = (size_t *)v_40;
                    if (*a1 >= result) {
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                a1 = ptr->field_0;
                a2 = *result;
                a4 = (a1 < a2) ? 1 : 0;
                v5 = *a3;
                a1 = (a1 < v5) ? 1 : 0;
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
                a2 = (a2 < v5) ? 1 : 0;
                a2 = (size_t *)((__int64)(__int64)a2 ^ (__int64)a4);
                if (a2 != 0) result = a3;
                if (a1 != 0) result = ptr;
                return (__int64)a2;
            }
            v_20 = 1;
            sub_1400BB5E0(ptr, v11, src, src2);
            return v_20;
        } while (v2 >= 33);
        return v_20;
    }
    return (__int64)result;
}