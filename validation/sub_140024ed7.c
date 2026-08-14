__int64 sub_140013110();
__int64 sub_140024CCB();
__int64 sub_140022D6B();
extern __int64 off_1401109D2;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_140024ED7(int *a1) {
    int v_10;
    int v_18;
    int v_20;
    int v_30;
    int v_40;
    char *str;
    __int64 *src;
    __int64 v7;
    __int64 v9;
    __int64 v6;
    __int64 *v5;
    __int64 v8;
    __int64 result;
    __int64 v3;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;

    src = (__int64 *)a1;
    if (*a1 == 0) {
        v7 = *(src + 32);
        if (v7 != 0) {
            v9 = &off_1401109D2;
            v6 = 1;
            return sub_140013110();
        }
    } else {
        v5 = str - 32;
        sub_140024CCB(v5, src);
        if (*v5 == 0) {
            v8 = *(src + 32);
            if (v8 != 0) {
                result = v_18;
                v6 = &off_1401109B9;
                v3 = &off_1401109A9;
                if (result != 0) v3 = v6;
                v2 = result + result*8;
                v2 += 16;
                sub_140013110(v8, v3, v2);
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_10);
                    _mm_storeu_si128((__m128i *)(src + 16), xmm1);
                    _mm_storeu_si128((__m128i *)src, xmm0);
                    result = 0;
                }
                return result;
            }
            return result;
        } else {
            if (*(src + 32) == 0) {
                return result;
            } else {
                xmm0 = _mm_loadu_si128((__m128i *)src);
                xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
                _mm_store_si128((__m128i *)&v_30, xmm1);
                _mm_store_si128((__m128i *)&v_40, xmm0);
                xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                xmm1 = _mm_loadu_si128((__m128i *)&v_10);
                _mm_storeu_si128((__m128i *)src, xmm0);
                _mm_storeu_si128((__m128i *)(src + 16), xmm1);
                sub_140022D6B(src);
                xmm0 = _mm_load_si128((__m128i *)&v_40);
                xmm1 = _mm_load_si128((__m128i *)&v_30);
                _mm_storeu_si128((__m128i *)src, xmm0);
                _mm_storeu_si128((__m128i *)(src + 16), xmm1);
            }
            return _mm_cvtsi128_si64(xmm1);
        }
    }
    return result;
}