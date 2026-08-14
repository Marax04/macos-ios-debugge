__int64 sub_140013110();
__int64 sub_140024CCB();
__int64 sub_140023492();
extern __int64 off_1401109D2;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_140023D16(int *a1, int a2) {
    int v_10;
    int v_18;
    int v_30;
    int v_40;
    int v_8;
    char *str;
    __int64 *src;
    __int64 v6;
    __int64 v8;
    __int64 v5;
    __int64 v2;
    __int64 *v4;
    __int64 v7;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;

    src = (__int64 *)a1;
    if (*a1 == 0) {
        v6 = *(src + 32);
        if (v6 != 0) {
            v8 = &off_1401109D2;
            v5 = 1;
            return sub_140013110();
        }
    } else {
        v2 = a2;
        v4 = str - 24;
        sub_140024CCB(v4, src);
        if (*v4 == 0) {
            v7 = *(src + 32);
            if (v7 != 0) {
                result = v_10;
                v5 = &off_1401109B9;
                a2 = &off_1401109A9;
                if (result != 0) a2 = v5;
                v2 = result + result*8;
                v2 += 16;
                sub_140013110(v7, a2, v2);
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    xmm0 = _mm_loadu_si128((__m128i *)&v_18);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_8);
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
                xmm0 = _mm_loadu_si128((__m128i *)&v_18);
                xmm1 = _mm_loadu_si128((__m128i *)&v_8);
                _mm_storeu_si128((__m128i *)src, xmm0);
                _mm_storeu_si128((__m128i *)(src + 16), xmm1);
                sub_140023492(src, v2);
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