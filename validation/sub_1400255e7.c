// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140021E7D();
__int64 sub_140013110();
__int64 sub_1400232AF();
__int64 sub_140024CCB();
extern __int64 off_14011D534;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_1400255E7(int *a1) {
    int v_10;
    int v_18;
    int v_20;
    int v_30;
    int v_40;
    char *str;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 *i;
    __int64 v7;
    __int64 v3;
    __int64 v9;
    __int64 v8;
    __int64 v6;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;

    ptr = (struct Struct_1_t *)a1;
    a1 = *a1;
    if (a1 != 0) {
        result = ptr->field_10;
        if (result < ptr->field_8) {
            a1 = *(a1 + result);
            if (a1 == 73) {
                ++result;
                ptr->field_10 = result;
                sub_140021E7D(ptr, 0);
                i = 2;
                if (result == 0) {
                    v7 = ptr->field_20;
                    if (v7 != 0) {
                        v3 = &off_14011D534;
                        sub_140013110(v7, v3, 1);
                        if (result == 0) {
                            sub_1400232AF(ptr);
                            v9 = result;
                            ++i;
                        }
                        result = (__int64)i;
                        return result;
                    }
                    return result;
                }
            } else {
                if (a1 != 66) {
                    sub_140021E7D(ptr, 0);
                    i = (__int64 *)result;
                    i = (__int64 *)((__int64)i + (__int64)i);
                } else {
                    ++result;
                    ptr->field_10 = result;
                    i = str - 32;
                    sub_140024CCB(i, ptr);
                    if (*i == 0) {
                        v8 = ptr->field_20;
                        if (v8 != 0) {
                            result = v_18;
                            v6 = &off_1401109B9;
                            v3 = &off_1401109A9;
                            if (result != 0) v3 = v6;
                            v2 = result + result*8;
                            v2 += 16;
                            sub_140013110(v8, v3, v2);
                            if (result == 0) {
                                xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_10);
                                _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                                _mm_storeu_si128((__m128i *)ptr, xmm0);
                                i = 0;
                            } else {
                                i = 2;
                            }
                            return (__int64)i;
                        }
                        return (__int64)i;
                    } else {
                        if (ptr->field_20 == 0) {
                            return (__int64)i;
                        } else {
                            xmm0 = _mm_loadu_si128((__m128i *)ptr);
                            xmm1 = _mm_loadu_si128((__m128i *)(ptr + 16));
                            _mm_store_si128((__m128i *)&v_30, xmm1);
                            _mm_store_si128((__m128i *)&v_40, xmm0);
                            xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                            xmm1 = _mm_loadu_si128((__m128i *)&v_10);
                            _mm_storeu_si128((__m128i *)ptr, xmm0);
                            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                            sub_1400255E7(ptr);
                            xmm0 = _mm_load_si128((__m128i *)&v_40);
                            xmm1 = _mm_load_si128((__m128i *)&v_30);
                            _mm_storeu_si128((__m128i *)ptr, xmm0);
                            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                        }
                        return _mm_cvtsi128_si64(xmm1);
                    }
                    return _mm_cvtsi128_si64(xmm1);
                }
            }
            return _mm_cvtsi128_si64(xmm1);
        }
    }
    return result;
}