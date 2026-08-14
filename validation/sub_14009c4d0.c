// inferred from 2 accesses on `a1`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 __fastcall sub_14009C4D0(struct Struct_1_t *a1, int *a2) {
    __int64 result;
    __int64 v5;
    __int64 i;
    __int64 v7;
    __int64 v8;
    __int64 v4;
    __int64 v3;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 *dst;
    __int64 v9;

    result = a1->field_0;
    v5 = a1->field_4;
    i = 2;
    v7 = v5;
    if (v5 >= result) {
        v8 = v7;
        v7 = *(__int64 *)(a1 + i*4);
        while (v7 >= v8) {
            ++i;
            if (v5 < result) {
                result = (__int64)a2;
                result >>= 1;
                v5 = result;
                v5 &= -8;
                v4 = v5;
                v4 = -v4;
                v7 = a1 + 16;
                v8 = a1 + (__int64)(__int64)a2*4;
                v8 -= 16;
                v3 = 0;
                do {
                    xmm0 = _mm_loadu_si128((__m128i *)(v7 - 16));
                    xmm1 = _mm_loadu_si128((__m128i *)v7);
                    xmm2 = _mm_loadu_si128((__m128i *)(v8 + v3*4 - 16));
                    xmm3 = _mm_loadu_si128((__m128i *)(v8 + v3*4));
                    xmm3 = _mm_shuffle_epi32(xmm3, 27);
                    xmm2 = _mm_shuffle_epi32(xmm2, 27);
                    _mm_storeu_si128((__m128i *)(v7 - 16), xmm3);
                    _mm_storeu_si128((__m128i *)v7, xmm2);
                    xmm0 = _mm_shuffle_epi32(xmm0, 27);
                    _mm_storeu_si128((__m128i *)(v8 + v3*4), xmm0);
                    xmm0 = _mm_shuffle_epi32(xmm1, 27);
                    _mm_storeu_si128((__m128i *)(v8 + v3*4 - 16), xmm0);
                    v3 -= 8;
                    v7 += 32;
                } while (v4 != v3);
                if (result != v5) {
                    result = -result;
                    dst = (__int64 *)a2;
                    dst = (__int64 *)((__int64)(__int64)dst >> 4);
                    v9 =  + (__int64)(__int64)dst*8;
                    v9 = -v9;
                    dst = (__int64 *)((__int64)(__int64)dst << 5);
                    dst = (__int64 *)((__int64)dst + (__int64)a1);
                    a1 += (__int64)(__int64)a2*4;
                    a1 -= 4;
                    do {
                        a2 = *dst;
                        v7 = *(__int64 *)(a1 + v9*4);
                        *dst = v7;
                        *(__int64 *)(a1 + v9*4) = (__int64)(a2);
                        --v9;
                        dst += 4;
                    } while (result != v9);
                }
            }
            return (__int64)dst;
        }
    } else {
        v8 = v7;
        v7 = *(__int64 *)(a1 + i*4);
        while (v7 < v8) {
            ++i;
            return i;
        }
    }
    if (i != a2) JUMPOUT(0x14009c5fc);
    return result;
}