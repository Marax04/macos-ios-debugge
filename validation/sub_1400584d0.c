__int64 __fastcall sub_1400584D0(__int64 *a1, __int64 a2, __int64 a3) {
    __m128i xmm0;
    __int64 result;
    __int64 v2;

    a3 &= a2;
    xmm0 = _mm_loadu_si128((__m128i *)(a1 + a3));
    result = _mm_movemask_epi8(xmm0);
    if (result == 0) {
        v2 = 16;
        a3 += v2;
        a3 &= a2;
        xmm0 = _mm_loadu_si128((__m128i *)(a1 + a3));
        result = _mm_movemask_epi8(xmm0);
        v2 += 16;
        while (result == 0) {
        }
    }
    result = __builtin_ctz(result);
    result += a3;
    result &= a2;
    if ((*(a1 + result) - 0) >= 0) {
        xmm0 = _mm_load_si128((__m128i *)a1);
        result = _mm_movemask_epi8(xmm0);
        result = __builtin_ctz(result);
        return result;
    } else {
        return result;
    }
}