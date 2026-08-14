extern __int64 off_1401247A8;

__int64 __fastcall sub_14008FF00(__int64 a1, __int64 *a2, __int64 a3) {
    __int64 v1;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;

    v1 = *a2;
    a3 = 0x8000000000000000;
    a3 ^= v1;
    /* test v1 , v1 */;
    v1 = 8;
    if (0 /* unresolved: flags < 0 */) v1 = a3;
    src = &off_1401247A8;
    v1 = *(src + v1*4);
    v1 += (__int64)src;
    JUMPOUT(v1);
    xmm0 = _mm_loadu_si128((__m128i *)a2);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a2 + 32));
    _mm_storeu_si128((__m128i *)(a1 + 32), xmm2);
    _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
    _mm_storeu_si128((__m128i *)a1, xmm0);
    return 0;
}