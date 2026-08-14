void __fastcall sub_14006CC10(__int64 a1, __int64 a2, __int64 a3) {
    __m128i xmm0;
    __m128i xmm1;

    xmm0 = _mm_loadu_si128((__m128i *)a2);
    xmm1 = _mm_loadu_si128((__m128i *)a3);
    xmm1 = _mm_xor_si128(xmm1, xmm0);
    _mm_storeu_si128((__m128i *)a1, xmm1);
    xmm0 = _mm_loadu_si128((__m128i *)(a2 + 16));
    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
    xmm1 = _mm_xor_si128(xmm1, xmm0);
    _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
}