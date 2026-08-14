__int64 sub_14002EDF0();
__int64 sub_1400F3340();
extern __int64 off_14010A568;
extern __int64 off_14010A6B8;

__int64 __fastcall sub_1400F2E20(int a1, int a2) {
    __int64 v4;
    __int64 v3;
    __int64 v7;
    __int64 *src;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v6;
    __int64 v2;
    __int64 *dst;

    v4 = a2;
    v3 = a1;
    sub_14002EDF0(0, 88);
    if (dst == 0) {
        sub_1400F3340(8, 88);
        v7 = a2;
        src = (__int64 *)a1;
        sub_14002EDF0(0, 80);
        if (dst == 0) JUMPOUT(0x1400f2ee4);
        v5 = &off_14010A568;
        *dst = v5;
        xmm0 = _mm_loadu_si128((__m128i *)v7);
        xmm1 = _mm_loadu_si128((__m128i *)(v7 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v7 + 32));
        _mm_storeu_si128((__m128i *)(dst + 8), xmm0);
        _mm_storeu_si128((__m128i *)(dst + 24), xmm1);
        _mm_storeu_si128((__m128i *)(dst + 40), xmm2);
        xmm0 = _mm_loadu_si128((__m128i *)src);
        _mm_storeu_si128((__m128i *)(dst + 56), xmm0);
        v6 = *(src + 16);
        *(dst + 72) = v6;
        return v6;
    } else {
        v2 = &off_14010A6B8;
        *dst = v2;
        xmm0 = _mm_loadu_si128((__m128i *)v4);
        xmm1 = _mm_loadu_si128((__m128i *)(v4 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v4 + 32));
        _mm_storeu_si128((__m128i *)(dst + 8), xmm0);
        _mm_storeu_si128((__m128i *)(dst + 24), xmm1);
        _mm_storeu_si128((__m128i *)(dst + 40), xmm2);
        xmm0 = _mm_loadu_si128((__m128i *)v3);
        xmm1 = _mm_loadu_si128((__m128i *)(v3 + 16));
        _mm_storeu_si128((__m128i *)(dst + 56), xmm0);
        _mm_storeu_si128((__m128i *)(dst + 72), xmm1);
        return _mm_cvtsi128_si64(xmm1);
    }
}