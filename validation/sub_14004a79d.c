__int64 sub_1400496A2();

__int64 __fastcall sub_14004A79D(int a1, size_t a2, int a3, size_t a4) {
    int v_168;
    int v_90;
    int v_c8;
    __int64 v4;
    __m128i xmm11;
    __m128i xmm0;
    __int64 v5;
    int v1;
    __int64 v3;
    __int64 *dst;
    __m128i xmm10;
    __m128i xmm7;

    a2 <<= 15;
    if ((0 /* overflow check on (a2 << 15) */)) JUMPOUT(0x14004a762);
    *(dst + 68) = *(dst + 68) + v1;
    /* pshufw $68, %mm0, %mm2 */;
    a1 = 0;
    do {
        v4 &= a3;
        xmm11 = _mm_loadu_si128((__m128i *)(a4 + v4));
        xmm0 = xmm11;
        xmm0 = _mm_cmpeq_epi8(xmm0, xmm10);
        v5 = _mm_movemask_epi8(xmm0);
        xmm11 = _mm_cmpeq_epi8(xmm11, xmm7);
        v1 = _mm_movemask_epi8(xmm11);
        if (v1 == 0) {
            v4 += a1;
            v4 += 16;
            a1 += 16;
        }
        v_168 = 12;
        v5 = v_c8;
        v3 = v_90;
        return sub_1400496A2();
    } while (true);
}