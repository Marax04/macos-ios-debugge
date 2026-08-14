__int64 sub_14002E5CA();
__int64 sub_14002E591();

__int64 __fastcall sub_14002E50D(__int64 a1, __int64 a2) {
    int arg_35;
    int arg_3d0;
    int arg_400;
    __int64 v4;
    __m128i xmm0;
    __int64 *dst;
    __int64 v2;
    __int64 *dst2;
    __int64 v3;

    *(__int64 *)((__int64)dst + (__int64)dst) = *(__int64 *)((__int64)dst + (__int64)dst) + dst;
    arg_35 += a2;
    v4 = v2;
    v4 = -v4;
    if ((0 /* overflow check on (-v4) */)) {
        xmm0 = _mm_load_si128((__m128i *)&arg_3d0);
        _mm_storeu_si128((__m128i *)(dst2 + 16), xmm0);
        *dst2 = v2;
        *(dst2 + 8) = v3;
        if (arg_400 != 0) JUMPOUT(0x14002e5b2);
        return sub_14002E5CA();
    } else {
        return sub_14002E591();
    }
}