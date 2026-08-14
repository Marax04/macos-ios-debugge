__int64 off_140108030();
extern __int64 off_140108038;
extern __int64 off_1401142E0;

__int64 __fastcall sub_140030BD0(__int64 *a1, __int64 a2) {
    __int64 *src;
    __int64 v4;
    __int64 v6;
    __int64 v5;
    __int64 v2;
    __m128i xmm0;
    __int64 v1;

    src = a1;
    if (*a1 != 0) {
        v4 = *(src + 8);
        off_140108030();
        ((__int64 (*)())off_140108038)(v1, 0, v4);
    }
    off_140108030();
    v6 = v1;
    a2 = 0;
    v5 = (__int64)src;
    JUMPOUT(off_140108038);
    v2 = v6;
    xmm0 = _mm_loadu_si128((__m128i *)&off_1401142E0);
    _mm_storeu_si128((__m128i *)v6, xmm0);
    return 0;
}