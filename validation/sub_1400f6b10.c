__int64 sub_1400F37A0();
extern __int64 off_140113E48;
extern __int64 off_140113E58;
extern __int64 off_140108260;
extern __int64 off_140108060;

__int64 __fastcall sub_1400F6B10() {
    __int64 rsp;
    int v_1;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    __int64 v10;
    __int64 v7;
    __m128i xmm0;
    __int64 v8;
    __int64 *i;
    __int64 *src;
    __int64 result;
    __int64 v6;
    __int64 v2;
    __int64 v9;
    int v4;

    v10 = rsp + 80;
    v7 = &off_140113E48;
    v_30 = v7;
    v_28 = 1;
    v_20 = 8;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_18, xmm0);
    v8 = &off_140113E58;
    i = v10 - 48;
    sub_1400F37A0(i, v8);
    v10 = rsp + 48;
    src = i;
    result = *i;
    if (result == 1) {
        i = 0xFFFFFF9D;
        result = *src;
        while (result == 1) {
            /* test i , i */;
            ++i;
        }
    }
    if (result == 0) {
        i = 1;
        result = 0;
        /* cmpxchg %(__int64)i, (%(__int64)src) */;
        if ((0 /* unresolved: flags != */)) {
            v6 = v10 - 1;
            v2 = off_140108260;
            v9 = off_140108060;
            do {
                v_1 = 2;
                ((__int64 (*)())v2)(src, v6, 1, 0xFFFFFFFF);
                if (result == 1) {
                    result = *src;
                    i = 0xFFFFFF9D;
                    do {
                        result = *src;
                        v4 = i + 1;
                        i = (__int64 *)v4;
                    } while ((i != 0));
                }
                ((__int64 (*)())v9)();
                return (__int64)i;
            } while (result != 1);
        }
        return (__int64)i;
    }
    return result;
}