__int64 sub_1400F37A0();
__int64 sub_140009EE0();
extern __int64 off_14010AA48;
extern __int64 off_14010AAD8;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14000A9E0(__int64 *a1, __int64 a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_28;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    __int64 v_38;
    int v_40;
    int v_48;
    int v_50;
    __int64 *result;
    __m128i xmm0;
    __int64 *src;
    __int64 i;
    __int64 v6;
    __int64 v8;
    __int64 *v2;
    __int64 v7;

    result = *a1;
    if (result != 3) {
        if (result >= 2) {
            result = (__int64 *)arg_28;
            if (result != 0) {
                if (result != 2) {
                    if (result != 3) {
                        result = &off_14010AA48;
                        v_38 = (__int64)result;
                        v_40 = 1;
                        v_48 = 8;
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)&v_50, xmm0);
                        a2 = &off_14010AAD8;
                        a1 = rsp + 56;
                        sub_1400F37A0(a1, a2, src);
                        a1 += 16;
                        return sub_140009EE0();
                    } else {
                        src = (__int64 *)arg_10;
                        v_28 = (int)a1;
                        result = (__int64 *)arg_18;
                        v_30 = (__int64)result;
                        if (result != 0) {
                            i = 0;
                            v6 = off_140108030;
                            v8 = off_140108038;
                            do {
                                v2 = i * 56;
                                result = *(__int64 *)((__int64)src + (__int64)v2 + 8);
                                v_20 = (__int64)result;
                                v7 = *(__int64 *)((__int64)src + (__int64)v2 + 16);
                                v2 = (__int64 *)((__int64)v2 + (__int64)src);
                                if (*v2 == 0) {
                                    ++i;
                                    result = (__int64 *)v_28;
                                    if (*(result + 8) != 0) {
                                        ((__int64 (*)())off_140108030)();
                                        a1 = result;
                                        a2 = 0;
                                        JUMPOUT(off_140108038);
                                    }
                                    return a2;
                                }
                                ((__int64 (*)())v6)();
                                ((__int64 (*)())v8)(result, 0, v_20);
                                return a2;
                            } while (i != v_30);
                        }
                        return a2;
                    }
                }
                return a2;
            }
            return a2;
        }
    }
    return (__int64)result;
}