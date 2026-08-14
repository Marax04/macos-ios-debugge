__int64 sub_14002EDF0();
__int64 sub_14006ACE0();
__int64 sub_1400F3326();
__int64 sub_1400F2808();
__int64 sub_14006A5A0();
__int64 sub_1400F27F0();
__int64 sub_1400A18F1();
__int64 sub_1400F3510();
__int64 off_140108030();
extern __int64 off_14011A3D0;
extern __int64 off_140108038;

__int64 __fastcall sub_1400A13C0(int a1, int a2, int a3, int a4) {
    __int64 rsp;
    int arg_30;
    __int64 v_100;
    int v_140;
    int v_150;
    int v_160;
    int v_20;
    int v_28;
    __int64 v_30;
    __int64 v_38;
    int v_40;
    __int64 v_50;
    int v_60;
    int v_70;
    int v_90;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    char *str;
    __int64 v8;
    __int64 v6;
    __int64 v2;
    __int64 *src;
    __int64 *i;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm8;
    __int64 i2;
    __int64 *result;
    __int64 v7;

    v8 = a4;
    v6 = a3;
    v2 = a2;
    src = (__int64 *)a1;
    sub_14002EDF0(0, 35);
    if (result != 0) {
        i = result;
        *result = v6;
        v8 = __ROL2__(v8, 8);
        *(result + 1) = v8;
        xmm0 = _mm_loadu_si128((__m128i *)v2);
        xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
        _mm_storeu_si128((__m128i *)(result + 3), xmm0);
        _mm_storeu_si128((__m128i *)(result + 19), xmm1);
        a2 = &off_14011A3D0;
        sub_14006ACE0(src, a2, result, 35);
        off_140108030();
        a1 = (int)result;
        a2 = 0;
        JUMPOUT(off_140108038);
    }
    sub_1400F3326(1, 35, result);
    src = (__int64 *)a2;
    i = (__int64 *)a1;
    sub_14002EDF0(0, 0xC00);
    if (result == 0) {
        sub_1400F3326(1, 0xC00);
        _mm_store_si128((__m128i *)&v_160, xmm8);
        _mm_store_si128((__m128i *)&v_150, xmm7);
        _mm_store_si128((__m128i *)&v_140, xmm6);
        i = (__int64 *)a3;
        src = (__int64 *)a2;
        v_40 = a1;
        sub_1400F2808(a1, 0, 0x400);
        sub_14002EDF0(8, 0x600);
        if (result == 0) JUMPOUT(0x1400a1a9f);
        v6 = (__int64)result;
        a1 = rsp + 96;
        v_50 = (__int64)src;
        v_38 = (__int64)i;
        sub_1400A13C0(a1, src, 160, i);
        xmm6 = _mm_load_si128((__m128i *)&v_60);
        xmm7 = _mm_load_si128((__m128i *)&v_70);
        v2 = rsp + 264;
        i = 0;
        xmm8 = _mm_setzero_si128();
        i2 = rsp + 256;
        src = 32;
        v8 = 0;
        do {
            result = i;
            result = __builtin_bswap64(result);
            _mm_store_si128((__m128i *)&v_a0, xmm6);
            _mm_store_si128((__m128i *)&v_b0, xmm7);
            v_100 = (__int64)result;
            _mm_storeu_si128((__m128i *)(v2 + 32), xmm8);
            _mm_storeu_si128((__m128i *)(v2 + 16), xmm8);
            _mm_storeu_si128((__m128i *)v2, xmm8);
            arg_30 = 0;
            v_28 = 27;
            v_20 = 8;
            a1 = rsp + 192;
            a2 = rsp + 160;
            sub_14006A5A0(a1, a2, i2, 0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_c0);
            xmm1 = _mm_loadu_si128((__m128i *)&v_d0);
            _mm_store_si128((__m128i *)&v_90, xmm1);
            _mm_store_si128((__m128i *)&str, xmm0);
            a3 = 0x600;
            a3 -= v8;
            if (a3 >= 32) a3 = src;
            v7 = a3 + v8;
            v8 += v6;
            sub_1400F27F0(v8, str, a3);
            ++i;
            v8 = v7;
        } while (i != 48);
        i = (__int64 *)v_38;
        i += 0x4242;
        i2 = 0;
        xmm6 = _mm_setzero_si128();
        v8 = rsp + 192;
        v7 = rsp + 160;
        src = rsp + 256;
        a3 = v_40;
        v_38 = (__int64)i;
        result = 0;
        return sub_1400A18F1();
    } else {
        v_28 = 0xC00;
        v_30 = (__int64)result;
        v_38 = 0;
        v7 = 0;
        v2 = rsp + 40;
        v6 = 0;
        do {
            v8 = *(src + v6);
            sub_1400F3510(v2);
            result = (__int64 *)v_30;
            *(result + v7) = v8;
            i2 = v7 + 1;
            v_38 = i2;
            a1 = v_28;
            if (i2 == a1) {
                sub_1400F3510(v2);
                a1 = v_28;
            }
            a2 = v8;
            a2 >>= 8;
            result = (__int64 *)v_30;
            *(result + v7 + 1) = a2;
            ++i2;
            v_38 = i2;
            if (i2 != a1) {
                v6 += 4;
                v8 >>= 16;
                *(result + v7 + 2) = v8;
                ++i2;
                v_38 = i2;
                v7 = i2;
                v7 = 768;
                v6 = 0;
                v2 = rsp + 40;
                do {
                    v8 = *(src + v6 + 0x400);
                    sub_1400F3510(v2);
                    result = (__int64 *)v_30;
                    *(result + v7) = v8;
                    i2 = v7 + 1;
                    v_38 = i2;
                    a1 = v_28;
                    if (i2 == a1) {
                        sub_1400F3510(v2);
                        a1 = v_28;
                    }
                    a2 = v8;
                    a2 >>= 8;
                    result = (__int64 *)v_30;
                    *(result + v7 + 1) = a2;
                    ++i2;
                    v_38 = i2;
                    if (i2 != a1) {
                        v8 >>= 16;
                        *(result + v7 + 2) = v8;
                        ++i2;
                        v_38 = i2;
                        v6 += 4;
                        v7 = i2;
                        v7 = 0x600;
                        v6 = 0;
                        v2 = rsp + 40;
                        do {
                            v8 = *(src + v6 + 0x800);
                            sub_1400F3510(v2);
                            result = (__int64 *)v_30;
                            *(result + v7) = v8;
                            i2 = v7 + 1;
                            v_38 = i2;
                            a1 = v_28;
                            if (i2 == a1) {
                                sub_1400F3510(v2);
                                a1 = v_28;
                            }
                            a2 = v8;
                            a2 >>= 8;
                            result = (__int64 *)v_30;
                            *(result + v7 + 1) = a2;
                            ++i2;
                            v_38 = i2;
                            if (i2 != a1) {
                                v8 >>= 16;
                                *(result + v7 + 2) = v8;
                                ++i2;
                                v_38 = i2;
                                v6 += 4;
                                v7 = i2;
                                v7 = 0x900;
                                v6 = 0;
                                v2 = rsp + 40;
                                do {
                                    v8 = *(src + v6 + 0xC00);
                                    sub_1400F3510(v2);
                                    result = (__int64 *)v_30;
                                    *(result + v7) = v8;
                                    i2 = v7 + 1;
                                    v_38 = i2;
                                    a1 = v_28;
                                    if (i2 == a1) {
                                        sub_1400F3510(v2);
                                        a1 = v_28;
                                    }
                                    a2 = v8;
                                    a2 >>= 8;
                                    result = (__int64 *)v_30;
                                    *(result + v7 + 1) = a2;
                                    ++i2;
                                    v_38 = i2;
                                    if (i2 != a1) {
                                        v8 >>= 16;
                                        *(result + v7 + 2) = v8;
                                        ++i2;
                                        v6 += 4;
                                        v7 = i2;
                                        result = (__int64 *)i2;
                                        *(i + 16) = result;
                                        xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                        _mm_storeu_si128((__m128i *)i, xmm0);
                                        return _mm_cvtsi128_si64(xmm0);
                                    }
                                    sub_1400F3510(v2, a2);
                                    result = (__int64 *)v_30;
                                    return (__int64)result;
                                } while (v6 != 0x400);
                                return (__int64)result;
                            }
                            sub_1400F3510(v2, a2);
                            result = (__int64 *)v_30;
                            return (__int64)result;
                        } while (v6 != 0x400);
                        return (__int64)result;
                    }
                    sub_1400F3510(v2, a2);
                    result = (__int64 *)v_30;
                    return (__int64)result;
                } while (v6 != 0x400);
                return (__int64)result;
            }
            sub_1400F3510(v2, a2);
            result = (__int64 *)v_30;
            return (__int64)result;
        } while (v6 != 0x400);
        return (__int64)result;
    }
}