__int64 sub_1400F3869();
__int64 sub_14002EDF0();
__int64 sub_14006ACE0();
__int64 sub_1400F3326();
__int64 sub_1400A14C0();
__int64 off_140108030();
extern __int64 off_140119F58;
extern __int64 off_14011A3B8;
extern __int64 off_14011A388;
extern __int64 off_14011A3D0;
extern __int64 off_140108038;
extern __int64 off_14011A3A0;

__int64 __fastcall sub_1400A11B0(int *a1) {
    __int64 rsp;
    int v_28;
    __int64 v_30;
    int v_38;
    int *v_0;
    __int64 v6;
    __int64 v8;
    __int64 *v4;
    __int64 v9;
    __int64 v5;
    __int64 v2;
    __int64 v12;
    __int64 v13;
    __int64 v10;
    __int64 i;
    __int64 *result;
    __int64 v7;
    __int64 v3;
    int v14;
    __m128i xmm0;
    __m128i xmm1;

    v6 = 1;
    v8 = 255;
    v4 = &off_140119F58;
    v9 = 0x200801C060148461;
    do {
        v5 = v6 + v6;
        v2 = a1 + v6*4;
        v12 = 0;
        while (v8 <= 255) {
            v13 = 0x7FE001;
            v13 -= *(v4 + v8*4);
            --v8;
            v10 = v12 + v6;
            i = v12;
            while (i != 256) {
                result = v6 + i;
                if (result < 256) {
                    v7 = *(a1 + i*4);
                    result = v_0[i];
                    v3 = result + v7;
                    v14 = result + v7 - 0x7FE001;
                    if (v3 < 0x7FE001) v14 = v3;
                    v7 -= (__int64)result;
                    result = v7 + 0x7FE001;
                    if (result < 0x7FE001) v7 = result;
                    v7 *= v13;
                    result = (__int64 *)v7;
                    result = (__int64 *)((__int64)(__int64)(__int64)result * v9); /* unsigned; high half in v3 */;
                    *(a1 + i*4) = v14;
                    v3 >>= 20;
                    result = v3 * 0x7FE001;
                    v7 -= (__int64)result;
                    v_0[i] = v7;
                    ++i;
                    v12 += v5;
                    /* cmp v6 , 128 */;
                    v6 = v5;
                    v6 = 1;
                    v8 = 0x7FDFFF;
                    v7 = 256;
                    do {
                        result = (__int64 *)v7;
                        result = (__int64 *)((__int64)(__int64)(__int64)result * v9); /* unsigned; high half in v3 */;
                        v3 >>= 20;
                        result = v3 * 0x7FE001;
                        v7 -= (__int64)result;
                        v7 *= v7;
                        result = (__int64 *)v8;
                        result = (__int64 *)((__int64)(__int64)result >> 1);
                        v8 = (__int64)result;
                    } while (!((v8 <= 1)));
                    v4 = 0;
                    do {
                        v8 = *(__int64 *)((__int64)a1 + (__int64)v4);
                        v7 = *(__int64 *)((__int64)a1 + (__int64)v4 + 4);
                        v8 *= v6;
                        result = (__int64 *)v8;
                        result = (__int64 *)((__int64)(__int64)(__int64)result * v9); /* unsigned; high half in v3 */;
                        v3 >>= 20;
                        result = v3 * 0x7FE001;
                        v8 -= (__int64)result;
                        v7 *= v6;
                        result = (__int64 *)v7;
                        result = (__int64 *)((__int64)(__int64)(__int64)result * v9); /* unsigned; high half in v3 */;
                        *(__int64 *)((__int64)a1 + (__int64)v4) = v8;
                        v3 >>= 20;
                        result = v3 * 0x7FE001;
                        v7 -= (__int64)result;
                        *(__int64 *)((__int64)a1 + (__int64)v4 + 4) = v7;
                        v4 += 8;
                    } while (v4 != 0x400);
                    return (__int64)v4;
                }
                v6 = &off_14011A3B8;
                sub_1400F3869(result, 256, v6);
                v6 = &off_14011A388;
                sub_1400F3869(v8, 256, v6);
                v14 = v7;
                v12 = v6;
                v2 = v3;
                v5 = (__int64)a1;
                sub_14002EDF0(0, 35);
                if (result != 0) {
                    v4 = result;
                    *result = v12;
                    v14 = __ROL2__(v14, 8);
                    *(result + 1) = v14;
                    xmm0 = _mm_loadu_si128((__m128i *)v2);
                    xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
                    _mm_storeu_si128((__m128i *)(result + 3), xmm0);
                    _mm_storeu_si128((__m128i *)(result + 19), xmm1);
                    v3 = &off_14011A3D0;
                    sub_14006ACE0(v5, v3, result, 35);
                    off_140108030();
                    a1 = (int *)result;
                    v3 = 0;
                    JUMPOUT(off_140108038);
                }
                sub_1400F3326(1, 35, result);
                v5 = v3;
                v4 = (__int64 *)a1;
                sub_14002EDF0(0, 0xC00);
                if (result == 0) JUMPOUT(0x1400a172f);
                v_28 = 0xC00;
                v_30 = (__int64)result;
                v_38 = 0;
                v13 = 0;
                v2 = rsp + 40;
                v12 = 0;
                return sub_1400A14C0();
            }
            v6 = &off_14011A3A0;
            sub_1400F3869(256, 256, v6, v7);
            return v6;
        }
        return v6;
    } while ((0 /* unresolved: flags < */));
    return (__int64)result;
}