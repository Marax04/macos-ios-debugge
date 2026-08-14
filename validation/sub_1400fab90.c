__int64 sub_140020E30();
__int64 sub_140020C70();
__int64 sub_1400F37D0();
__int64 sub_140020C60();
__int64 sub_1400F4640();
extern __int64 off_14012D270;
extern __int64 off_14008C740;
extern __int64 off_14011B42B;
extern __int64 off_140117360;
extern __int64 off_14008C220;

__int64 __fastcall sub_1400FAB90(int a1, int *a2, __int64 *a3, __int64 *a4) {
    __int64 rsp;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    __int64 *v_0;
    char *str;
    char *str2;
    __int64 v5;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 result;
    __int64 *src;
    __int64 v3;
    __int64 v6;
    __int64 v7;
    __int64 v8;

    v5 = (__int64)a2;
    v2 = a1;
    a1 = off_14012D270;
    a2 = __readgsqword(88);
    a1 = v_0[a1];
    a1 += 32;
    str2 = (char *)a1;
    xmm0 = _mm_loadu_si128((__m128i *)a3);
    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a3 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(a3 + 48));
    _mm_storeu_si128((__m128i *)&v_30, xmm0);
    _mm_storeu_si128((__m128i *)&v_40, xmm1);
    _mm_storeu_si128((__m128i *)&v_50, xmm2);
    _mm_storeu_si128((__m128i *)&v_60, xmm3);
    xmm0 = _mm_loadu_si128((__m128i *)(a3 + 64));
    _mm_storeu_si128((__m128i *)&v_70, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(a3 + 80));
    _mm_storeu_si128((__m128i *)&v_80, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)(a3 + 96));
    _mm_storeu_si128((__m128i *)&v_90, xmm0);
    a1 = a3[14];
    v_a0 = a1;
    v_a8 = 0;
    a2 = &off_14008C740;
    sub_140020E30(v5, a2, str2);
    a1 = (int)str2;
    sub_140020C70(a1);
    result = v_a8;
    xmm0 = _mm_loadu_si128((__m128i *)&v_b0);
    if (result != 1) {
        if (result != 2) {
            a1 = &off_14011B42B;
            src = &off_140117360;
            sub_1400F37D0(a1, 40, src);
            v3 = (__int64)src;
            v6 = (__int64)a2;
            v2 = a1;
            a1 = src + 272;
            a2 = *(src + 256);
            v_d0 = a1;
            v_d8 = 0;
            v_e0 = (int)a2;
            v_e8 = 1;
            xmm0 = _mm_loadu_si128((__m128i *)a4);
            xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
            xmm2 = _mm_loadu_si128((__m128i *)(a4 + 32));
            xmm3 = _mm_loadu_si128((__m128i *)(a4 + 48));
            _mm_store_si128((__m128i *)&str, xmm0);
            _mm_store_si128((__m128i *)&v_30, xmm1);
            _mm_store_si128((__m128i *)&v_40, xmm2);
            _mm_store_si128((__m128i *)&v_50, xmm3);
            xmm0 = _mm_loadu_si128((__m128i *)(a4 + 64));
            _mm_store_si128((__m128i *)&v_60, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(a4 + 80));
            _mm_store_si128((__m128i *)&v_70, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(a4 + 96));
            _mm_store_si128((__m128i *)&v_80, xmm0);
            a1 = a4[14];
            v_90 = a1;
            v_98 = 0;
            a2 = &off_14008C220;
            sub_140020E30(v6, a2, str);
            v7 = v_d8;
            if (v7 == 3) {
                v8 = v_98;
                xmm0 = _mm_load_si128((__m128i *)&v_a0);
                if (v8 != 1) {
                    if (v8 != 2) JUMPOUT(0x1400fadf4);
                    a1 = _mm_cvtsi128_si64(xmm0);
                    xmm0 = _mm_shuffle_epi32(xmm0, 238);
                    a2 = _mm_cvtsi128_si64(xmm0);
                    sub_140020C60(a1, a2);
                }
                _mm_storeu_si128((__m128i *)v2, xmm0);
                xmm0 = _mm_load_si128((__m128i *)&v_b0);
                xmm1 = _mm_load_si128((__m128i *)&v_c0);
                _mm_storeu_si128((__m128i *)(v2 + 16), xmm0);
                _mm_storeu_si128((__m128i *)(v2 + 32), xmm1);
                return 0;
            }
            a2 = rsp + 216;
            sub_1400F4640(v3, a2);
            v8 = v_98;
            xmm0 = _mm_load_si128((__m128i *)&v_a0);
            while (v8 != 1) {
                return _mm_cvtsi128_si64(xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        } else {
            a1 = _mm_cvtsi128_si64(xmm0);
            xmm0 = _mm_shuffle_epi32(xmm0, 238);
            a2 = _mm_cvtsi128_si64(xmm0);
            sub_140020C60(a1, a2);
        }
    }
    xmm1 = _mm_loadu_si128((__m128i *)&v_c0);
    xmm2 = _mm_loadu_si128((__m128i *)&v_d0);
    _mm_storeu_si128((__m128i *)(v2 + 32), xmm2);
    _mm_storeu_si128((__m128i *)(v2 + 16), xmm1);
    _mm_storeu_si128((__m128i *)v2, xmm0);
    return result;
}