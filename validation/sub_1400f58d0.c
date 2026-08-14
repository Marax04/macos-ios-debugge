// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F5BF0();
__int64 sub_1400F5B9F();
__int64 sub_140026DF0();
extern __int64 off_140108450;
extern __int64 off_140108460;
extern __int64 off_140108470;
extern __int64 off_1401110E8;

__int64 __fastcall sub_1400F58D0(__int64 *a1,struct Struct_1_t *a2, __int64 a3, size_t a4) {
    int v_20;
    char *str;
    __int64 v6;
    __int64 i;
    __int64 result;
    __int64 *src;
    __int64 *v5;
    __int64 v2;
    int v10;
    __m128i xmm1;
    __m128i xmm0;
    __int64 xmm2;
    __int64 v7;
    __int64 v8;
    __int64 *dst;

    v6 = a2->field_20;
    i = a2->field_28;
    result = 0;
    if (i < v6) {
        src = a2->field_18;
        v5 = (__int64 *)v6;
        v5 -= i;
        v2 = *(src + i);
        v10 = v2 - 48;
        while (v10 < 10) {
            ++i;
            a2->field_28 = i;
            ++result;
            result = (__int64)v5;
            xmm1 = _mm_cvtsi64_si128(a4);
            xmm1 = _mm_unpacklo_epi32(xmm1, _mm_load_si128((__m128i *)&off_140108450));
            /* subpd off_140108460, %xmm1 */;
            xmm0 = xmm1;
            /* unpckhpd %xmm1, %xmm0 */;
            /* addsd %xmm1, %xmm0 */;
            a4 = result;
            a4 = -a4;
            if (a4 < 0) a4 = result;
            if (a4 >= 309) {
                xmm1 = _mm_setzero_pd();
                xmm2 = off_140108470;
                do {
                    if (result < 0) {
                        /* divsd %xmm2, %xmm0 */;
                        result += 308;
                        a4 = result;
                        a4 = -a4;
                        if (a4 < 0) a4 = result;
                        v5 = &off_1401110E8;
                        xmm1 = v5[a4];
                        if (result < 0) JUMPOUT(0x1400f5b84);
                        /* mulsd %xmm1, %xmm0 */;
                        v7 = _mm_cvtsi128_si64(xmm0);
                        a4 = 0x7FFFFFFFFFFFFFFF;
                        a4 &= v7;
                        v8 = 0x7FF0000000000000;
                        if (a4 != v8) JUMPOUT(0x1400f5b88);
                    }
                    str = 14;
                    dst = a1;
                    sub_1400F5BF0(a2, str, a3, a4);
                    *(dst + 8) = str;
                    result = 1;
                    *dst = str;
                    return sub_1400F5B9F();
                } while (a4 >= 309);
            }
            return result;
        }
        if (v2 == 46) JUMPOUT(0x1400f5a2a);
        if (v2 != 69) {
            if (v2 != 101) {
                return result;
            }
        }
        v_20 = result;
        sub_140026DF0(0);
        return sub_1400F5B9F();
    }
    return result;
}