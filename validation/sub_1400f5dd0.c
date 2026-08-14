// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_140026DF0();
extern __int64 off_140108450;
extern __int64 off_140108460;
extern __int64 off_140108470;
extern __int64 off_1401110E8;
extern __int64 off_140108480;

__int64 __fastcall sub_1400F5DD0(__int64 *a1,struct Struct_1_t *a2, __int64 a3, size_t a4) {
    int v_80;
    __int64 result;
    __int64 v5;
    __int64 i;
    __int64 *src;
    __int64 i2;
    __int64 *v2;
    __m128i xmm1;
    __m128i xmm0;
    __int64 xmm2;
    __int64 v8;
    __int64 v7;

    result = v_80;
    v5 = a2->field_20;
    i = a2->field_28;
    if (i < v5) {
        src = a2->field_18;
        v5 = -v5;
        ++i;
        i2 = *(src + i - 1);
        v2 = i2 - 48;
        while (v2 <= 9) {
            a2->field_28 = i;
            i2 = v5 + i;
            ++i2;
            ++i;
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
                    if (result >= 0) JUMPOUT(0x1400f5f0b);
                    /* divsd %xmm2, %xmm0 */;
                    result += 308;
                    a4 = result;
                    a4 = -a4;
                    if (a4 < 0) a4 = result;
                } while (a4 >= 309);
            }
            v2 = &off_1401110E8;
            xmm1 = v2[a4];
            if (result < 0) JUMPOUT(0x1400f5f00);
            /* mulsd %xmm1, %xmm0 */;
            v8 = _mm_cvtsi128_si64(xmm0);
            v7 = 0x7FFFFFFFFFFFFFFF;
            v7 &= v8;
            result = 0x7FF0000000000000;
            if (v7 == result) JUMPOUT(0x1400f5f0b);
            if (a3 == 0) {
                xmm0 = _mm_xor_si128(xmm0, _mm_load_si128((__m128i *)&off_140108480));
            }
            *(a1 + 8) = _mm_cvtsi128_si64(xmm0);
            result = 0;
            *a1 = result;
            return result;
        }
        i2 |= 32;
        if (i2 == 101) {
            return sub_140026DF0();
        }
    }
    return result;
}