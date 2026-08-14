// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14000112B();
__int64 sub_1400012E9();
__int64 sub_1400012EB();
__int64 sub_140001560();
__int64 sub_1400012F2();
extern __int64 off_140108450;
extern __int64 off_140108460;

__int64 __fastcall sub_140001000(__int64 *a1,struct Struct_1_t *a2, __int64 a3, __int64 *a4) {
    __int64 rsp;
    int v_20;
    int v_38;
    int v_40;
    __int64 v2;
    __int64 v6;
    __int64 *i;
    __int64 *result;
    __int64 *src;
    __int64 i2;
    __int64 v7;
    __int64 v8;
    __m128i xmm0;
    __m128i xmm1;

    v2 = a2->field_20;
    v6 = a2->field_28;
    i = (__int64 *)v6;
    i -= v2;
    if (!((i >= 0))) {
        result = a2 + 24;
        src = *result;
        i2 = *(src + v6);
        if (i2 == 46) {
            i2 = v6 + 1;
            a2->field_28 = i2;
            if (i2 >= v2) JUMPOUT(0x1400011aa);
            v7 = 0x1999999999999998;
            i2 = v6;
            i2 -= v2;
            ++i2;
            ++i;
            v6 += 2;
            v2 = 0;
            v8 = v7 + 1;
            return sub_14000112B();
        } else {
            if (i2 != 69) {
                if (i2 != 101) {
                    a2 = 1;
                    if (a3 == 0) {
                        result = a4;
                        result = (__int64 *)(-(__int64)result);
                        if ((result < 0)) JUMPOUT(0x140001162);
                        xmm0 = _mm_cvtsi64_si128(a4);
                        xmm0 = _mm_unpacklo_epi32(xmm0, _mm_load_si128((__m128i *)&off_140108450));
                        /* subpd off_140108460, %xmm0 */;
                        xmm1 = xmm0;
                        /* unpckhpd %xmm0, %xmm1 */;
                        /* addsd %xmm0, %xmm1 */;
                        a2 = _mm_cvtsi128_si64(xmm1);
                        result = 0x8000000000000000;
                        result = (__int64 *)((__int64)(__int64)result | (__int64)a2);
                        return sub_1400012E9();
                    } else {
                        result = a4;
                        return sub_1400012EB();
                    }
                }
            }
            i = a1;
            v_20 = 0;
            a1 = rsp + 56;
            sub_140001560(a1);
            if (v_38 == 0) {
                result = (__int64 *)v_40;
                a2 = 0;
                a1 = i;
                return sub_1400012EB();
            } else {
                result = (__int64 *)v_40;
                *(i + 8) = result;
                *i = 3;
                return sub_1400012F2();
            }
        }
    }
    return (__int64)result;
}