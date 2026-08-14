// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F5BF0();
extern __int64 off_140108630;

__int64 __fastcall sub_1400F5C90(__int64 *a1,struct Struct_1_t *a2, __int64 a3, __int64 a4) {
    int v_70;
    char *str;
    __int64 result;
    __int64 *dst;
    __int64 v7;
    __int64 v4;
    __int64 i;
    __int64 *src;
    __int64 i2;
    __m128i xmm0;

    result = v_70;
    result ^= 1;
    result |= a4;
    if (result != 1) {
        str = 14;
        dst = a1;
        sub_1400F5BF0(a2, str, a3, a4);
        v7 = (__int64)dst;
        *(dst + 8) = str;
        result = 1;
        *dst = str;
        return result;
    } else {
        v4 = a2->field_20;
        i = a2->field_28;
        if (i < v4) {
            src = a2->field_18;
            v4 = -v4;
            ++i;
            i2 = *(src + i - 1);
            i2 += 208;
            while (i2 < 10) {
                a2->field_28 = i;
                i2 = v4 + i;
                ++i2;
                ++i;
            }
        }
        xmm0 = _mm_setzero_si128();
        if (a3 == 0) {
            xmm0 = _mm_cvtsi64_si128((__int64)(off_140108630));
        }
        *(a1 + 8) = _mm_cvtsi128_si64(xmm0);
        result = 0;
        *a1 = v4;
        return result;
    }
}