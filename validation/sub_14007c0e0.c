// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F96F0();
extern __int64 off_140108850;

__int64 __fastcall sub_14007C0E0(struct Struct_1_t *a1, int a2) {
    __int64 v4;
    __int64 v9;
    __int64 v2;
    __int64 v3;
    __int64 *dst;
    __int64 v7;
    __int64 v10;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    int v11;
    __int64 result;
    __int64 v8;
    __int64 v6;

    v4 = 0xF1357AEA2E62A9C5;
    v4 *= a2;
    v4 = __ROL8__(v4, 26);
    if (((__int64 *)a1)[2] == 0) {
        v9 = a1 + 32;
        v2 = a2;
        v3 = (__int64)a1;
        sub_1400F96F0(0, a1, 1, v9, v6);
        a1 = (struct Struct_1_t *)v3;
        a2 = v2;
    }
    dst = a1->field_0;
    v7 = a1->field_8;
    v10 = v4;
    v10 >>= 57;
    xmm0 = _mm_cvtsi32_si128(v6);
    xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
    xmm0 = _mm_shufflelo_epi16(xmm0, 0);
    xmm0 = _mm_shuffle_epi32(xmm0, 68);
    v2 = 0;
    xmm1 = _mm_cmpeq_epi32(xmm1, xmm1);
    v3 = 0;
    do {
        v4 &= v7;
        xmm2 = _mm_loadu_si128((__m128i *)(dst + v4));
        xmm3 = xmm2;
        xmm3 = _mm_cmpeq_epi8(xmm3, xmm0);
        v11 = _mm_movemask_epi8(xmm3);
        if (v2 == 1) {
            xmm2 = _mm_cmpeq_epi8(xmm2, xmm1);
            result = _mm_movemask_epi8(xmm2);
            if (result == 0) {
                v2 = 1;
                v4 += v3;
                v4 += 16;
                v3 += 16;
            }
            result = *(dst + v8);
            if (result >= 0) JUMPOUT(0x14007c230);
            result &= 1;
            v3 = v8 - 16;
            v3 &= v7;
            *(dst + v8) = v6;
            *(dst + v3 + 16) = v6;
            xmm0 = _mm_loadu_si128((__m128i *)(a1 + 16));
            xmm1 = _mm_cvtsi32_si128(result);
            /* shufpd $2, off_140108850, %xmm1 */;
            xmm0 = _mm_sub_epi64(xmm0, xmm1);
            _mm_storeu_si128((__m128i *)(a1 + 16), xmm0);
            v8 <<= 3;
            v8 = -v8;
            *(dst + v8 - 8) = a2;
            return v8;
        }
        result = _mm_movemask_epi8(xmm2);
        if (result == 0) {
            v2 = 0;
            return v2;
        }
        v8 = __builtin_ctz(result);
        v8 += v4;
        v8 &= v7;
        return result;
    } while (true);
}