// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F9220();
extern __int64 off_140108850;

__int64 __fastcall sub_14007B080(struct Struct_1_t *a1, int a2, int a3) {
    __int64 v4;
    __int64 *result;
    __int64 v2;
    __int64 v3;
    int v11;
    __int64 v6;
    __int64 v5;
    __m128i xmm0;
    __int64 v9;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    int v10;
    __int64 v8;
    __int64 v7;

    v4 = 0xF1357AEA2E62A9C5;
    v4 *= a2;
    v4 = __ROL8__(v4, 26);
    if (((__int64 *)a1)[2] == 0) {
        result = a1 + 32;
        v2 = a2;
        v3 = (__int64)a1;
        v11 = a3;
        sub_1400F9220(a1, 1, result, v2);
        a1 = (struct Struct_1_t *)v3;
        a2 = v2;
        a3 = v11;
    }
    result = a1->field_0;
    v6 = a1->field_8;
    v5 = v4;
    v5 >>= 57;
    xmm0 = _mm_cvtsi32_si128(v5);
    xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
    xmm0 = _mm_shufflelo_epi16(xmm0, 0);
    xmm0 = _mm_shuffle_epi32(xmm0, 68);
    v3 = result - 16;
    v9 = 0;
    xmm1 = _mm_cmpeq_epi32(xmm1, xmm1);
    v2 = 0;
    do {
        v4 &= v6;
        xmm2 = _mm_loadu_si128((__m128i *)(result + v4));
        xmm3 = xmm2;
        xmm3 = _mm_cmpeq_epi8(xmm3, xmm0);
        v10 = _mm_movemask_epi8(xmm3);
        if (v9 == 1) {
            xmm2 = _mm_cmpeq_epi8(xmm2, xmm1);
            v11 = _mm_movemask_epi8(xmm2);
            if (v11 == 0) {
                v9 = 1;
                v4 += v2;
                v4 += 16;
                v2 += 16;
            }
            v2 = *(result + v7);
            if (v2 >= 0) JUMPOUT(0x14007b1fb);
            v2 &= 1;
            v3 = v7 - 16;
            v3 &= v6;
            *(result + v7) = v5;
            *(result + v3 + 16) = v5;
            xmm0 = _mm_cvtsi32_si128(v2);
            /* shufpd $2, off_140108850, %xmm0 */;
            xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
            xmm1 = _mm_sub_epi64(xmm1, xmm0);
            _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
            v8 = v7;
            v8 = -v8;
            v7 <<= 4;
            v7 = -v7;
            *(result + v7 - 16) = a2;
            v8 <<= 4;
            *(result + v8 - 8) = a3;
            return v8;
        }
        v7 = _mm_movemask_epi8(xmm2);
        if (v7 == 0) {
            v9 = 0;
            return v9;
        }
        v7 = __builtin_ctz(v7);
        v7 += v4;
        v7 &= v6;
        return (__int64)result;
    } while (true);
}