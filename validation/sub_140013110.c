// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 14 accesses on `ptr`
struct Struct_2_t {
    __int16 field_0; // offset 0
    __int16 field_2; // offset 2
    __int16 field_4; // offset 4
    __int16 field_6; // offset 6
    __int16 field_8; // offset 8
    __int16 field_A; // offset 10
    __int16 field_C; // offset 12
    __int16 field_E; // offset 14
    __int16 field_10; // offset 16
    __int16 field_12; // offset 18
    __int16 field_14; // offset 20
    __int16 field_16; // offset 22
    __int16 field_18; // offset 24
    __int64 field_1A; // offset 26
};

__int64 sub_1400134B9();
__int64 sub_140011BE0();
extern __int64 off_140121038;
extern __int64 off_140108570;
extern __int64 off_140108580;

__int64 __fastcall sub_140013110(struct Struct_1_t *a1, __int64 *a2, size_t a3, __int64 a4) {
    int arg_4;
    __int64 v_10;
    int v_8;
    __int64 v2;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 v9;
    __int64 result;
    __int64 v5;
    __int64 v7;
    __int64 v6;
    __int64 v8;
    __int64 v4;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __m128i xmm4;
    __m128i xmm5;

    v2 = a3;
    ptr = (struct Struct_2_t *)a2;
    v3 = ((__int64 *)a1)[2];
    if ((v3 & 0x18000000) != 0) {
        if ((v3 & 0x10000000) != 0) {
            v9 = ((__int64 *)a1)[2];
            if (v9 == 0) {
                a3 = 0;
            } else {
                v2 += (__int64)ptr;
                a3 = 0;
                a2 = (__int64 *)ptr;
                result = v9;
                while (a2 != v2) {
                    a3 = *a2;
                    if (a3 >= 0) {
                        v5 = a2 + 1;
                        a3 = v5;
                        a3 -= (__int64)a2;
                        a3 += a4;
                        a2 = (__int64 *)v5;
                        --result;
                        result = 0;
                        v9 -= result;
                        v2 = a3;
                        result = ((__int64 *)a1)[2];
                        if (v9 >= result) {
                            v7 = a1->field_0;
                            a1 = a1->field_8;
                            v6 = ((__int64 *)a1)[3];
                            v8 = v7;
                            a2 = (__int64 *)ptr;
                            v3 = v2;
                            JUMPOUT(v6);
                            v8 = a3;
                            return sub_1400134B9();
                        } else {
                            v_8 = result;
                            a3 = result;
                            a3 -= v9;
                            result = v3;
                            result >>= 29;
                            result &= 3;
                            a2 = &off_140121038;
                            result = *(a2 + result*4);
                            result += (__int64)a2;
                            v_10 = (__int64)ptr;
                            arg_4 = a3;
                            JUMPOUT(result);
                            v8 = 0;
                            return sub_1400134B9();
                        }
                    }
                    if (a3 < 224) {
                        v5 = a2 + 2;
                        return v5;
                    }
                    if (a3 < 240) {
                        v5 = a2 + 3;
                        return v5;
                    }
                    v5 = a2 + 4;
                    return v5;
                }
                a3 = a4;
                return a3;
            }
            return a3;
        } else {
            if (v2 >= 32) {
                v4 = (__int64)a1;
                sub_140011BE0(ptr, v2, a3, a3);
                a1 = (struct Struct_1_t *)v4;
                v9 = result;
            } else {
                if (v2 == 0) {
                    v9 = 0;
                    v2 = 0;
                } else {
                    if (v2 >= 4) {
                        result = v2;
                        result &= 28;
                        a2 = ptr->field_0;
                        xmm0 = _mm_cvtsi32_si128(a2);
                        a2 = ptr->field_2;
                        xmm1 = _mm_cvtsi32_si128(a2);
                        xmm2 = _mm_load_si128((__m128i *)&off_140108570);
                        xmm0 = _mm_cmpgt_epi8(xmm0, xmm2);
                        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                        xmm0 = _mm_shufflelo_epi16(xmm0, 212);
                        xmm0 = _mm_shuffle_epi32(xmm0, 212);
                        xmm3 = _mm_load_si128((__m128i *)&off_140108580);
                        xmm0 = _mm_and_si128(xmm0, xmm3);
                        xmm1 = _mm_cmpgt_epi8(xmm1, xmm2);
                        xmm1 = _mm_unpacklo_epi8(xmm1, xmm1);
                        xmm1 = _mm_shufflelo_epi16(xmm1, 212);
                        xmm1 = _mm_shuffle_epi32(xmm1, 212);
                        xmm1 = _mm_and_si128(xmm1, xmm3);
                        if (result != 4) {
                            a2 = ptr->field_4;
                            xmm4 = _mm_cvtsi32_si128(a2);
                            a2 = ptr->field_6;
                            xmm5 = _mm_cvtsi32_si128(a2);
                            xmm4 = _mm_cmpgt_epi8(xmm4, xmm2);
                            xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                            xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                            xmm4 = _mm_shuffle_epi32(xmm4, 212);
                            xmm4 = _mm_and_si128(xmm4, xmm3);
                            xmm5 = _mm_cmpgt_epi8(xmm5, xmm2);
                            xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                            xmm5 = _mm_shufflelo_epi16(xmm5, 212);
                            xmm5 = _mm_shuffle_epi32(xmm5, 212);
                            xmm5 = _mm_and_si128(xmm5, xmm3);
                            xmm0 = _mm_add_epi64(xmm0, xmm4);
                            xmm1 = _mm_add_epi64(xmm1, xmm5);
                            if (result != 8) {
                                a2 = ptr->field_8;
                                xmm4 = _mm_cvtsi32_si128(a2);
                                a2 = ptr->field_A;
                                xmm5 = _mm_cvtsi32_si128(a2);
                                xmm4 = _mm_cmpgt_epi8(xmm4, xmm2);
                                xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                                xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                                xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                xmm4 = _mm_and_si128(xmm4, xmm3);
                                xmm5 = _mm_cmpgt_epi8(xmm5, xmm2);
                                xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                                xmm5 = _mm_shufflelo_epi16(xmm5, 212);
                                xmm5 = _mm_shuffle_epi32(xmm5, 212);
                                xmm5 = _mm_and_si128(xmm5, xmm3);
                                xmm0 = _mm_add_epi64(xmm0, xmm4);
                                xmm1 = _mm_add_epi64(xmm1, xmm5);
                                if (result != 12) {
                                    a2 = ptr->field_C;
                                    xmm4 = _mm_cvtsi32_si128(a2);
                                    a2 = ptr->field_E;
                                    xmm5 = _mm_cvtsi32_si128(a2);
                                    xmm4 = _mm_cmpgt_epi8(xmm4, xmm2);
                                    xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                                    xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                                    xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                    xmm4 = _mm_and_si128(xmm4, xmm3);
                                    xmm5 = _mm_cmpgt_epi8(xmm5, xmm2);
                                    xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                                    xmm5 = _mm_shufflelo_epi16(xmm5, 212);
                                    xmm5 = _mm_shuffle_epi32(xmm5, 212);
                                    xmm5 = _mm_and_si128(xmm5, xmm3);
                                    xmm0 = _mm_add_epi64(xmm0, xmm4);
                                    xmm1 = _mm_add_epi64(xmm1, xmm5);
                                    if (result != 16) {
                                        a2 = ptr->field_10;
                                        xmm4 = _mm_cvtsi32_si128(a2);
                                        a2 = ptr->field_12;
                                        xmm5 = _mm_cvtsi32_si128(a2);
                                        xmm4 = _mm_cmpgt_epi8(xmm4, xmm2);
                                        xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                                        xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                                        xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                        xmm4 = _mm_and_si128(xmm4, xmm3);
                                        xmm5 = _mm_cmpgt_epi8(xmm5, xmm2);
                                        xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                                        xmm5 = _mm_shufflelo_epi16(xmm5, 212);
                                        xmm5 = _mm_shuffle_epi32(xmm5, 212);
                                        xmm5 = _mm_and_si128(xmm5, xmm3);
                                        xmm0 = _mm_add_epi64(xmm0, xmm4);
                                        xmm1 = _mm_add_epi64(xmm1, xmm5);
                                        if (result != 20) {
                                            a2 = ptr->field_14;
                                            xmm4 = _mm_cvtsi32_si128(a2);
                                            a2 = ptr->field_16;
                                            xmm5 = _mm_cvtsi32_si128(a2);
                                            xmm4 = _mm_cmpgt_epi8(xmm4, xmm2);
                                            xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                                            xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                                            xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                            xmm4 = _mm_and_si128(xmm4, xmm3);
                                            xmm5 = _mm_cmpgt_epi8(xmm5, xmm2);
                                            xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                                            xmm5 = _mm_shufflelo_epi16(xmm5, 212);
                                            xmm5 = _mm_shuffle_epi32(xmm5, 212);
                                            xmm5 = _mm_and_si128(xmm5, xmm3);
                                            xmm0 = _mm_add_epi64(xmm0, xmm4);
                                            xmm1 = _mm_add_epi64(xmm1, xmm5);
                                            if (result != 24) {
                                                a2 = ptr->field_18;
                                                xmm4 = _mm_cvtsi32_si128(a2);
                                                a2 = ptr->field_1A;
                                                xmm5 = _mm_cvtsi32_si128(a2);
                                                xmm4 = _mm_cmpgt_epi8(xmm4, xmm2);
                                                xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                                                xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                                                xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                                xmm4 = _mm_and_si128(xmm4, xmm3);
                                                xmm5 = _mm_cmpgt_epi8(xmm5, xmm2);
                                                xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                                                xmm2 = _mm_shufflelo_epi16(xmm5, 212);
                                                xmm2 = _mm_shuffle_epi32(xmm2, 212);
                                                xmm2 = _mm_and_si128(xmm2, xmm3);
                                                xmm0 = _mm_add_epi64(xmm0, xmm4);
                                                xmm1 = _mm_add_epi64(xmm1, xmm2);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        xmm0 = _mm_add_epi64(xmm0, xmm1);
                        xmm1 = _mm_shuffle_epi32(xmm0, 238);
                        xmm1 = _mm_add_epi64(xmm1, xmm0);
                        v9 = _mm_cvtsi128_si64(xmm1);
                    } else {
                        result = 0;
                        v9 = 0;
                        a2 = 0;
                        a2 = (*(__int64 *)(ptr + result) >= 192) ? 1 : 0;
                        v9 += (__int64)a2;
                        ++result;
                    }
                    while (v2 != result) {
                        return result;
                    }
                }
            }
        }
        return result;
    }
    return result;
}