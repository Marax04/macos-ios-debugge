// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[24];
    __int64 field_48; // offset 72
};

// inferred from 15 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[24];
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    char _pad_60[16];
    __int64 field_78; // offset 120
    char _pad_78[120];
    __int64 field_F8; // offset 248
    char _pad_F8[368];
    __int64 field_270; // offset 624
    __int64 field_278; // offset 632
    __int64 field_280; // offset 640
    __int64 field_288; // offset 648
};

__int64 sub_1400F0FFA();
__int64 sub_140107010();
__int64 sub_1400F3510();
__int64 sub_1400F5F90();
__int64 sub_1400F1034();
extern __int64 off_140108850;
extern __int64 off_140124D48;

__int64 __fastcall sub_1400EF880(size_t *a1,struct Struct_1_t *a2) {
    int v_20;
    int v_28;
    __int64 v_44;
    __int64 v_48;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    __int64 v_88;
    int v_90;
    int v_a0;
    int *arg_0;
    struct Struct_2_t *ptr;
    __int64 *result;
    __int64 v4;
    __m128i xmm6;
    __m128i xmm7;
    __int64 *dst;
    __int64 v5;
    __int64 v12;
    __int64 v6;
    __int64 v7;
    __m128i xmm0;
    __int64 v10;
    __int64 i;
    __int64 v2;
    __int64 v9;
    __m128i xmm1;
    __m128i xmm2;
    __int64 *src;

    _mm_store_si128((__m128i *)&v_a0, xmm7);
    _mm_store_si128((__m128i *)&v_90, xmm6);
    ptr = (struct Struct_2_t *)a1;
    a1 = a2->field_20;
    result = a2->field_28;
    result = (__int64 *)((__int64)(__int64)result << 5);
    v_48 = (__int64)a1;
    result = (__int64 *)((__int64)result + (__int64)a1);
    v_88 = (__int64)result;
    result = a2->field_48;
    v_44 = (__int64)result;
    v4 = 0;
    result = ptr + 72;
    v_78 = (__int64)result;
    result = ptr + 104;
    v_70 = (__int64)result;
    xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
    xmm7 = _mm_load_si128((__m128i *)&off_140108850);
    dst = &off_140124D48;
    a1 = (size_t *)v_48;
    if (a1 == v_88) {
        a1 = ptr->field_28;
        result = 3;
        if (a1 == 0) JUMPOUT(0x1400f102c);
        v5 = ptr->field_20;
        v12 = 0xF1357AEA2E62A9C5;
        if (ptr->field_60 == 0) JUMPOUT(0x1400f102e);
        a1 = (size_t *)((__int64)(__int64)a1 << 4);
        a1 += v5;
        v6 = ptr->field_48;
        v7 = ptr->field_50;
        ptr = v5 + 16;
        xmm0 = _mm_cmpeq_epi32(xmm0, xmm0);
        return sub_1400F0FFA();
    } else {
        v10 = (__int64)dst;
        i = ptr->field_10;
        result = 0xFFFFFFFF;
        if (i >= result) i = result;
        v2 = a1[3];
        v_20 = (int)a1;
        if ((ptr->field_58 == 0)) {
            a1 = (size_t *)v_78;
            a2 = (struct Struct_1_t *)v_70;
            sub_140107010(a1, a2);
            a1 = (size_t *)v_20;
        }
        result = a1 + 32;
        v_48 = (__int64)result;
        result = v4 + 1;
        v_80 = (__int64)result;
        v6 = v2;
        v7 = 0xF1357AEA2E62A9C5;
        v6 *= v7;
        v6 = __ROL8__(v6, 26);
        dst = ptr->field_48;
        a2 = ptr->field_50;
        result = (__int64 *)v6;
        result = (__int64 *)((__int64)(__int64)result >> 57);
        xmm0 = _mm_cvtsi32_si128(result);
        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
        xmm0 = _mm_shufflelo_epi16(xmm0, 0);
        xmm0 = _mm_shuffle_epi32(xmm0, 68);
        a1 = 0;
        v9 = 0;
        do {
            v6 &= (__int64)a2;
            xmm1 = _mm_loadu_si128((__m128i *)&*(dst + v6));
            xmm2 = xmm1;
            xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
            v12 = _mm_movemask_epi8(xmm2);
            v5 = v_28;
            if (a1 == 1) {
                xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
                src = _mm_movemask_epi8(xmm1);
                if (src == 0) {
                    a1 = 1;
                    v_28 = v5;
                    v6 += v9;
                    v6 += 16;
                    v9 += 16;
                }
                v6 = *(dst + v5);
                if (v6 >= 0) {
                    xmm0 = _mm_load_si128((__m128i *)&*dst);
                    v5 = _mm_movemask_epi8(xmm0);
                    v5 = __builtin_ctz(v5);
                    v6 = *(dst + v5);
                }
                v6 &= 1;
                v7 = v5 - 16;
                v7 &= (__int64)a2;
                *(dst + v5) = result;
                *(dst + v7 + 16) = result;
                xmm0 = _mm_loadu_si128((__m128i *)(ptr + 88));
                a1 = (size_t *)v6;
                xmm1 = _mm_cvtsi32_si128(v6);
                /* shufps $228, %xmm7, %xmm1 */;
                xmm0 = _mm_sub_epi64(xmm0, xmm1);
                _mm_storeu_si128((__m128i *)(ptr + 88), xmm0);
                v9 = v5;
                v9 = -v9;
                v5 <<= 3;
                v5 = -v5;
                *(dst + v5 - 8) = v2;
                *(dst + v9*8 - 4) = i;
                v12 = 0x8000000000000000;
                a1 = (size_t *)v_20;
                dst = (__int64 *)v10;
                if (v4 == 0) {
                    result = (__int64 *)v_44;
                    if (a1[3] == result) {
                        v4 = ptr->field_278;
                        result = (__int64 *)v4;
                        result = (__int64 *)((__int64)(__int64)result << 17);
                        a1 = ptr->field_270;
                        a2 = ptr->field_280;
                        a2 = (struct Struct_1_t *)((__int64)(__int64)a2 ^ (__int64)a1);
                        v5 = ptr->field_288;
                        v5 ^= v4;
                        v6 = (__int64)a2;
                        v6 ^= v4;
                        ptr->field_278 = v6;
                        a1 = (size_t *)((__int64)(__int64)a1 ^ v5);
                        ptr->field_270 = a1;
                        a2 = (struct Struct_1_t *)((__int64)(__int64)a2 ^ (__int64)result);
                        ptr->field_280 = a2;
                        v5 = __ROL8__(v5, 45);
                        ptr->field_288 = v5;
                        v2 = ptr->field_78;
                        i = ptr->field_10;
                        if (i == ptr->field_0) {
                            sub_1400F3510(ptr, a2, v5, v6);
                        }
                        result = ptr->field_8;
                        *(result + i) = v2;
                        ++i;
                        ptr->field_10 = i;
                        result = ptr->field_0;
                        result -= i;
                        if (result <= 7) {
                            sub_1400F5F90(ptr, i, 8, v6);
                            i = ptr->field_10;
                        }
                        result = v4 + v4*4;
                        result = __ROL8__(result, 7);
                        result += (__int64)(__int64)result*8;
                        a1 = ptr->field_8;
                        *(a1 + i) = result;
                        result = i + 8;
                        ptr->field_10 = result;
                        v2 = ptr->field_F8;
                        if (result == ptr->field_0) {
                            sub_1400F3510(ptr);
                        }
                        result = ptr->field_8;
                        *(result + i + 8) = v2;
                        i += 9;
                        ptr->field_10 = i;
                        v4 = ptr->field_278;
                        result = (__int64 *)v4;
                        result = (__int64 *)((__int64)(__int64)result << 17);
                        a1 = ptr->field_270;
                        a2 = ptr->field_280;
                        a2 = (struct Struct_1_t *)((__int64)(__int64)a2 ^ (__int64)a1);
                        v5 = ptr->field_288;
                        v5 ^= v4;
                        v6 = (__int64)a2;
                        v6 ^= v4;
                        ptr->field_278 = v6;
                        a1 = (size_t *)((__int64)(__int64)a1 ^ v5);
                        ptr->field_270 = a1;
                        a2 = (struct Struct_1_t *)((__int64)(__int64)a2 ^ (__int64)result);
                        ptr->field_280 = a2;
                        v5 = __ROL8__(v5, 45);
                        ptr->field_288 = v5;
                        result = ptr->field_0;
                        result -= i;
                        if (result <= 7) {
                            sub_1400F5F90(ptr, i, 8);
                            i = ptr->field_10;
                        }
                        result = v4 + v4*4;
                        result = __ROL8__(result, 7);
                        result += (__int64)(__int64)result*8;
                        a1 = ptr->field_8;
                        *(a1 + i) = result;
                        i += 8;
                        ptr->field_10 = i;
                        a1 = (size_t *)v_20;
                    }
                }
                result = a1[2];
                while (result != 0) {
                    src = *(a1 + 8);
                    v9 = result + (__int64)(__int64)result*2;
                    v9 <<= 4;
                    v9 += (__int64)src;
                    i = src + 48;
                    result = *src;
                    a1 = (size_t *)result;
                    a1 = (size_t *)((__int64)(__int64)a1 ^ v12);
                    /* test result , result */;
                    result = 8;
                    if (0 /* unresolved: flags >= 0 */) a1 = result;
                    result = arg_0[(__int64)a1];
                    result = (__int64 *)((__int64)result + (__int64)dst);
                    JUMPOUT(result);
                    return (__int64)result;
                }
                a2 = a1[3];
                result = 2;
                return sub_1400F1034();
            }
            v5 = _mm_movemask_epi8(xmm1);
            if (v5 == 0) {
                a1 = 0;
                return (__int64)a1;
            }
            v5 = __builtin_ctz(v5);
            v5 += v6;
            v5 &= (__int64)a2;
            return (__int64)result;
        } while (true);
    }
}