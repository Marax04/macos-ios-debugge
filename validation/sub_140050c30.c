// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 7 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[32];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140011760();
__int64 sub_1400F3B20();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_140051448();
__int64 sub_1400F27F0();
__int64 sub_1400F37A0();
__int64 sub_1400F3600();
__int64 sub_1400518EB();
__int64 sub_1400F5F90();
__int64 sub_1400F3360();
__int64 sub_140017B60();
__int64 sub_140011BE0();
__int64 sub_1400513BD();
__int64 sub_1400513B8();
__int64 sub_1400513A7();
__int64 sub_1400513C0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14000C620;
extern __int64 off_140116170;
extern __int64 off_140115F58;
extern __int64 off_140116000;
extern __int64 off_14011AF40;
extern __int64 off_140116018;
extern __int64 off_140116720;
extern __int64 off_140116708;
extern __int64 off_1401161C8;
extern __int64 off_1401086A0;
extern __int64 off_140108580;
extern __int64 off_140108570;

__int64 __fastcall sub_140050C30(int *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int arg_2;
    int arg_4;
    int arg_6;
    int arg_8;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    __int64 v_80;
    int v_88;
    int v_90;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    __int64 v_c0;
    int v_e0;
    struct Struct_2_t *ptr;
    __int64 result;
    __int64 v4;
    __int64 v8;
    __int64 i;
    __int64 v12;
    struct Struct_3_t *ptr2;
    __int64 i2;
    __int64 v10;
    __int64 v11;
    __m128i xmm0;
    __int64 v6;
    __m128i xmm2;
    __m128i xmm3;
    __m128i xmm1;
    int v7;
    __m128i xmm4;
    __m128i xmm5;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_e0, xmm6);
    ptr = (struct Struct_2_t *)a1;
    result = a2->field_0;
    v_28 = result;
    result = a2->field_8;
    v_30 = result;
    if (*a1 != 1) {
        v4 = 0;
    } else {
        v4 = 0;
        if (__OFSUB(v4, ptr->field_48)) {
            result = ptr + 24;
            v_80 = result;
            result = &off_14000C620;
            v_88 = result;
            result = &off_140116170;
            v_38 = result;
            v_40 = 2;
            v_58 = 0;
            v8 = rsp + 128;
            v_48 = v8;
            v_50 = 1;
            i = rsp + 56;
            a1 = (int *)v_28;
            a2 = (struct Struct_1_t *)v_30;
            sub_140011760(a1, a2, i, v6);
            v12 = result;
            v4 |= result;
            if ((v4 != 0)) JUMPOUT(0x1400518eb);
            v4 = ptr->field_40;
            if (v4 != 0) {
                ptr2 = ptr->field_38;
                a1 =  + v4*8;
                result = a1 + (__int64)(__int64)a1*2;
                v12 = a1 + (__int64)(__int64)a1*2;
                v12 -= 24;
                a1 = (int *)v12;
                a1 = (int *)((__int64)(__int64)a1 >> 3);
                ptr = 0xAAAAAAAAAAAAAAAB;
                ptr = (struct Struct_2_t *)((__int64)(__int64)(__int64)ptr * (__int64)a1);
                a1 = (int *)ptr2;
                while (result != 0) {
                    result -= 24;
                    ptr += a1[2];
                    a1 += 24;
                    a1 = &off_140115F58;
                    i = &off_140116000;
                    sub_1400F3B20(a1, 53, i);
                }
                if (ptr >= 0) {
                    if ((0 /* unresolved: flags == */)) {
                        result = 1;
                    } else {
                        sub_14002EDF0(0, ptr);
                        if (result == 0) {
                            sub_1400F3326(1, ptr);
                            v_a8 = 1;
                            result = v6 + 1;
                            v_b0 = result;
                            i = 20;
                            v12 = 0;
                            i2 = v6;
                            return sub_140051448();
                        }
                    }
                    v_80 = (__int64)ptr;
                    v_88 = result;
                    v_90 = 0;
                    a2 = ptr2->field_8;
                    v10 = ptr2->field_10;
                    if (v10 <= ptr) {
                        i2 = 0;
                        v11 = result;
                        a1 = result + i2;
                        sub_1400F27F0(a1, a2, v10);
                        i2 += v10;
                        v10 = (__int64)ptr;
                        v10 -= i2;
                        if (v4 != 1) {
                            a1 = (int *)v11;
                            a1 += i2;
                            v4 = 0;
                            while (v10 != 0) {
                                a2 = *(__int64 *)(ptr2 + v4 + 32);
                                i = *(__int64 *)(ptr2 + v4 + 40);
                                --v10;
                                *a1 = 46;
                                v10 -= i;
                                if ((v10 < 0)) {
                                    result = &off_14011AF40;
                                    v_38 = result;
                                    v_40 = 1;
                                    v_48 = 8;
                                    xmm0 = _mm_setzero_si128();
                                    _mm_storeu_si128((__m128i *)&v_50, xmm0);
                                    a2 = &off_140116018;
                                    a1 = rsp + 56;
                                    sub_1400F37A0(a1, a2, i);
                                    v6 = &off_140116720;
                                    sub_1400F3600(0, v8, v10, v6);
                                    v6 = &off_140116708;
                                    sub_1400F3600(v8, i, v10, v6);
                                }
                                i2 = a1 + i;
                                ++i2;
                                ++a1;
                                sub_1400F27F0(a1, a2, i);
                                v4 += 24;
                                a1 = (int *)i2;
                                ptr -= v10;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_80);
                                _mm_store_si128((__m128i *)&v_b0, xmm0);
                                v_c0 = (__int64)ptr;
                                result = rsp + 176;
                                v_80 = result;
                                result = &off_14000C620;
                                v_88 = result;
                                result = &off_1401161C8;
                                v_38 = result;
                                v_40 = 2;
                                v_58 = 0;
                                v_48 = v8;
                                v_50 = 1;
                                i = rsp + 56;
                                a1 = (int *)v_28;
                                a2 = (struct Struct_1_t *)v_30;
                                sub_140011760(a1, a2, i);
                                v12 = result;
                                if (v_b0 == 0) JUMPOUT(0x1400518eb);
                                i2 = v_b8;
                                off_140108030();
                                off_140108038(result, 0, i2);
                                return sub_1400518EB();
                            }
                            return i2;
                        }
                        return i2;
                    }
                    do {
                        a1 = rsp + 128;
                        i2 = (__int64)a2;
                        sub_1400F5F90(a1, 0, v10);
                        a2 = (struct Struct_1_t *)i2;
                        result = v_88;
                        i2 = v_90;
                        return i2;
                    } while (true);
                } else {
                    sub_1400F3360();
                }
            }
            v12 = 0;
            return sub_1400518EB();
        } else {
            v6 = ptr->field_8;
            v4 = ptr->field_10;
            ptr2 = ptr->field_50;
            v10 = ptr->field_58;
            v_a0 = v6;
            if (v10 == 0) {
                return v_a0;
            } else {
                v11 = v10 - 1;
                if (v11 >= v6) v11 = v6;
                i2 = v6;
                i2 -= v11;
                a2 = v11 + 1;
                a1 = -1;
                while (a2 != 1) {
                    result = a2 - 1;
                    ++a1;
                    /* cmp *((__int64)ptr2 + (__int64)a2 - 2) , 10 */;
                    a2 = (struct Struct_1_t *)result;
                    v8 = v11;
                    v8 -= (__int64)a1;
                    if (v8 <= v10) {
                        a2 = v8 + ptr2;
                        if (v8 == 0) {
                            i = v11 + 1;
                            v12 = 0;
                            v8 = 0;
                        } else {
                            if (v8 >= 4) {
                                a1 = (int *)v8;
                                a1 = (int *)((__int64)(__int64)a1 & -4);
                                i = result;
                                i &= -4;
                                xmm0 = _mm_setzero_si128();
                                v6 = 0;
                                xmm2 = _mm_load_si128((__m128i *)&off_1401086A0);
                                xmm3 = _mm_load_si128((__m128i *)&off_140108580);
                                xmm1 = _mm_setzero_si128();
                                for (; i != v6; v6 += 4) {
                                    v7 = *(__int64 *)(ptr2 + v6);
                                    xmm4 = _mm_cvtsi32_si128(v7);
                                    v7 = *(__int64 *)(ptr2 + v6 + 2);
                                    xmm5 = _mm_cvtsi32_si128(v7);
                                    xmm4 = _mm_cmpeq_epi8(xmm4, xmm2);
                                    xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
                                    xmm4 = _mm_shufflelo_epi16(xmm4, 212);
                                    xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                    xmm4 = _mm_and_si128(xmm4, xmm3);
                                    xmm0 = _mm_add_epi64(xmm0, xmm4);
                                    xmm5 = _mm_cmpeq_epi8(xmm5, xmm2);
                                    xmm5 = _mm_unpacklo_epi8(xmm5, xmm5);
                                    xmm4 = _mm_shufflelo_epi16(xmm5, 212);
                                    xmm4 = _mm_shuffle_epi32(xmm4, 212);
                                    xmm4 = _mm_and_si128(xmm4, xmm3);
                                    xmm1 = _mm_add_epi64(xmm1, xmm4);
                                }
                                xmm1 = _mm_add_epi64(xmm1, xmm0);
                                xmm0 = _mm_shuffle_epi32(xmm1, 238);
                                xmm0 = _mm_add_epi64(xmm0, xmm1);
                                v12 = _mm_cvtsi128_si64(xmm0);
                                if (v8 != a1) {
                                    result -= (__int64)a1;
                                    a1 = (int *)((__int64)a1 + (__int64)ptr2);
                                    for (i = 0; result != i; ++i) {
                                        v6 = 0;
                                        v6 = (*(a1 + i) == 10) ? 1 : 0;
                                        v12 += v6;
                                    }
                                }
                            } else {
                                a1 = 0;
                                v12 = 0;
                                return v12;
                            }
                            i = v11 + 1;
                            if (i < v8) {
                                return i;
                            }
                        }
                        i -= v8;
                        a1 = rsp + 56;
                        sub_140017B60(a1, a2, i, v6);
                        if (v_38 != 1) {
                            a1 = (int *)v_40;
                            a2 = (struct Struct_1_t *)v_48;
                            if (a2 >= 32) {
                                sub_140011BE0(a1, a2);
                                v11 = result;
                                return sub_1400513BD();
                            } else {
                                if (a2 == 0) {
                                    v11 = 0;
                                    return sub_1400513BD();
                                } else {
                                    if (a2 >= 4) {
                                        result = (__int64)a2;
                                        result &= 28;
                                        i = *a1;
                                        xmm0 = _mm_cvtsi32_si128(i);
                                        i = arg_2;
                                        xmm1 = _mm_cvtsi32_si128(i);
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
                                            i = arg_4;
                                            xmm4 = _mm_cvtsi32_si128(i);
                                            i = arg_6;
                                            xmm5 = _mm_cvtsi32_si128(i);
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
                                                i = arg_8;
                                                xmm4 = _mm_cvtsi32_si128(i);
                                                i = a1[1];
                                                xmm5 = _mm_cvtsi32_si128(i);
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
                                                    i = a1[1];
                                                    xmm4 = _mm_cvtsi32_si128(i);
                                                    i = a1[1];
                                                    xmm5 = _mm_cvtsi32_si128(i);
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
                                                        i = a1[2];
                                                        xmm4 = _mm_cvtsi32_si128(i);
                                                        i = a1[2];
                                                        xmm5 = _mm_cvtsi32_si128(i);
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
                                                            i = a1[2];
                                                            xmm4 = _mm_cvtsi32_si128(i);
                                                            i = a1[2];
                                                            xmm5 = _mm_cvtsi32_si128(i);
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
                                                                i = a1[3];
                                                                xmm4 = _mm_cvtsi32_si128(i);
                                                                i = a1[3];
                                                                xmm5 = _mm_cvtsi32_si128(i);
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
                                        v11 = _mm_cvtsi128_si64(xmm1);
                                        return sub_1400513B8();
                                    } else {
                                        result = 0;
                                        v11 = 0;
                                        return sub_1400513A7();
                                    }
                                }
                            }
                        } else {
                            v11 -= v8;
                            return sub_1400513C0();
                        }
                    }
                    return v11;
                }
                a2 = (struct Struct_1_t *)ptr2;
                return (__int64)a2;
            }
        }
        return (__int64)a2;
    }
    return result;
}