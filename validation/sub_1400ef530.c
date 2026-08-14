// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[48];
    __int64 field_48; // offset 72
};

// inferred from 8 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[16];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
};

__int64 sub_1400F3B20();
__int64 sub_1400F3600();
__int64 sub_1400EF809();
extern __int64 off_14011D608;
extern __int64 off_14011D620;
extern __int64 off_14011D638;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400EF530(struct Struct_1_t *a1, int *a2) {
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    char *str;
    __int64 *result;
    __int64 v7;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 v4;
    __int64 v8;
    __m128i xmm0;
    __int64 v9;
    __int64 v6;
    __int64 v5;
    __m128i xmm1;
    int v12;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v11;
    __int64 v10;

    result = a2[3];
    v_38 = (__int64)result;
    result = a2[4];
    v_30 = (__int64)result;
    v7 = a2[5];
    if (v7 != 0) {
        if (a2[12] != 0) {
            v7 <<= 4;
            ptr = (struct Struct_2_t *)v_30;
            v7 += (__int64)ptr;
            v3 = a2[10];
            v4 = a2[9];
            result = *(a2 + 8);
            v_40 = (__int64)result;
            result = a2[2];
            v_28 = (__int64)result;
            v8 = 0xF1357AEA2E62A9C5;
            xmm0 = _mm_cmpeq_epi32(xmm0, xmm0);
            do {
                result = ptr->field_0;
                v9 = ptr->field_8;
                v6 = v9;
                v6 *= v8;
                v6 = __ROL8__(v6, 26);
                ptr += 16;
                v5 = v6;
                v5 >>= 57;
                xmm1 = _mm_cvtsi32_si128(v5);
                xmm1 = _mm_unpacklo_epi8(xmm1, xmm1);
                xmm1 = _mm_shufflelo_epi16(xmm1, 0);
                xmm1 = _mm_shuffle_epi32(xmm1, 68);
                v12 = 0;
                do {
                    v6 &= v3;
                    xmm2 = _mm_loadu_si128((__m128i *)(v4 + v6));
                    xmm3 = xmm2;
                    xmm3 = _mm_cmpeq_epi8(xmm3, xmm1);
                    v11 = _mm_movemask_epi8(xmm3);
                    xmm2 = _mm_cmpeq_epi8(xmm2, xmm0);
                    v5 = _mm_movemask_epi8(xmm2);
                    if (v5 == 0) {
                        v6 += (__int64)str;
                        v6 += 16;
                    }
                    a1 = &off_14011D608;
                    v4 = &off_14011D620;
                    sub_1400F3B20(a1, 22, v4);
                    v5 = &off_14011D638;
                    v4 = v_28;
                    sub_1400F3600(result, v6, v4, v5);
                    ptr = (struct Struct_2_t *)result;
                    if (*result != 0) {
                        v3 = ptr->field_8;
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, v3);
                    }
                    a1 = ptr->field_50;
                    if (a1 != 0) {
                        result =  + (__int64)(__int64)a1*8 + 23;
                        result = (__int64 *)((__int64)(__int64)result & -16);
                        a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)result);
                        if (a1 != -17) {
                            v3 = ptr->field_48;
                            v3 -= (__int64)result;
                            ((__int64 (*)())off_140108030)(a1);
                            ((__int64 (*)())off_140108038)(result, 0, v3);
                        }
                    }
                    if (ptr->field_18 != 0) {
                        v3 = ptr->field_20;
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, v3);
                    }
                    v3 = ptr->field_38;
                    v10 = ptr->field_40;
                    if (v10 == 0) JUMPOUT(0x1400ef83c);
                    v11 = v3 + 32;
                    v8 = off_140108030;
                    v9 = off_140108038;
                    return sub_1400EF809();
                } while (true);
            } while (ptr != v7);
            if (v_38 != 0) {
                ptr = (struct Struct_2_t *)a1;
                v3 = (__int64)a2;
                ((__int64 (*)())off_140108030)(a1, a2, v4, v5);
                ((__int64 (*)())off_140108038)(result, 0, v_30);
                a2 = (int *)v3;
                a1 = (struct Struct_1_t *)ptr;
            }
            result = a2[2];
            a1->field_10 = result;
            xmm0 = _mm_loadu_si128((__m128i *)a2);
            _mm_storeu_si128((__m128i *)a1, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(a2 + 72));
            xmm1 = _mm_loadu_si128((__m128i *)(a2 + 88));
            _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
            _mm_storeu_si128((__m128i *)(a1 + 40), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(a2 + 48));
            _mm_storeu_si128((__m128i *)(a1 + 56), xmm0);
            result = a2[8];
            a1->field_48 = result;
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}