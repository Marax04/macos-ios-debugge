// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[144];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 sub_1400548B0();
__int64 sub_1400F27F0();
extern __int64 off_140108660;
extern __int64 off_140108670;

__int64 __fastcall sub_140057260(__int64 a1, __int64 a2, int *a3) {
    __int64 rsp;
    int v_27;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_90;
    int v_98;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    struct Struct_3_t *ptr3;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v9;
    __int64 result;
    __int64 v5;
    __int64 v11;
    __int64 v7;
    __int64 v6;
    __m128i xmm6;
    __int64 v10;
    __int64 v4;
    __m128i xmm7;
    __m128i xmm8;

    _mm_store_si128((__m128i *)&v_d0, xmm8);
    _mm_store_si128((__m128i *)&v_c0, xmm7);
    _mm_store_si128((__m128i *)&v_b0, xmm6);
    ptr = (struct Struct_1_t *)a3;
    ptr2 = (struct Struct_2_t *)a2;
    ptr3 = (struct Struct_3_t *)a1;
    a2 = *(a3 + 8);
    a3 = a3[2];
    xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + 56));
    xmm1 = _mm_shuffle_epi32(xmm0, 68);
    xmm1 = _mm_xor_si128(xmm1, _mm_load_si128((__m128i *)&off_140108660));
    _mm_store_si128((__m128i *)&v_60, xmm1);
    xmm1 = _mm_shuffle_epi32(xmm0, 238);
    xmm1 = _mm_xor_si128(xmm1, _mm_load_si128((__m128i *)&off_140108670));
    _mm_store_si128((__m128i *)&v_70, xmm1);
    _mm_store_si128((__m128i *)&v_80, xmm0);
    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&v_90, xmm0);
    v_a0 = 0;
    v9 = rsp + 96;
    sub_1400548B0(v9, a2, a3);
    v_27 = 255;
    a2 = rsp + 39;
    sub_1400548B0(v9, a2, 1);
    result = v_70;
    v5 = v_90;
    v5 <<= 56;
    v5 |= v_98;
    a1 = v_78;
    a1 ^= v5;
    a3 = (int *)v_60;
    a3 += result;
    a2 = v_68;
    a2 += a1;
    result = __ROL8__(result, 13);
    result ^= (__int64)a3;
    a1 = __ROL8__(a1, 16);
    a3 = __ROL8__(a3, 32);
    a1 ^= a2;
    a2 += result;
    result = __ROL8__(result, 17);
    a3 += a1;
    result ^= a2;
    a1 = __ROL8__(a1, 21);
    a1 ^= (__int64)a3;
    a2 = __ROL8__(a2, 32);
    a3 = (int *)((__int64)(__int64)a3 ^ v5);
    a2 ^= 255;
    a3 += result;
    result = __ROL8__(result, 13);
    a2 += a1;
    result ^= (__int64)a3;
    a1 = __ROL8__(a1, 16);
    a1 ^= a2;
    a3 = __ROL8__(a3, 32);
    a2 += result;
    a3 += a1;
    result = __ROL8__(result, 17);
    result ^= a2;
    a1 = __ROL8__(a1, 21);
    a2 = __ROL8__(a2, 32);
    a1 ^= (__int64)a3;
    a3 += result;
    result = __ROL8__(result, 13);
    a2 += a1;
    result ^= (__int64)a3;
    a1 = __ROL8__(a1, 16);
    a1 ^= a2;
    a3 = __ROL8__(a3, 32);
    a2 += result;
    a3 += a1;
    result = __ROL8__(result, 17);
    result ^= a2;
    a1 = __ROL8__(a1, 21);
    a2 = __ROL8__(a2, 32);
    a1 ^= (__int64)a3;
    a3 += result;
    result = __ROL8__(result, 13);
    a2 += a1;
    result ^= (__int64)a3;
    a1 = __ROL8__(a1, 16);
    a1 ^= a2;
    a2 += result;
    result = __ROL8__(result, 17);
    a1 = __ROL8__(a1, 21);
    v11 = a2;
    v11 = __ROL8__(v11, 32);
    v11 ^= result;
    v11 ^= a1;
    v11 ^= a2;
    v7 = ptr2->field_8;
    a2 = ptr2->field_10;
    result = v11;
    result >>= 57;
    v6 = ptr2->field_20;
    v5 = ptr2->field_18;
    xmm0 = _mm_cvtsi32_si128(result);
    xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
    xmm0 = _mm_shufflelo_epi16(xmm0, 0);
    xmm6 = _mm_shuffle_epi32(xmm0, 68);
    a1 = ptr->field_8;
    v10 = ptr->field_10;
    v4 = 0;
    xmm7 = _mm_cmpeq_epi32(xmm7, xmm7);
    v9 = v11;
    do {
        v9 &= v6;
        xmm8 = _mm_loadu_si128((__m128i *)(v5 + v9));
        xmm0 = xmm8;
        xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
        result = _mm_movemask_epi8(xmm0);
        xmm8 = _mm_cmpeq_epi8(xmm8, xmm7);
        result = _mm_movemask_epi8(xmm8);
        if (result == 0) {
            v9 += v4;
            v9 += 16;
            v4 += 16;
        }
        sub_1400F27F0(ptr3, ptr, 144, v5);
        ptr3->field_90 = ptr2;
        ptr3->field_98 = v11;
        xmm6 = _mm_load_si128((__m128i *)&v_b0);
        xmm7 = _mm_load_si128((__m128i *)&v_c0);
        xmm8 = _mm_load_si128((__m128i *)&v_d0);
        return result;
    } while (true);
}