// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[1];
    __int64 field_1; // offset 1
    int field_9; // offset 9
    __int16 field_D; // offset 13
    __int64 field_F; // offset 15
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[1];
    __int64 field_1; // offset 1
    int field_9; // offset 9
    __int16 field_D; // offset 13
    __int64 field_F; // offset 15
};

__int64 sub_14006EA36();
extern __int64 off_140108840;

__int64 __fastcall sub_14006E560(__int64 *a1, int a2, int a3, int a4) {
    __int64 rsp;
    int v_1;
    int v_10;
    int v_11;
    int v_12;
    int v_13;
    int v_14;
    int v_15;
    int v_16;
    int v_17;
    int v_18;
    int v_19;
    int v_1a;
    int v_1b;
    int v_1c;
    int v_1d;
    int v_1e;
    int v_1f;
    int v_2;
    int v_20;
    int v_3;
    int v_30;
    int v_4;
    int v_48;
    int v_5;
    int v_50;
    int v_58;
    int v_6;
    int v_60;
    int v_7;
    int v_70;
    int v_8;
    int v_9;
    int v_a;
    int v_b;
    int v_c;
    int v_d;
    int v_e;
    int v_f;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v2;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __m128i xmm3;
    __m128i xmm4;
    __m128i xmm5;
    int v7;
    __int64 i;
    __int64 v6;
    int v11;
    __int64 *i2;
    __int64 *i3;
    __int64 v5;

    v_50 = a2;
    result = a3;
    v_58 = a3;
    result &= 0xFFFFFFE0;
    v_48 = result;
    if (!((result == 0))) {
        xmm0 = _mm_loadu_si128((__m128i *)a1);
        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
        xmm0 = _mm_shufflelo_epi16(xmm0, 0);
        xmm0 = _mm_shuffle_epi32(xmm0, 68);
        xmm1 = xmm0;
        xmm1 = _mm_unpackhi_epi8(xmm1, xmm1);
        xmm2 = _mm_load_si128((__m128i *)&off_140108840);
        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
        v2 = v_48;
        ptr = (struct Struct_1_t *)v_50;
        do {
            ptr2 = ptr + 16;
            xmm3 = _mm_loadu_si128((__m128i *)ptr);
            _mm_store_si128((__m128i *)&v_20, xmm3);
            xmm4 = _mm_loadu_si128((__m128i *)(ptr + 16));
            _mm_store_si128((__m128i *)&v_30, xmm4);
            xmm5 = xmm3;
            xmm5 = _mm_unpackhi_epi8(xmm5, xmm5);
            /* pmullw %xmm1, %xmm5 */;
            xmm5 = _mm_and_si128(xmm5, xmm2);
            xmm3 = _mm_unpacklo_epi8(xmm3, xmm3);
            /* pmullw %xmm0, %xmm3 */;
            xmm3 = _mm_and_si128(xmm3, xmm2);
            /* packuswb %xmm5, %xmm3 */;
            _mm_store_si128((__m128i *)&v_10, xmm3);
            xmm5 = xmm4;
            xmm5 = _mm_unpackhi_epi8(xmm5, xmm5);
            /* pmullw %xmm1, %xmm5 */;
            xmm5 = _mm_and_si128(xmm5, xmm2);
            xmm4 = _mm_unpacklo_epi8(xmm4, xmm4);
            /* pmullw %xmm0, %xmm4 */;
            xmm4 = _mm_and_si128(xmm4, xmm2);
            /* packuswb %xmm5, %xmm4 */;
            _mm_store_si128((__m128i *)&*(__int64 *)rsp, xmm4);
            _mm_store_si128((__m128i *)&v_60, xmm3);
            v7 = v_60;
            _mm_store_si128((__m128i *)&v_70, xmm4);
            i = 1;
            v6 = 15;
            v11 = v_70;
            i2 = rsp + 17;
            i3 = rsp + 1;
            do {
                a2 = *(a1 + i);
                a4 = 0;
                do {
                    result = *(__int64 *)(rsp + a4 + 32);
                    result *= a2; /* unsigned; high half in a2 */;
                    *(i2 + a4) = *(i2 + a4) + result;
                    result = *(__int64 *)(rsp + a4 + 48);
                    result *= a2; /* unsigned; high half in a2 */;
                    *(i3 + a4) = *(i3 + a4) + result;
                    ++a4;
                } while (v6 != a4);
                v5 = 16;
                v5 -= i;
                result = *(__int64 *)(rsp + v5 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                a4 = result;
                result = *(__int64 *)(rsp + v5 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v5 = result;
                if (i == 1) {
                    ++i;
                    v7 -= a4;
                    v11 -= v5;
                    --v6;
                    ++i3;
                    ++i2;
                    v_10 = v7;
                    result = v_10;
                    *(__int64 *)ptr = (__int64)(result);
                    result = v_11;
                    ptr->field_1 = result;
                    result = v_19;
                    ptr->field_9 = result;
                    result = v_1d;
                    ptr->field_D = result;
                    result = v_1f;
                    ptr->field_F = result;
                    ptr += 32;
                    *(__int64 *)rsp = v11;
                    result = *(__int64 *)rsp;
                    *(__int64 *)ptr2 = (__int64)(result);
                    result = v_1;
                    ptr2->field_1 = result;
                    result = v_9;
                    ptr2->field_9 = result;
                    result = v_d;
                    ptr2->field_D = result;
                    result = v_f;
                    ptr2->field_F = result;
                    v2 -= 32;
                    if ((v_58 & 16) == 0) JUMPOUT(0x14006ebcf);
                    ptr = (struct Struct_1_t *)v_50;
                    ptr += v_48;
                    xmm0 = _mm_loadu_si128((__m128i *)ptr);
                    _mm_store_si128((__m128i *)&v_10, xmm0);
                    xmm1 = _mm_loadu_si128((__m128i *)a1);
                    xmm1 = _mm_unpacklo_epi8(xmm1, xmm1);
                    xmm1 = _mm_shufflelo_epi16(xmm1, 0);
                    xmm1 = _mm_shuffle_epi32(xmm1, 68);
                    xmm2 = xmm0;
                    xmm2 = _mm_unpackhi_epi8(xmm2, xmm2);
                    /* pmullw %xmm1, %xmm2 */;
                    xmm3 = _mm_load_si128((__m128i *)&off_140108840);
                    xmm2 = _mm_and_si128(xmm2, xmm3);
                    xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                    /* pmullw %xmm1, %xmm0 */;
                    xmm0 = _mm_and_si128(xmm0, xmm3);
                    /* packuswb %xmm2, %xmm0 */;
                    _mm_store_si128((__m128i *)&*(__int64 *)rsp, xmm0);
                    a2 = 1;
                    a3 = 15;
                    a4 = rsp + 2;
                    v5 = 0;
                    return sub_14006EA36();
                }
                a3 = 17;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_11 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_1 -= result;
                if (i == 2) {
                    return v_1;
                }
                a3 = 18;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_12 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_2 -= result;
                if (i == 3) {
                    return v_2;
                }
                a3 = 19;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_13 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_3 -= result;
                if (i == 4) {
                    return v_3;
                }
                a3 = 20;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_14 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_4 -= result;
                if (i == 5) {
                    return v_4;
                }
                a3 = 21;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_15 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_5 -= result;
                if (i == 6) {
                    return v_5;
                }
                a3 = 22;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_16 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_6 -= result;
                if (i == 7) {
                    return v_6;
                }
                a3 = 23;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_17 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_7 -= result;
                if (i == 8) {
                    return v_7;
                }
                a3 = 24;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_18 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_8 -= result;
                if (i == 9) {
                    return v_8;
                }
                a3 = 25;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_19 -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_9 -= result;
                if (i == 10) {
                    return v_9;
                }
                a3 = 26;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_1a -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_a -= result;
                if (i == 11) {
                    return v_a;
                }
                a3 = 27;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_1b -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_b -= result;
                if (i == 12) {
                    return v_b;
                }
                a3 = 28;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_1c -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_c -= result;
                if (i == 13) {
                    return v_c;
                }
                a3 = 29;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_1d -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_d -= result;
                if (i == 14) {
                    return v_d;
                }
                a3 = 30;
                a3 -= i;
                result = *(__int64 *)(rsp + a3 + 32);
                result *= a2; /* unsigned; high half in a2 */;
                v_1e -= result;
                result = *(__int64 *)(rsp + a3 + 48);
                result *= a2; /* unsigned; high half in a2 */;
                v_e -= result;
                return v_e;
            } while (i != 16);
            return v_e;
        } while (!((v2 == 0)));
    }
    return result;
}