// [crypto] ChaCha20 sigma constants
// inferred from 3 accesses on `a1`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a2`
struct Struct_2_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_14006B5E0(struct Struct_1_t *a1,struct Struct_2_t *a2, int *a3, size_t a4) {
    __int64 rsp;
    int v_10;
    int v_14;
    int v_18;
    int v_1c;
    int v_20;
    int v_24;
    int v_28;
    int v_2c;
    int v_30;
    int v_34;
    int v_38;
    int v_3c;
    int v_40;
    int v_44;
    int v_48;
    int v_50;
    int v_54;
    int v_58;
    int v_5c;
    int v_60;
    int v_64;
    int v_68;
    int v_6c;
    int v_70;
    int v_74;
    int v_78;
    int v_7c;
    int v_8;
    int v_80;
    int v_84;
    int v_88;
    int v_8c;
    int v_98;
    int v_a0;
    int v_c;
    __int64 result;
    int v7;
    int v2;
    __int64 i;
    int v6;
    int v3;
    int v8;
    int v9;
    int v10;
    int v5;
    int v11;
    __m128i xmm0;
    __m128i xmm1;

    if (a4 != 0) {
        result = a1->field_0;
        v_34 = result;
        result = a1->field_4;
        v_30 = result;
        result = a1->field_8;
        v_2c = result;
        result = ((__int64 *)a1)[1];
        v_28 = result;
        v7 = ((__int64 *)a1)[2];
        result = ((__int64 *)a1)[2];
        v_24 = result;
        result = ((__int64 *)a1)[3];
        v_20 = result;
        result = ((__int64 *)a1)[3];
        v_1c = result;
        v2 = a2->field_0;
        result = a2->field_4;
        v_18 = result;
        result = a2->field_8;
        v_14 = result;
        i = 0;
        v_3c = v7;
        v_38 = v2;
        do {
            v_48 = (int)a3;
            v_a0 = a4;
            v_10 = 0x6B206574;
            v_8 = 0x79622D32;
            v6 = 0x3320646E;
            v3 = 0x61707865;
            v_40 = 10;
            result = v_34;
            v_98 = i;
            v8 = i;
            v_c = v7;
            v7 = v_30;
            v9 = v2;
            v2 = v_24;
            a4 = v_2c;
            v10 = v_18;
            a1 = (struct Struct_1_t *)v_20;
            a3 = (int *)v_28;
            a2 = (struct Struct_2_t *)v_14;
            v5 = v_1c;
            do {
                v3 += result;
                v8 ^= v3;
                v8 = __ROL4__(v8, 16);
                v11 = v_c;
                v11 += v8;
                result ^= v11;
                result = __ROL4__(result, 12);
                v3 += result;
                v8 ^= v3;
                v8 = __ROL4__(v8, 8);
                v11 += v8;
                result ^= v11;
                result = __ROL4__(result, 7);
                v6 += v7;
                v9 ^= v6;
                v9 = __ROL4__(v9, 16);
                v2 += v9;
                v7 ^= v2;
                v7 = __ROL4__(v7, 12);
                v6 += v7;
                v9 ^= v6;
                v9 = __ROL4__(v9, 8);
                v2 += v9;
                v_44 = v2;
                v7 ^= v2;
                v7 = __ROL4__(v7, 7);
                v2 = v_8;
                v2 += a4;
                v10 ^= v2;
                v10 = __ROL4__(v10, 16);
                a1 += v10;
                a4 ^= (__int64)a1;
                a4 = __ROL4__(a4, 12);
                v2 += a4;
                v10 ^= v2;
                v10 = __ROL4__(v10, 8);
                a1 += v10;
                a4 ^= (__int64)a1;
                a4 = __ROL4__(a4, 7);
                i = v_10;
                i += (__int64)a3;
                a2 = (struct Struct_2_t *)((__int64)(__int64)a2 ^ i);
                a2 = __ROL4__(a2, 16);
                v5 += (__int64)a2;
                a3 = (int *)((__int64)(__int64)a3 ^ v5);
                a3 = __ROL4__(a3, 12);
                i += (__int64)a3;
                a2 = (struct Struct_2_t *)((__int64)(__int64)a2 ^ i);
                a2 = __ROL4__(a2, 8);
                v5 += (__int64)a2;
                a3 = (int *)((__int64)(__int64)a3 ^ v5);
                a3 = __ROL4__(a3, 7);
                v3 += v7;
                a2 = (struct Struct_2_t *)((__int64)(__int64)a2 ^ v3);
                a2 = __ROL4__(a2, 16);
                a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)a2);
                v7 ^= (__int64)a1;
                v7 = __ROL4__(v7, 12);
                v3 += v7;
                a2 = (struct Struct_2_t *)((__int64)(__int64)a2 ^ v3);
                a2 = __ROL4__(a2, 8);
                a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)a2);
                v7 ^= (__int64)a1;
                v7 = __ROL4__(v7, 7);
                v6 += a4;
                v8 ^= v6;
                v8 = __ROL4__(v8, 16);
                v5 += v8;
                a4 ^= v5;
                a4 = __ROL4__(a4, 12);
                v6 += a4;
                v8 ^= v6;
                v8 = __ROL4__(v8, 8);
                v5 += v8;
                a4 ^= v5;
                a4 = __ROL4__(a4, 7);
                v2 += (__int64)a3;
                v9 ^= v2;
                v9 = __ROL4__(v9, 16);
                v11 += v9;
                a3 = (int *)((__int64)(__int64)a3 ^ v11);
                a3 = __ROL4__(a3, 12);
                v2 += (__int64)a3;
                v_8 = v2;
                v9 ^= v2;
                v2 = v_44;
                v9 = __ROL4__(v9, 8);
                v11 += v9;
                v_c = v11;
                a3 = (int *)((__int64)(__int64)a3 ^ v11);
                a3 = __ROL4__(a3, 7);
                i += result;
                v10 ^= i;
                v10 = __ROL4__(v10, 16);
                v2 += v10;
                result ^= v2;
                result = __ROL4__(result, 12);
                i += result;
                v_10 = i;
                v10 ^= i;
                v10 = __ROL4__(v10, 8);
                v2 += v10;
                result ^= v2;
                result = __ROL4__(result, 7);
                --v_40;
            } while ((v_40 != 0));
            v3 += 0x61707865;
            v_50 = v3;
            v6 += 0x3320646E;
            v_54 = v6;
            v6 = v_8;
            v6 += 0x79622D32;
            v_58 = v6;
            v6 = v_10;
            v6 += 0x6B206574;
            v_5c = v6;
            result += v_34;
            v_60 = result;
            v7 += v_30;
            v_64 = v7;
            a4 += v_2c;
            v_68 = a4;
            a3 += v_28;
            v_6c = (int)a3;
            v7 = v_3c;
            result = v_c;
            result += v7;
            v_70 = result;
            v2 += v_24;
            v_74 = v2;
            a1 += v_20;
            v_78 = (int)a1;
            v5 += v_1c;
            v_7c = v5;
            i = v_98;
            v8 += i;
            v_80 = v8;
            v2 = v_38;
            v9 += v2;
            v_84 = v9;
            v10 += v_18;
            v_88 = v10;
            a2 += v_14;
            v_8c = (int)a2;
            a4 = v_a0;
            result = 64;
            if (a4 < 64) result = a4;
            if (a4 >= 4) {
                a3 = (int *)v_48;
                if (a4 >= 32) {
                    a1 = (struct Struct_1_t *)result;
                    xmm0 = _mm_loadu_si128((__m128i *)a3);
                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
                    xmm0 = _mm_xor_si128(xmm0, v_50);
                    xmm1 = _mm_xor_si128(xmm1, v_60);
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 96);
                    _mm_storeu_si128((__m128i *)a3, xmm0);
                    _mm_storeu_si128((__m128i *)(a3 + 16), xmm1);
                    if (a1 == 32) {
                        if (result == a1) {
                            a3 += result;
                            ++i;
                            a4 -= result;
                            return a4;
                        }
                        if ((result & 28) == 0) {
                            do {
                                a2 = *(__int64 *)(rsp + a1 + 80);
                                *(__int64 *)((__int64)a3 + (__int64)a1) = *(__int64 *)((__int64)a3 + (__int64)a1) ^ (__int64)a2;
                                ++a1;
                                return (__int64)a1;
                            } while (result != a1);
                        }
                        a2 = (struct Struct_2_t *)a1;
                        a1 = (struct Struct_1_t *)result;
                        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 124);
                        do {
                            v5 = *(__int64 *)(rsp + a2 + 80);
                            *(__int64 *)((__int64)a3 + (__int64)a2) = *(__int64 *)((__int64)a3 + (__int64)a2) ^ v5;
                            a2 += 4;
                        } while (a1 != a2);
                        return (__int64)a2;
                    }
                    xmm0 = _mm_loadu_si128((__m128i *)(a3 + 32));
                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 48));
                    xmm0 = _mm_xor_si128(xmm0, v_70);
                    xmm1 = _mm_xor_si128(xmm1, v_80);
                    _mm_storeu_si128((__m128i *)(a3 + 32), xmm0);
                    _mm_storeu_si128((__m128i *)(a3 + 48), xmm1);
                    return _mm_cvtsi128_si64(xmm1);
                }
                a1 = 0;
                return (__int64)a1;
            }
            a1 = 0;
            a3 = (int *)v_48;
            return (__int64)a3;
        } while (!((a4 == 0)));
    }
    return result;
}