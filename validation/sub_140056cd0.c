// inferred from 17 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F27F0();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400548B0();
extern __int64 off_140108660;
extern __int64 off_140108670;

__int64 __fastcall sub_140056CD0(int *a1, __int64 *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_28;
    int arg_30;
    int arg_38;
    int arg_40;
    int arg_48;
    int arg_50;
    int arg_58;
    int arg_60;
    int arg_68;
    int arg_70;
    int arg_78;
    int arg_8;
    int arg_80;
    int arg_88;
    int v_27;
    int v_28;
    __int64 v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
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
    __int64 v4;
    __int64 v11;
    struct Struct_1_t *ptr;
    __int64 v12;
    __int64 v10;
    __int64 result;
    __int64 v13;
    __int64 v6;
    __int64 v8;
    __int64 v2;
    __int64 v9;
    struct Struct_2_t *ptr2;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v7;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm8;

    v4 = a2[2];
    if (v4 >= 0) {
        do {
            v11 = (__int64)a2;
            ptr = (struct Struct_1_t *)a1;
            v12 = arg_8;
            v10 = 1;
            sub_1400F27F0(v10, v12, v4);
            result = arg_18;
            v13 = 0x8000000000000003;
            v6 = v13;
            if (result == v13) {
                result = arg_30;
                v8 = v13;
                if (result == v13) {
                    result = arg_48;
                    v12 = v13;
                    if (result != v13) {
                        v12 = 0x8000000000000000;
                        a1 = (int *)result;
                        a1 = (int *)((__int64)(__int64)a1 ^ v12);
                        /* test result , result */;
                        result = 1;
                        if (0 /* unresolved: flags < 0 */) result = a1;
                        if (result == 0) {
                            result = arg_60;
                            v2 = v13;
                            if (result == v13) {
                                result = arg_78;
                                if (result != v13) {
                                    v13 = 0x8000000000000000;
                                    a1 = (int *)result;
                                    a1 = (int *)((__int64)(__int64)a1 ^ v13);
                                    /* test result , result */;
                                    result = 1;
                                    if (0 /* unresolved: flags < 0 */) result = a1;
                                    if (result != 0) {
                                        if (result != 2) {
                                            v9 = arg_88;
                                            if (v9 < 0) {
                                                sub_1400F3360();
                                            }
                                            v_38 = v8;
                                            v_40 = v7;
                                            v_28 = v6;
                                            v_30 = (__int64)ptr2;
                                            v_60 = (int)a2;
                                            v11 = arg_80;
                                            if ((v11 == 0)) {
                                                v13 = 1;
                                            } else {
                                                sub_14002EDF0(0, v9);
                                                if (result == 0) {
                                                    sub_1400F3326(1, v9);
                                                    _mm_store_si128((__m128i *)&v_d0, xmm8);
                                                    _mm_store_si128((__m128i *)&v_c0, xmm7);
                                                    _mm_store_si128((__m128i *)&v_b0, xmm6);
                                                    v2 = (__int64)ptr2;
                                                    ptr = (struct Struct_1_t *)a2;
                                                    v9 = (__int64)a1;
                                                    a2 = ptr2->field_8;
                                                    ptr2 = ptr2->field_10;
                                                    xmm0 = _mm_loadu_si128((__m128i *)(ptr + 56));
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
                                                    v11 = rsp + 96;
                                                    sub_1400548B0(v11, a2, ptr2);
                                                    v_27 = 255;
                                                    a2 = rsp + 39;
                                                    sub_1400548B0(v11, a2, 1);
                                                    result = v_70;
                                                    v6 = v_90;
                                                    v6 <<= 56;
                                                    v6 |= v_98;
                                                    a1 = (int *)v_78;
                                                    a1 = (int *)((__int64)(__int64)a1 ^ v6);
                                                    ptr2 = (struct Struct_2_t *)v_60;
                                                    ptr2 += result;
                                                    a2 = (__int64 *)v_68;
                                                    a2 = (__int64 *)((__int64)a2 + (__int64)a1);
                                                    result = __ROL8__(result, 13);
                                                    result ^= (__int64)ptr2;
                                                    a1 = __ROL8__(a1, 16);
                                                    ptr2 = __ROL8__(ptr2, 32);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                    a2 += result;
                                                    result = __ROL8__(result, 17);
                                                    ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)a1);
                                                    result ^= (__int64)a2;
                                                    a1 = __ROL8__(a1, 21);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)ptr2);
                                                    a2 = __ROL8__(a2, 32);
                                                    ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 ^ v6);
                                                    a2 = (__int64 *)((__int64)(__int64)a2 ^ 255);
                                                    ptr2 += result;
                                                    result = __ROL8__(result, 13);
                                                    a2 = (__int64 *)((__int64)a2 + (__int64)a1);
                                                    result ^= (__int64)ptr2;
                                                    a1 = __ROL8__(a1, 16);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                    ptr2 = __ROL8__(ptr2, 32);
                                                    a2 += result;
                                                    ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)a1);
                                                    result = __ROL8__(result, 17);
                                                    result ^= (__int64)a2;
                                                    a1 = __ROL8__(a1, 21);
                                                    a2 = __ROL8__(a2, 32);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)ptr2);
                                                    ptr2 += result;
                                                    result = __ROL8__(result, 13);
                                                    a2 = (__int64 *)((__int64)a2 + (__int64)a1);
                                                    result ^= (__int64)ptr2;
                                                    a1 = __ROL8__(a1, 16);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                    ptr2 = __ROL8__(ptr2, 32);
                                                    a2 += result;
                                                    ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)a1);
                                                    result = __ROL8__(result, 17);
                                                    result ^= (__int64)a2;
                                                    a1 = __ROL8__(a1, 21);
                                                    a2 = __ROL8__(a2, 32);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)ptr2);
                                                    ptr2 += result;
                                                    result = __ROL8__(result, 13);
                                                    a2 = (__int64 *)((__int64)a2 + (__int64)a1);
                                                    result ^= (__int64)ptr2;
                                                    a1 = __ROL8__(a1, 16);
                                                    a1 = (int *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                    a2 += result;
                                                    result = __ROL8__(result, 17);
                                                    a1 = __ROL8__(a1, 21);
                                                    v13 = (__int64)a2;
                                                    v13 = __ROL8__(v13, 32);
                                                    v13 ^= result;
                                                    v13 ^= (__int64)a1;
                                                    v13 ^= (__int64)a2;
                                                    v8 = ptr->field_8;
                                                    a2 = ptr->field_10;
                                                    result = v13;
                                                    result >>= 57;
                                                    v7 = ptr->field_20;
                                                    v6 = ptr->field_18;
                                                    xmm0 = _mm_cvtsi32_si128(result);
                                                    xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                    xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                    xmm6 = _mm_shuffle_epi32(xmm0, 68);
                                                    a1 = (int *)arg_8;
                                                    v12 = arg_10;
                                                    v4 = 0;
                                                    xmm7 = _mm_cmpeq_epi32(xmm7, xmm7);
                                                    v11 = v13;
                                                    do {
                                                        v11 &= v7;
                                                        xmm8 = _mm_loadu_si128((__m128i *)(v6 + v11));
                                                        xmm0 = xmm8;
                                                        xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                                                        result = _mm_movemask_epi8(xmm0);
                                                        xmm8 = _mm_cmpeq_epi8(xmm8, xmm7);
                                                        result = _mm_movemask_epi8(xmm8);
                                                        if (result != 0) JUMPOUT(0x140057582);
                                                        v11 += v4;
                                                        v11 += 16;
                                                        v4 += 16;
                                                    } while (true);
                                                } else {
                                                    v13 = result;
                                                }
                                            }
                                            sub_1400F27F0(v13, v11, v9, v6);
                                            a1 = (int *)v13;
                                            v13 = v9;
                                            a2 = (__int64 *)v_60;
                                            ptr2 = (struct Struct_2_t *)v_30;
                                            v6 = v_28;
                                            v7 = v_40;
                                            v8 = v_38;
                                            *(__int64 *)ptr = (__int64)(v4);
                                            ptr->field_8 = v10;
                                            ptr->field_10 = v4;
                                            ptr->field_18 = v6;
                                            ptr->field_20 = ptr2;
                                            ptr->field_28 = a2;
                                            ptr->field_30 = v8;
                                            ptr->field_38 = v7;
                                            result = v_58;
                                            ptr->field_40 = result;
                                            ptr->field_48 = v12;
                                            result = v_70;
                                            ptr->field_50 = result;
                                            result = v_50;
                                            ptr->field_58 = result;
                                            ptr->field_60 = v2;
                                            result = v_68;
                                            ptr->field_68 = result;
                                            result = v_48;
                                            ptr->field_70 = result;
                                            ptr->field_78 = v13;
                                            ptr->field_80 = a1;
                                            ptr->field_88 = v9;
                                            return result;
                                        }
                                        a1 = (int *)arg_80;
                                        v9 = arg_88;
                                        v13 = 0x8000000000000002;
                                        return v13;
                                    }
                                }
                                return v13;
                            }
                            v2 = 0x8000000000000000;
                            a1 = (int *)result;
                            a1 = (int *)((__int64)(__int64)a1 ^ v2);
                            /* test result , result */;
                            result = 1;
                            if (0 /* unresolved: flags < 0 */) result = a1;
                            if (result == 2) {
                                result = arg_68;
                                v_68 = result;
                                result = arg_70;
                                v_48 = result;
                                v2 = 0x8000000000000002;
                                result = arg_78;
                                if (result != v13) {
                                    return result;
                                }
                                return result;
                            }
                            if (result != 1) {
                                return result;
                            }
                            result = arg_70;
                            if (result < 0) {
                                return result;
                            }
                            v_48 = result;
                            v_38 = v8;
                            v_40 = v7;
                            v_28 = v6;
                            v_30 = (__int64)ptr2;
                            v_60 = (int)a2;
                            v9 = arg_68;
                            if (result == 0) {
                                v_68 = (int)a1;
                                v2 = v_48;
                                sub_1400F27F0(1, v9, v2, v6);
                                a2 = (__int64 *)v_60;
                                ptr2 = (struct Struct_2_t *)v_30;
                                v6 = v_28;
                                v7 = v_40;
                                v8 = v_38;
                                result = arg_78;
                                if (result != v13) {
                                    return result;
                                }
                                return result;
                            }
                            a2 = (__int64 *)v_48;
                            sub_14002EDF0(0, a2, a1, v2);
                            if (result != 0) {
                                a1 = (int *)result;
                                return (__int64)a1;
                            }
                            a2 = (__int64 *)v_48;
                            sub_1400F3326(1, a2);
                            return (__int64)a2;
                        }
                        if (result != 2) {
                            result = arg_58;
                            if (result < 0) {
                                return result;
                            }
                            v_50 = result;
                            v_38 = v8;
                            v_40 = v7;
                            v_28 = v6;
                            v_30 = (__int64)ptr2;
                            v2 = (__int64)a2;
                            v9 = arg_50;
                            if (result == 0) {
                                v_70 = (int)a1;
                                v12 = v_50;
                                sub_1400F27F0(1, v9, v12);
                                a2 = (__int64 *)v2;
                                ptr2 = (struct Struct_2_t *)v_30;
                                v6 = v_28;
                                v7 = v_40;
                                v8 = v_38;
                                return v8;
                            }
                            a2 = (__int64 *)v_50;
                            sub_14002EDF0(0, a2, ptr2, v6);
                            if (result != 0) {
                                a1 = (int *)result;
                                return (__int64)a1;
                            }
                            a2 = (__int64 *)v_50;
                            sub_1400F3326(1, a2);
                            return (__int64)a2;
                        }
                        result = arg_50;
                        v_70 = result;
                        result = arg_58;
                        v_50 = result;
                        v12 = 0x8000000000000002;
                    }
                    return v12;
                }
                v8 = 0x8000000000000000;
                a1 = (int *)result;
                a1 = (int *)((__int64)(__int64)a1 ^ v8);
                /* test result , result */;
                result = 1;
                if (0 /* unresolved: flags < 0 */) result = a1;
                if (result == 2) {
                    v7 = arg_38;
                    result = arg_40;
                    v_58 = result;
                    v8 = 0x8000000000000002;
                    result = arg_48;
                    v12 = v13;
                    if (result == v13) {
                        return v12;
                    }
                    return v12;
                }
                if (result != 1) {
                    result = arg_48;
                    v12 = v13;
                    if (result == v13) {
                        return v12;
                    }
                    return v12;
                }
                result = arg_40;
                if (result < 0) {
                    return result;
                }
                v_58 = result;
                v_28 = v6;
                v_30 = (__int64)ptr2;
                v2 = (__int64)a2;
                v9 = arg_38;
                if (result == 0) {
                    v12 = 1;
                    v9 = v_58;
                    sub_1400F27F0(v12, v9, v9);
                    v7 = v12;
                    v8 = v9;
                    a2 = (__int64 *)v2;
                    ptr2 = (struct Struct_2_t *)v_30;
                    v6 = v_28;
                    result = arg_48;
                    v12 = v13;
                    if (result == v13) {
                        return v12;
                    }
                    return v12;
                }
                a2 = (__int64 *)v_58;
                sub_14002EDF0(0, a2, ptr2, 0x8000000000000002);
                if (result != 0) {
                    v12 = result;
                    return v12;
                }
                a2 = (__int64 *)v_58;
                sub_1400F3326(1, a2);
                return (__int64)a2;
            }
            a1 = (int *)result;
            a1 = (int *)((__int64)(__int64)a1 ^ v6);
            /* test result , result */;
            result = 1;
            if (0 /* unresolved: flags < 0 */) result = a1;
            if (result == 2) {
                ptr2 = (struct Struct_2_t *)arg_20;
                a2 = (__int64 *)arg_28;
                result = arg_30;
                v8 = v13;
                if (result == v13) {
                    return v8;
                }
                return v8;
            }
            if (result != 1) {
                return v8;
            }
            a2 = (__int64 *)arg_28;
            if (a2 < 0) {
                return (__int64)a2;
            }
            v12 = arg_20;
            if (a2 == 0) {
                v2 = (__int64)a2;
                sub_1400F27F0(1, a1, v2);
                a2 = (__int64 *)v2;
                result = arg_30;
                v8 = v13;
                if (result != v13) {
                    return v8;
                }
                return v8;
            }
            v2 = (__int64)a2;
            sub_14002EDF0(0, a2, ptr2, 0x8000000000000000);
            if (result != 0) {
                a1 = (int *)result;
                return (__int64)a1;
            }
            sub_1400F3326(1, v2);
            return (__int64)a1;
        } while (true);
    }
    return result;
}