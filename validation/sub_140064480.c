// inferred from 8 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    char field_8; // offset 8
    char field_9; // offset 9
    __int16 field_A; // offset 10
    char field_C; // offset 12
    char field_D; // offset 13
    char field_E; // offset 14
    __int64 field_F; // offset 15
    char _pad_F[17];
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140064DC0();
__int64 sub_140064FE0();
__int64 sub_140064210();
__int64 sub_14002EDF0();
__int64 sub_14004F470();
__int64 sub_14004F7E0();
__int64 sub_1400F3340();
__int64 sub_1400F3B80();
extern __int64 off_1401086E0;
extern __int64 off_1401159D0;
extern __int64 off_140116DE8;
extern __int64 off_140116DB8;
extern __int64 off_140116C89;
extern __int64 off_140115EA0;

__int64 __fastcall sub_140064480(size_t *a1, int a2, size_t a3, int a4) {
    __int64 rsp;
    int arg_1;
    int arg_2;
    int arg_3;
    int arg_4;
    int arg_5;
    int arg_6;
    int arg_7;
    int arg_8;
    int arg_9;
    __int64 v_20;
    __int64 v_30;
    __int64 v_31;
    __int64 v_35;
    __int64 v_37;
    __int64 v_38;
    int v_39;
    int v_3a;
    int v_3c;
    int v_3d;
    int v_3e;
    int v_3f;
    __int64 v_40;
    __int64 v_48;
    int v_49;
    __int64 v_50;
    int v_58;
    __int64 v_68;
    __int64 v_69;
    int v_6a;
    int v_6c;
    __int64 v_6d;
    int v_6f;
    int v_70;
    int v_78;
    int v_79;
    __int64 v_80;
    __int64 v_88;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_aa;
    __int64 v_b0;
    int *v_0;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *result;
    int v11;
    __int64 v6;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *v7;
    __int64 i;
    __int64 *i2;
    __int64 v2;
    __int64 v8;

    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    a1 = rsp + 48;
    sub_140064DC0(a1);
    result = (__int64 *)v_30;
    v11 = v_38;
    if (result != 3) {
        a3 = v_39;
        a2 = v_3a;
        a1 = (size_t *)v_3c;
        a4 = v_3d;
        v6 = v_3e;
        v5 = v_3f;
        xmm0 = _mm_cvtsi64_si128((__int64)(v_40));
        xmm1 = _mm_loadu_si128((__m128i *)&v_48);
        _mm_store_si128((__m128i *)&v_90, xmm1);
        ptr2 = (struct Struct_2_t *)v_58;
    } else {
        result = ptr2->field_18;
        if (result != 0) {
            a1 = ptr2->field_10;
            if (*a1 != 58) {
                xmm0 = _mm_setzero_si128();
                _mm_store_si128((__m128i *)&v_90, xmm0);
                xmm0 = _mm_cvtsi64_si128((__int64)(off_1401086E0));
                result = 1;
                v5 = 0;
                v6 = 0;
                a4 = 0;
                a1 = 0;
                a2 = 0;
                a3 = 0;
                v11 = 0;
            } else {
                ++a1;
                --result;
                ptr2->field_10 = a1;
                ptr2->field_18 = result;
                a1 = rsp + 48;
                sub_140064FE0(a1, ptr2);
                a2 = v_30;
                v7 = (__int64 *)v_38;
                if (a2 != 3) {
                    result = (__int64 *)v_58;
                    v_88 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_39);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_49);
                    _mm_storeu_si128((__m128i *)&v_79, xmm1);
                    _mm_storeu_si128((__m128i *)&v_69, xmm0);
                    v_68 = (__int64)v7;
                } else {
                    i = ptr2->field_18;
                    if (i != 0) {
                        i2 = ptr2->field_10;
                        if (*i2 != 58) {
                            xmm0 = _mm_setzero_si128();
                            _mm_storeu_si128((__m128i *)&v_78, xmm0);
                            a1 = rsp + 104;
                            v_68 = 0;
                            v_6f = 0;
                            v_6d = 0;
                            v_69 = 0;
                            v_70 = 8;
                            result = (__int64 *)v_88;
                            v_50 = (__int64)result;
                            _mm_store_si128((__m128i *)&v_40, xmm0);
                            result = (__int64 *)v_68;
                            v_30 = (__int64)result;
                            result = (__int64 *)v_69;
                            v_31 = (__int64)result;
                            result = (__int64 *)v_6d;
                            v_35 = (__int64)result;
                            result = (__int64 *)v_6f;
                            v_37 = (__int64)result;
                            result = (__int64 *)v_70;
                            v_38 = (__int64)result;
                            result = 2;
                        } else {
                            ++i2;
                            --i;
                            ptr2->field_10 = i2;
                            ptr2->field_18 = i;
                            v_90 = 1;
                            v_98 = 2;
                            v_a0 = 2;
                            v_a8 = 0x3000;
                            v_aa = 57;
                            a1 = rsp + 48;
                            a2 = rsp + 144;
                            sub_140064210(a1, a2, ptr2);
                            a2 = v_30;
                            a1 = (size_t *)v_38;
                            a3 = v_40;
                            if (a2 != 3) {
                                a4 = v_48;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_50);
                                result = (__int64 *)a1;
                                result = (__int64 *)((__int64)(__int64)result >> 8);
                            } else {
                                if (a3 == 1) {
                                    a3 = *a1;
                                    a2 = 1;
                                    if (a3 != 43) {
                                        result = 1;
                                        if (a3 != 45) {
                                            a2 = 0;
                                            a3 = 0;
                                            v2 = *(a1 + a2);
                                            v2 += 0xFFFFFFD0;
                                            while (v2 <= 9) {
                                                a3 += a3;
                                                a3 += a3*4;
                                                v2 += a3;
                                                ++a2;
                                                a3 = v2;
                                                if (v2 >= 61) {
                                                    ptr2->field_10 = i2;
                                                    ptr2->field_18 = i;
                                                    sub_14002EDF0(0, 48);
                                                    if (result != 0) {
                                                        a1 = 0x8000000000000001;
                                                        *result = a1;
                                                        *(result + 8) = v2;
                                                        a1 = &off_1401159D0;
                                                        xmm1 = _mm_cvtsi64_si128(a1);
                                                        xmm0 = _mm_cvtsi64_si128(result);
                                                        xmm0 = _mm_unpacklo_epi64(xmm0, xmm1);
                                                        a2 = 1;
                                                        a3 = 8;
                                                        result = 0;
                                                        a1 = 0;
                                                        v_68 = (__int64)a1;
                                                        v_69 = (__int64)result;
                                                        a1 = (size_t *)result;
                                                        a1 = (size_t *)((__int64)(__int64)a1 >> 48);
                                                        v_6f = (int)a1;
                                                        result = (__int64 *)((__int64)(__int64)result >> 32);
                                                        v_6d = (__int64)result;
                                                        v_70 = a3;
                                                        v_78 = a4;
                                                        _mm_storeu_si128((__m128i *)&v_80, xmm0);
                                                        a1 = rsp + 104;
                                                        result = (__int64 *)v_88;
                                                        v_50 = (__int64)result;
                                                        result = (__int64 *)v_68;
                                                        a3 = v_69;
                                                        a4 = v_6d;
                                                        v5 = v_6f;
                                                        v6 = v_70;
                                                        ptr2 = (struct Struct_2_t *)v_78;
                                                        v_40 = (__int64)ptr2;
                                                        ptr2 = (struct Struct_2_t *)v_80;
                                                        v_48 = (__int64)ptr2;
                                                        v_30 = (__int64)result;
                                                        v_31 = a3;
                                                        v_35 = a4;
                                                        v_37 = v5;
                                                        v_38 = v6;
                                                        result = 2;
                                                        if (a2 != 1) result = a2;
                                                        a2 = v_50;
                                                        a1[4] = a2;
                                                        a2 = v_30;
                                                        a3 = v_31;
                                                        a4 = v_35;
                                                        v5 = v_37;
                                                        v2 = v_38;
                                                        xmm0 = _mm_load_si128((__m128i *)&v_40);
                                                        _mm_storeu_si128((__m128i *)(a1 + 16), xmm0);
                                                        *a1 = a2;
                                                        arg_1 = a3;
                                                        arg_5 = a4;
                                                        arg_7 = v5;
                                                        arg_8 = v2;
                                                        v11 = v_68;
                                                        a3 = v_69;
                                                        a2 = v_6a;
                                                        a1 = (size_t *)v_6c;
                                                        xmm0 = _mm_cvtsi64_si128((__int64)(v_70));
                                                        xmm1 = _mm_loadu_si128((__m128i *)&v_78);
                                                        _mm_store_si128((__m128i *)&v_90, xmm1);
                                                        ptr2 = (struct Struct_2_t *)v_88;
                                                        a4 = (int)a1;
                                                        a4 >>= 8;
                                                        v6 = (__int64)a1;
                                                        v6 >>= 16;
                                                        v5 = (__int64)a1;
                                                        v5 >>= 24;
                                                        *(__int64 *)ptr = (__int64)(result);
                                                        ptr->field_8 = v11;
                                                        ptr->field_9 = a3;
                                                        ptr->field_A = a2;
                                                        ptr->field_C = a1;
                                                        ptr->field_D = a4;
                                                        ptr->field_E = v6;
                                                        ptr->field_F = v5;
                                                        /* movlps %xmm0, 16(%(__int64)ptr) */;
                                                        xmm0 = _mm_load_si128((__m128i *)&v_90);
                                                        _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
                                                        ptr->field_28 = ptr2;
                                                        return _mm_cvtsi128_si64(xmm0);
                                                    }
                                                } else {
                                                    v7 = ptr2->field_10;
                                                    v8 = ptr2->field_18;
                                                    i = 8;
                                                    if (v8 != 0) {
                                                        if (*v7 != 46) {
                                                            result = 0;
                                                            a1 = 0;
                                                        } else {
                                                            result = v7 + 1;
                                                            a1 = v8 - 1;
                                                            ptr2->field_10 = result;
                                                            ptr2->field_18 = a1;
                                                            v_90 = 1;
                                                            v_98 = -1;
                                                            v_a0 = 1;
                                                            v_a8 = 0x3000;
                                                            v_aa = 57;
                                                            a1 = rsp + 48;
                                                            a2 = rsp + 144;
                                                            sub_140064210(a1, a2, ptr2, a4);
                                                            a2 = v_30;
                                                            a1 = (size_t *)v_38;
                                                            i = v_40;
                                                            if (a2 != 3) {
                                                                a3 = v_48;
                                                                result = (__int64 *)v_50;
                                                                a4 = v_58;
                                                                if (a2 != 1) {
                                                                    v5 = (__int64)a1;
                                                                    v5 >>= 32;
                                                                    v_68 = (__int64)a1;
                                                                    v_6c = v5;
                                                                    v_70 = i;
                                                                    v_78 = a3;
                                                                    v_80 = (__int64)result;
                                                                    v_88 = a4;
                                                                    return v_88;
                                                                } else {
                                                                    a2 = 0xFFFFFFFF00000000;
                                                                    a2 &= (__int64)a1;
                                                                    v_30 = 1;
                                                                    a1 = (size_t *)((__int64)(__int64)a1 | a2);
                                                                    v_38 = (__int64)a1;
                                                                    v_40 = i;
                                                                    v_48 = a3;
                                                                    v_50 = (__int64)result;
                                                                    v_58 = a4;
                                                                    ptr2->field_10 = v7;
                                                                    ptr2->field_18 = v8;
                                                                    a1 = rsp + 48;
                                                                    sub_14004F470(a1, 0, 0, 0);
                                                                    i = 0;
                                                                    result = (__int64 *)i;
                                                                    result = (__int64 *)((__int64)(__int64)result >> 32);
                                                                    a1 = 0;
                                                                    if ((i & 1) != 0) a1 = result;
                                                                    ptr->field_8 = a1;
                                                                    ptr->field_C = v11;
                                                                    ptr->field_D = v7;
                                                                    ptr->field_E = v2;
                                                                    *(__int64 *)ptr = (__int64)(3);
                                                                }
                                                                return (__int64)a1;
                                                            } else {
                                                                v_b0 = (__int64)v7;
                                                                if (i < 10) {
                                                                    if (i != 0) {
                                                                        if (i != 1) {
                                                                            result = *a1;
                                                                            if (result != 43) {
                                                                                if (i != 9) {
                                                                                    result = (__int64 *)i;
                                                                                    a2 = 0;
                                                                                    i2 = 0;
                                                                                    a3 = *(a1 + a2);
                                                                                    a3 += 0xFFFFFFD0;
                                                                                    while (a3 <= 9) {
                                                                                        a4 = v7 + (__int64)(__int64)v7*4;
                                                                                        i2 = a3 + a4*2;
                                                                                        ++a2;
                                                                                        result = 0x8000000000000001;
                                                                                        v_30 = (__int64)result;
                                                                                        a1 = rsp + 48;
                                                                                        sub_14004F7E0(a1, a2, a3, a4);
                                                                                        result = i2;
                                                                                        a1 = &off_140116DE8;
                                                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * v_0[i]); /* unsigned; high half in a2 */;
                                                                                        if ((0 /* unresolved: flags OF */)) {
                                                                                            sub_14002EDF0(0, 48, a3, a4);
                                                                                            if (result == 0) {
                                                                                                sub_1400F3340(8, 48);
                                                                                                a2 = 1;
                                                                                                do {
                                                                                                    v_30 = a2;
                                                                                                    result = &off_140116DB8;
                                                                                                    v_20 = (__int64)result;
                                                                                                    a1 = &off_140116C89;
                                                                                                    a4 = &off_140115EA0;
                                                                                                    a3 = rsp + 48;
                                                                                                    sub_1400F3B80(a1, 22, a3, a4);
                                                                                                    a2 = 0;
                                                                                                } while (true);
                                                                                            } else {
                                                                                                a1 = 0x8000000000000001;
                                                                                                *result = a1;
                                                                                                a4 = &off_1401159D0;
                                                                                                a3 = 0;
                                                                                                a1 = 0;
                                                                                                a2 = 0;
                                                                                                v7 = (__int64 *)v_b0;
                                                                                                i = 8;
                                                                                                return i;
                                                                                            }
                                                                                        } else {
                                                                                            i = (__int64)result;
                                                                                            result = 0x8000000000000001;
                                                                                            v_30 = (__int64)result;
                                                                                            a1 = rsp + 48;
                                                                                            sub_14004F7E0(a1);
                                                                                            i <<= 32;
                                                                                            ++i;
                                                                                        }
                                                                                        return i;
                                                                                    }
                                                                                } else {
                                                                                    result += 0xFFFFFFD0;
                                                                                    if (result <= 9) {
                                                                                        result = (__int64 *)((__int64)result + (__int64)result);
                                                                                        result += (__int64)(__int64)result*4;
                                                                                        a3 = arg_1;
                                                                                        a3 += 0xFFFFFFD0;
                                                                                        result += a3;
                                                                                        a2 = (result < 0) ? 1 : 0;
                                                                                        if (a3 <= 9) {
                                                                                            if (a2 == 0) {
                                                                                                result = (__int64 *)((__int64)result + (__int64)result);
                                                                                                result += (__int64)(__int64)result*4;
                                                                                                a3 = arg_2;
                                                                                                a3 += 0xFFFFFFD0;
                                                                                                result += a3;
                                                                                                a2 = (result < 0) ? 1 : 0;
                                                                                                if (a3 <= 9) {
                                                                                                    if (a2 == 0) {
                                                                                                        result = (__int64 *)((__int64)result + (__int64)result);
                                                                                                        result += (__int64)(__int64)result*4;
                                                                                                        a3 = arg_3;
                                                                                                        a3 += 0xFFFFFFD0;
                                                                                                        result += a3;
                                                                                                        a2 = (result < 0) ? 1 : 0;
                                                                                                        if (a3 <= 9) {
                                                                                                            if (a2 == 0) {
                                                                                                                a2 = 10;
                                                                                                                result = (__int64 *)((__int64)(__int64)(__int64)result * a2); /* unsigned; high half in a2 */;
                                                                                                                if (!((0 /* unresolved: flags OF */))) {
                                                                                                                    a3 = arg_4;
                                                                                                                    a3 += 0xFFFFFFD0;
                                                                                                                    result += a3;
                                                                                                                    a2 = (result < 0) ? 1 : 0;
                                                                                                                    if (a3 <= 9) {
                                                                                                                        if (a2 == 0) {
                                                                                                                            a2 = 10;
                                                                                                                            result = (__int64 *)((__int64)(__int64)(__int64)result * a2); /* unsigned; high half in a2 */;
                                                                                                                            if (!((0 /* unresolved: flags OF */))) {
                                                                                                                                a3 = arg_5;
                                                                                                                                a3 += 0xFFFFFFD0;
                                                                                                                                result += a3;
                                                                                                                                a2 = (result < 0) ? 1 : 0;
                                                                                                                                if (a3 <= 9) {
                                                                                                                                    if (a2 == 0) {
                                                                                                                                        a2 = 10;
                                                                                                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * a2); /* unsigned; high half in a2 */;
                                                                                                                                        if (!((0 /* unresolved: flags OF */))) {
                                                                                                                                            a3 = arg_6;
                                                                                                                                            a3 += 0xFFFFFFD0;
                                                                                                                                            result += a3;
                                                                                                                                            a2 = (result < 0) ? 1 : 0;
                                                                                                                                            if (a3 <= 9) {
                                                                                                                                                if (a2 == 0) {
                                                                                                                                                    a2 = 10;
                                                                                                                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * a2); /* unsigned; high half in a2 */;
                                                                                                                                                    if (!((0 /* unresolved: flags OF */))) {
                                                                                                                                                        a3 = arg_7;
                                                                                                                                                        a3 += 0xFFFFFFD0;
                                                                                                                                                        result += a3;
                                                                                                                                                        a2 = (result < 0) ? 1 : 0;
                                                                                                                                                        if (a3 <= 9) {
                                                                                                                                                            if (a2 == 0) {
                                                                                                                                                                a2 = 10;
                                                                                                                                                                result = (__int64 *)((__int64)(__int64)(__int64)result * a2); /* unsigned; high half in a2 */;
                                                                                                                                                                if (!((0 /* unresolved: flags OF */))) {
                                                                                                                                                                    i2 = result;
                                                                                                                                                                    a1 = (size_t *)arg_8;
                                                                                                                                                                    a1 += 0xFFFFFFD0;
                                                                                                                                                                    i2 = (__int64 *)((__int64)i2 + (__int64)a1);
                                                                                                                                                                    result = (i2 < 0) ? 1 : 0;
                                                                                                                                                                    if (a1 <= 9) {
                                                                                                                                                                        i = 9;
                                                                                                                                                                        if (result == 0) {
                                                                                                                                                                            return i;
                                                                                                                                                                        } else {
                                                                                                                                                                        }
                                                                                                                                                                    }
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                return i;
                                                                            } else {
                                                                                ++a1;
                                                                                result = i - 1;
                                                                            }
                                                                        } else {
                                                                            a2 = *a1;
                                                                            if (a2 != 43) {
                                                                                i = 1;
                                                                                result = 1;
                                                                                if (a2 != 45) {
                                                                                    return (__int64)result;
                                                                                }
                                                                            }
                                                                            return (__int64)result;
                                                                        }
                                                                        return (__int64)result;
                                                                    }
                                                                } else {
                                                                    if (arg_9 <= 191) JUMPOUT(0x140064d9b);
                                                                    result = *a1;
                                                                    if (result != 43) {
                                                                        return (__int64)result;
                                                                    } else {
                                                                        ++a1;
                                                                        result = 8;
                                                                        i = 9;
                                                                        return i;
                                                                    }
                                                                }
                                                                return i;
                                                            }
                                                        }
                                                        return i;
                                                    }
                                                    return i;
                                                }
                                                return i;
                                            }
                                            return i;
                                        } else {
                                        }
                                    }
                                } else {
                                    if (a3 != 0) {
                                        if (*a1 != 43) {
                                            result = 2;
                                            if (a3 >= 3) {
                                                a2 = 0;
                                                a4 = 10;
                                                v2 = 0;
                                                while (a3 != a2) {
                                                    v5 = *(a1 + a2);
                                                    v5 += 0xFFFFFFD0;
                                                    result = (__int64 *)v2;
                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * a4); /* unsigned; high half in a2 */;
                                                    if (!((0 /* overflow check on (v5 + 0xFFFFFFD0) */))) {
                                                        if (v5 <= 9) {
                                                            v2 = (__int64)result;
                                                            ++a2;
                                                            v2 += v5;
                                                            a2 = 2;
                                                            return a2;
                                                        }
                                                    }
                                                    a2 = 0;
                                                    /* cmp v5 , 10 */;
                                                    ++a2;
                                                    return a2;
                                                }
                                            } else {
                                                return a2;
                                            }
                                            return a2;
                                        } else {
                                            ++a1;
                                            result = a3 - 1;
                                            a3 = (size_t)result;
                                            if ((a3 < 4)) {
                                                return a3;
                                            } else {
                                                return a3;
                                            }
                                            return a3;
                                        }
                                        return a3;
                                    }
                                    return a3;
                                }
                                return a3;
                            }
                            return a3;
                        }
                        return a3;
                    }
                    return a3;
                }
                return a3;
            }
            return a3;
        }
        return a3;
    }
    return (__int64)result;
}