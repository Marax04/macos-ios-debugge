// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_140059720();
__int64 sub_1400620FE();
__int64 sub_140055430();
__int64 sub_140059AA0();
__int64 sub_14004F470();
__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_140054AA0();
__int64 sub_140069780();
extern __int64 off_14011AB0E;

__int64 __fastcall sub_140061990(size_t *a1, int *a2) {
    __int64 rsp;
    int arg_4;
    int arg_6;
    int arg_7;
    int v_100;
    int v_108;
    int v_110;
    int v_118;
    __int64 v_120;
    int v_128;
    int v_130;
    int v_168;
    int v_178;
    int v_180;
    int v_188;
    int v_190;
    int v_1a0;
    int v_1b0;
    int v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_39;
    int v_3d;
    int v_3f;
    int v_40;
    int v_48;
    int v_50;
    int v_51;
    int v_52;
    int v_53;
    int v_60;
    int v_68;
    __int64 v_70;
    int v_78;
    int v_80;
    int v_87;
    int v_90;
    int v_97;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_c8;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    int v_f0;
    int v_f8;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *v9;
    __int64 v8;
    __int64 result;
    __int64 v11;
    __int64 v10;
    __int64 v2;
    __int64 v7;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v5;
    struct Struct_3_t *ptr3;

    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    v9 = a2[2];
    v8 = a2[3];
    v_168 = 0;
    v_178 = 1;
    result = 0x9207E5D005B2300;
    v_180 = result;
    v_188 = 0xFF800021;
    a1 = rsp + 168;
    a2 = rsp + 360;
    sub_140059720(a1, a2, ptr2);
    v11 = v_a8;
    v_70 = (__int64)v9;
    v_78 = v8;
    if (v11 != 1) {
        v10 = v_b0;
        v2 = v_b8;
        v9 = (__int64 *)v_c0;
        v8 = v_c8;
        v7 = v_d0;
        if (v11 == 3) {
            ptr->field_8 = v10;
            ptr->field_10 = v2;
            ptr->field_18 = v9;
            *(__int64 *)ptr = (__int64)(3);
            return sub_1400620FE();
        }
    } else {
        xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
        xmm1 = _mm_loadu_si128((__m128i *)&v_b8);
        xmm2 = _mm_loadu_si128((__m128i *)&v_c8);
        _mm_store_si128((__m128i *)&v_1b0, xmm2);
        _mm_store_si128((__m128i *)&v_1a0, xmm1);
        _mm_store_si128((__m128i *)&v_190, xmm0);
        ptr2->field_10 = v9;
        ptr2->field_18 = v8;
        if (v8 != 0) {
            if (*v9 != 92) {
                v_97 = 0;
                v_90 = 0;
                v11 = 1;
                v2 = 8;
                result = rsp + 144;
                a1 = 0;
                v8 = arg_7;
                result = 0;
                v10 = 0;
                if (v11 == 1) {
                    v_d8 = 1;
                    v_e0 = v10;
                    v_e8 = v2;
                    a1 = (size_t *)((__int64)(__int64)a1 << 8);
                    result |= (__int64)a1;
                    v_f0 = result;
                    v_f8 = v8;
                    v_100 = v7;
                    a1 = rsp + 504;
                    a2 = rsp + 400;
                    v5 = rsp + 216;
                    sub_140055430(a1, a2, v5);
                    ptr2->field_10 = v9;
                    result = v_78;
                    ptr2->field_18 = result;
                    a1 = rsp + 32;
                    sub_140059AA0(a1, ptr2);
                    v11 = v_20;
                    if (v11 != 3) {
                        v10 = v_28;
                        v2 = v_30;
                        v9 = (__int64 *)v_38;
                        v8 = v_40;
                        v7 = v_48;
                        if (v11 != 1) {
                            a1 = rsp + 504;
                            sub_14004F470(a1);
                            if (v11 != 3) {
                                if (v11 != 1) JUMPOUT(0x1400620e7);
                                v_20 = 1;
                                v_28 = v10;
                                v_30 = v2;
                                v_38 = (__int64)v9;
                                v_40 = v8;
                                v_48 = v7;
                                result = v_70;
                                ptr2->field_10 = result;
                                result = v_78;
                                ptr2->field_18 = result;
                                result = 0x8000000000000001;
                                ptr->field_8 = result;
                                *(__int64 *)ptr = (__int64)(3);
                                a1 = rsp + 32;
                                sub_14004F470(a1);
                                return sub_1400620FE();
                            }
                        } else {
                            v_108 = 1;
                            v_110 = v10;
                            v_118 = v2;
                            v_120 = (__int64)v9;
                            v_128 = v8;
                            v_130 = v7;
                            a1 = rsp + 552;
                            a2 = rsp + 504;
                            v5 = rsp + 264;
                            sub_140055430(a1, a2, v5);
                            ptr3 = (struct Struct_3_t *)v_70;
                            ptr2->field_10 = ptr3;
                            v5 = v_78;
                            ptr2->field_18 = v5;
                            if (v5 == 0) JUMPOUT(0x140062062);
                            a2 = ptr3->field_0;
                            result = v5 - 1;
                            a1 = ptr3 + 1;
                            ptr2->field_10 = a1;
                            ptr2->field_18 = result;
                            if (a2 != 10) {
                                if (a2 != 13) JUMPOUT(0x140062062);
                                if (result == 0) JUMPOUT(0x140062062);
                                a2 = ptr3->field_1;
                                v5 -= 2;
                                ptr3 += 2;
                                ptr2->field_10 = ptr3;
                                ptr2->field_18 = v5;
                                if (a2 != 10) JUMPOUT(0x14006205a);
                            }
                            a1 = rsp + 552;
                            sub_14004F470(a1, a2, v5, ptr3);
                            v9 = 1;
                            v2 = &off_14011AB0E;
                            v10 = 0x8000000000000000;
                        }
                        return v10;
                    } else {
                        a1 = (size_t *)v_28;
                        v_50 = 0;
                        if (a1 >= 128) {
                            result = (__int64)a1;
                            result &= 63;
                            result |= 128;
                            a2 = (int *)a1;
                            a2 = (int *)((__int64)(__int64)a2 >> 6);
                            if (a1 >= 0x800) {
                                a2 = (int *)((__int64)(__int64)a2 & 63);
                                a2 = (int *)((__int64)(__int64)a2 | 128);
                                v5 = (__int64)a1;
                                v5 >>= 12;
                                if (a1 > 0xFFFF) {
                                    v5 &= 63;
                                    v5 |= 128;
                                    a1 = (size_t *)((__int64)(__int64)a1 >> 18);
                                    a1 = (size_t *)((__int64)(__int64)a1 | 240);
                                    v_50 = (int)a1;
                                    v_51 = v5;
                                    v_52 = (int)a2;
                                    v_53 = result;
                                    v9 = 4;
                                } else {
                                    v5 |= 224;
                                    v_50 = v5;
                                    v_51 = (int)a2;
                                    v_52 = result;
                                    v9 = 3;
                                }
                            } else {
                                a2 = (int *)((__int64)(__int64)a2 | 192);
                                v_50 = (int)a2;
                                v_51 = result;
                                v9 = 2;
                            }
                        } else {
                            v_50 = (int)a1;
                            v9 = 1;
                        }
                        sub_14002EDF0(0, v9, v5);
                        if (result == 0) JUMPOUT(0x140062112);
                        v2 = result;
                        a2 = rsp + 80;
                        sub_1400F27F0(result, a2, v9);
                        v10 = (__int64)v9;
                    }
                    return v10;
                } else {
                    a1 = (size_t *)((__int64)(__int64)a1 << 8);
                    v9 = (__int64 *)result;
                    v9 = (__int64 *)((__int64)(__int64)v9 | (__int64)a1);
                    a1 = rsp + 400;
                    sub_14004F470(a1);
                    if (v11 != 3) {
                        return (__int64)a1;
                    }
                }
                return (__int64)a1;
            } else {
                result = v9 + 1;
                a1 = v8 - 1;
                ptr2->field_10 = result;
                ptr2->field_18 = a1;
                v_50 = 0;
                v_60 = 0;
                v_68 = 0x920;
                a1 = rsp + 32;
                a2 = rsp + 80;
                sub_140054AA0(a1, a2, ptr2);
                v11 = v_20;
                if (v11 == 3) {
                    a1 = rsp + 32;
                    sub_140069780(a1, ptr2);
                    v11 = v_20;
                    if (v11 != 3) {
                        v10 = v_28;
                        v2 = v_30;
                        result = v_38;
                        a1 = (size_t *)v_39;
                        v_80 = (int)a1;
                        a1 = (size_t *)v_40;
                        v_87 = (int)a1;
                        v7 = v_48;
                        a1 = (size_t *)v_80;
                        a2 = (int *)v_87;
                        v_97 = (int)a2;
                        v_90 = (int)a1;
                        a1 = rsp + 144;
                        a2 = rsp + 128;
                        if (v11 == 1) a2 = a1;
                        a1 = (size_t *)arg_4;
                        v5 = arg_6;
                        v5 <<= 16;
                        v5 |= (__int64)a1;
                        v5 <<= 32;
                        a1 = *a2;
                        a1 = (size_t *)((__int64)(__int64)a1 | v5);
                        v8 = arg_7;
                        if (v11 != 1) {
                            return v8;
                        } else {
                            return v8;
                        }
                        return v8;
                    } else {
                        a2 = ptr2->field_10;
                        v9 = ptr2->field_18;
                        v2 = 8;
                        if (v9 != 0) {
                            v7 = rsp + 32;
                            v10 = 0;
                            while (*a2 == 92) {
                                v_a0 = (int)a2;
                                result = a2 + 1;
                                a1 = v9 - 1;
                                ptr2->field_10 = result;
                                ptr2->field_18 = a1;
                                v_50 = 0;
                                v_60 = 0;
                                v_68 = 0x920;
                                a2 = rsp + 80;
                                sub_140054AA0(v7, a2, ptr2);
                                v11 = v_20;
                                if (v11 == 3) {
                                    sub_140069780(v7, ptr2);
                                    v11 = v_20;
                                    if (v11 == 3) {
                                        result = ptr2->field_18;
                                        if (result != v9) {
                                            a2 = ptr2->field_10;
                                            v9 = (__int64 *)result;
                                            v2 = 8;
                                            a1 = 0;
                                            v8 = 0;
                                            v9 = 0;
                                            result = 0;
                                            v10 = 0;
                                            v_20 = 1;
                                            v_28 = v10;
                                            v_30 = v2;
                                            v_38 = result;
                                            v_39 = (int)a1;
                                            result = (__int64)a1;
                                            result >>= 48;
                                            v_3f = result;
                                            a1 = (size_t *)((__int64)(__int64)a1 >> 32);
                                            v_3d = (int)a1;
                                            v_40 = v8;
                                            v_48 = v7;
                                            ptr2->field_10 = a2;
                                            ptr2->field_18 = v9;
                                            a1 = rsp + 32;
                                            sub_14004F470(a1, a2);
                                            v11 = 3;
                                            v10 = 0x8000000000000000;
                                            v2 = 1;
                                            a1 = 0;
                                            result = 0;
                                            v8 = 0;
                                            return v8;
                                        }
                                        v11 = 2;
                                        v2 = 8;
                                        return v2;
                                    }
                                }
                                v10 = v_28;
                                v2 = v_30;
                                result = v_38;
                                a1 = (size_t *)v_3f;
                                a1 = (size_t *)((__int64)(__int64)a1 << 16);
                                a2 = (int *)v_3d;
                                a2 = (int *)((__int64)(__int64)a2 | (__int64)a1);
                                a2 = (int *)((__int64)(__int64)a2 << 32);
                                a1 = (size_t *)v_39;
                                a1 = (size_t *)((__int64)(__int64)a1 | (__int64)a2);
                                v8 = v_40;
                                v7 = v_48;
                                if (v11 != 1) {
                                    v9 = (__int64 *)v_70;
                                    if (v11 == 1) {
                                        return (__int64)v9;
                                    } else {
                                        return (__int64)v9;
                                    }
                                    return (__int64)v9;
                                } else {
                                    a2 = (int *)v_a0;
                                    return (__int64)a2;
                                }
                                return (__int64)a2;
                            }
                            a1 = 0;
                            v8 = 0;
                            return v8;
                        }
                        return v8;
                    }
                    return v8;
                }
                return v8;
            }
            return v8;
        }
        return v8;
    }
    return result;
}