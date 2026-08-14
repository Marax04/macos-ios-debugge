// inferred from 2 accesses on `a3`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char field_8; // offset 8
    __int64 field_9; // offset 9
};

// inferred from 11 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[1];
    char field_49; // offset 73
    char field_4A; // offset 74
    __int16 field_4B; // offset 75
    __int64 field_4D; // offset 77
};

// inferred from 63 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    char field_8; // offset 8
    char field_9; // offset 9
    int field_A; // offset 10
    char _pad_A[2];
    __int64 field_10; // offset 16
    char field_18; // offset 24
    char field_19; // offset 25
    int field_1A; // offset 26
    char _pad_1A[2];
    __int64 field_20; // offset 32
    char field_28; // offset 40
    char field_29; // offset 41
    int field_2A; // offset 42
    char _pad_2A[2];
    __int64 field_30; // offset 48
    char field_38; // offset 56
    char field_39; // offset 57
    int field_3A; // offset 58
    char _pad_3A[2];
    __int64 field_40; // offset 64
    char field_48; // offset 72
    char field_49; // offset 73
    int field_4A; // offset 74
    char _pad_4A[2];
    __int64 field_50; // offset 80
    char field_58; // offset 88
    char field_59; // offset 89
    int field_5A; // offset 90
    char _pad_5A[2];
    __int64 field_60; // offset 96
    char field_68; // offset 104
    char field_69; // offset 105
    int field_6A; // offset 106
    char _pad_6A[2];
    __int64 field_70; // offset 112
    char field_78; // offset 120
    int field_79; // offset 121
    char _pad_79[3];
    __int64 field_80; // offset 128
    char field_88; // offset 136
    char field_89; // offset 137
    int field_8A; // offset 138
    char _pad_8A[2];
    __int64 field_90; // offset 144
    char field_98; // offset 152
    __int64 field_99; // offset 153
    char _pad_99[7];
    char field_A8; // offset 168
    __int64 field_A9; // offset 169
    char _pad_A9[7];
    char field_B8; // offset 184
    char field_B9; // offset 185
    int field_BA; // offset 186
    char _pad_BA[2];
    __int64 field_C0; // offset 192
    char field_C8; // offset 200
    char field_C9; // offset 201
    int field_CA; // offset 202
    char _pad_CA[2];
    __int64 field_D0; // offset 208
    char field_D8; // offset 216
    char field_D9; // offset 217
    int field_DA; // offset 218
    char _pad_DA[2];
    __int64 field_E0; // offset 224
    char field_E8; // offset 232
    char field_E9; // offset 233
    int field_EA; // offset 234
    char _pad_EA[2];
    __int64 field_F0; // offset 240
    char field_F8; // offset 248
    __int64 field_F9; // offset 249
    char _pad_F9[7];
    char field_108; // offset 264
    __int64 field_109; // offset 265
    char _pad_109[7];
    char field_118; // offset 280
    char field_119; // offset 281
    __int64 field_11A; // offset 282
};

__int64 sub_1400F87E0();
__int64 sub_14002EDF0();
__int64 sub_14008FF00();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_140094CC0();
__int64 sub_1400FAE10();
__int64 sub_140093009();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401190A3;
extern __int64 off_1401248C8;
extern __int64 off_1401248A0;

__int64 __fastcall sub_140090304(size_t *a1, int *a2,struct Struct_1_t *a3, int *a4) {
    __int64 rsp;
    __int64 __rdx_rax;
    int arg_2;
    int arg_8;
    __int64 v_100;
    __int64 v_108;
    int v_10e;
    __int64 v_118;
    int v_11e;
    __int64 v_128;
    int v_1f0;
    int v_20;
    int v_200;
    int v_210;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    int v_39;
    __int64 v_40;
    int v_48;
    int v_49;
    int v_50;
    int v_58;
    int v_59;
    int v_60;
    int v_68;
    int v_69;
    int v_6a;
    __int64 v_70;
    int v_75;
    int v_78;
    int v_80;
    __int64 v_88;
    int v_90;
    __int64 v_98;
    __int64 v_a0;
    int v_b0;
    __int64 v_cc;
    __int64 v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    int v_f0;
    __int64 v_f8;
    struct Struct_2_t *result;
    __int64 *dst2;
    __int64 i;
    __int64 *dst;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *i2;
    __m128i xmm2;
    __int64 *dst3;
    struct Struct_4_t *ptr2;
    __int64 i3;
    __int64 v5;
    struct Struct_3_t *ptr;

    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_75 += (__int64)a1;
    *(__int64 *)(a3 - 119) = (__int64)(*(__int64 *)(a3 - 119) + a4);
    /* test result[(__int64)result] , result */;
    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_75 += (__int64)a1;
    *(a4 - 57) = *(a4 - 57) | (__int64)a4;
    *(__int64 *)a3 = (__int64)(a3->field_0 + a3);
    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_39 += (__int64)a1;
    *(__int64 *)a3 = (__int64)(a3->field_0 | (__int64)a4);
    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_39 += (__int64)a1;
    *(__int64 *)a3 = (__int64)(a3->field_0 + a3);
    *(__int64 *)result = (__int64)(result->field_0 + result);
    *(dst - 115) = *(dst - 115) + a1;
    result = (struct Struct_2_t *)((__int64)(__int64)result | 127);
    a1 = (size_t *)((__int64)(__int64)a1 << 4);
    a1 = (size_t *)((__int64)a1 + (__int64)a3);
    v_78 = (int)a1;
    v_f0 = (int)a3;
    dst2 = 0x8000000000000000;
    if (!((dst2 == 0))) {
        v_f8 = (__int64)ptr2;
        v_100 = (__int64)dst;
        i = 0;
        a1 = (size_t *)v_f0;
        dst = &off_1401190A3;
        v6 = 0xE38E38E38E38E38F;
        result = *a1;
        a2 = a1[5];
        v_210 = (int)a2;
        xmm0 = _mm_loadu_si128((__m128i *)(a1 + 24));
        _mm_store_si128((__m128i *)&v_200, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)(a1 + 8));
        a1 += 48;
        v_80 = (int)a1;
        _mm_store_si128((__m128i *)&v_1f0, xmm0);
        a1 = 0x800000000000001B;
        while (result != a1) {
            v_40 = (__int64)result;
            result = (struct Struct_2_t *)v_210;
            a1 = rsp + 72;
            a1[4] = result;
            xmm0 = _mm_load_si128((__m128i *)&v_1f0);
            xmm1 = _mm_load_si128((__m128i *)&v_200);
            _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
            _mm_storeu_si128((__m128i *)a1, xmm0);
            result = ptr->field_10;
            a3 = result + (__int64)(__int64)result*4;
            a3 = __ROL8__(a3, 7);
            a2 = ptr->field_8;
            a4 = (int *)result;
            a1 = ptr->field_18;
            a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
            i2 = (__int64 *)a1;
            i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
            result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)ptr->field_20);
            a4 = (int *)((__int64)(__int64)a4 << 17);
            ptr->field_10 = i2;
            a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
            ptr->field_8 = a2;
            a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
            ptr->field_18 = a1;
            result = __ROL8__(result, 45);
            ptr->field_20 = result;
            a3 += (__int64)(__int64)a3*8;
            if (a3 >= ptr->field_49) {
                a3 = i2 + (__int64)(__int64)i2*4;
                a3 = __ROL8__(a3, 7);
                a4 = (int *)i2;
                a4 = (int *)((__int64)(__int64)a4 << 17);
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)i2);
                i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)a1);
                ptr->field_10 = i2;
                a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                ptr->field_8 = a2;
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
                ptr->field_18 = a1;
                result = __ROL8__(result, 45);
                ptr->field_20 = result;
                a3 += (__int64)(__int64)a3*8;
                if (a3 >= ptr->field_4B) {
                    a1 = (size_t *)v_40;
                    result = (struct Struct_2_t *)a1;
                    result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)dst2);
                    /* test a1 , a1 */;
                    a1 = 8;
                    if (0 /* unresolved: flags >= 0 */) result = a1;
                    a1 = result - 9;
                    if (a1 < 3) {
                        xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                        xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                        xmm2 = _mm_loadu_si128((__m128i *)&v_60);
                        _mm_store_si128((__m128i *)&v_b0, xmm2);
                        _mm_store_si128((__m128i *)&v_a0, xmm1);
                        _mm_store_si128((__m128i *)&v_90, xmm0);
                        if (i == v_d8) {
                            a1 = rsp + 216;
                            sub_1400F87E0(a1, a2, 8);
                            v6 = 0xE38E38E38E38E38F;
                        }
                        dst3 = (__int64 *)v_e0;
                        result =  + i*2;
                        result += i;
                        result = (struct Struct_2_t *)((__int64)(__int64)result << 4);
                        xmm0 = _mm_load_si128((__m128i *)&v_90);
                        xmm1 = _mm_load_si128((__m128i *)&v_a0);
                        xmm2 = _mm_load_si128((__m128i *)&v_b0);
                        _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)result + 32), xmm2);
                        _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)result + 16), xmm1);
                        _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)result), xmm0);
                        ++i;
                        v_e8 = i;
                        a1 = (size_t *)v_80;
                        if (a1 == v_78) JUMPOUT(0x14009304a);
                    }
                    i = ptr->field_10;
                    a1 =  + i*4;
                    a1 += i;
                    a1 = __ROL8__(a1, 7);
                    dst3 = ptr->field_8;
                    a2 = (int *)i;
                    i2 = ptr->field_18;
                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                    ptr2 = (struct Struct_4_t *)i2;
                    ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ i);
                    i ^= ptr->field_20;
                    a2 = (int *)((__int64)(__int64)a2 << 17);
                    ptr->field_10 = ptr2;
                    dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                    ptr->field_8 = dst3;
                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)a2);
                    ptr->field_18 = i2;
                    i = __ROL8__(i, 45);
                    ptr->field_20 = i;
                    a1 += (__int64)(__int64)a1*8;
                    if (a1 >= ptr->field_4A) {
                        sub_14002EDF0(0, 48);
                        if (result == 0) JUMPOUT(0x140093532);
                        ptr2 = (struct Struct_4_t *)result;
                        a2 = rsp + 64;
                        sub_14008FF00(result, a2);
                        a1 = ptr2->field_0;
                        result = (struct Struct_2_t *)a1;
                        result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)dst2);
                        if (a1 >= 0) result = a3;
                        a1 = (size_t *)v_40;
                        a2 = (int *)a1;
                        a2 = (int *)((__int64)(__int64)a2 ^ (__int64)dst2);
                        if (a1 >= 0) a2 = a3;
                        if (result != a2) {
                            dst2 = 0;
                            dst2 = (__int64 *)((__int64)(__int64)dst2 ^ 1);
                            i2 = 1;
                            result = (struct Struct_2_t *)v_d8;
                            i = v_e8;
                            result -= i;
                            if (i2 > result) {
                                v_20 = 48;
                                a1 = rsp + 216;
                                sub_1400F2D20(a1, i, i2, 8);
                                i = v_e8;
                            }
                            result = (struct Struct_2_t *)i2;
                            result = (struct Struct_2_t *)((__int64)(__int64)result << 4);
                            a3 = result + (__int64)(__int64)result*2;
                            dst3 = (__int64 *)v_e0;
                            a1 =  + i*2;
                            a1 += i;
                            a1 = (size_t *)((__int64)(__int64)a1 << 4);
                            a1 = (size_t *)((__int64)a1 + (__int64)dst3);
                            sub_1400F27F0(a1, ptr2, a3);
                            i += (__int64)i2;
                            v_e8 = i;
                            off_140108030();
                            off_140108038(result, 0, ptr2);
                            if (dst2 == 0) {
                                dst2 = 0x8000000000000000;
                                v6 = 0xE38E38E38E38E38F;
                                if ((v_40 - 0) < 0) {
                                    return v6;
                                }
                                if (v_40 == 0) {
                                    if (v_58 == 0) {
                                        return v6;
                                    }
                                    i2 = (__int64 *)v_60;
                                    off_140108030();
                                    off_140108038(result, 0, i2);
                                    v6 = 0xE38E38E38E38E38F;
                                    return v6;
                                }
                                i2 = (__int64 *)v_48;
                                off_140108030();
                                off_140108038(result, 0, i2);
                                v6 = 0xE38E38E38E38E38F;
                                return v6;
                            }
                            ptr->field_40 = ptr->field_40 + 1;
                            ptr->field_28 = ptr->field_28 + 1;
                            return v6;
                        }
                        dst2 = 1;
                        if (result > 26) {
                            return (__int64)dst2;
                        }
                        a1 = &off_1401248C8;
                        switch ((__int64)result) {
                            case 7:
                                return (__int64)a1;
                            case 9:
                                return (__int64)a1;
                            case 11:
                                result = ptr2->field_8;
                                /* cmp result , v_48 */;
                                return (__int64)result;
                            default:
                                result = ptr2->field_29;
                                if (result != v_69) {
                                    return (__int64)result;
                                }
                                result = ptr2->field_28;
                                if (result != v_68) {
                                    return (__int64)result;
                                }
                                result = ptr2->field_8;
                                if (result != v_48) {
                                    return (__int64)result;
                                }
                                if (result == 0) {
                                    result = ptr2->field_9;
                                    if (result != v_49) {
                                        return (__int64)result;
                                    }
                                    result = ptr2->field_18;
                                    if (result != v_58) {
                                        return (__int64)result;
                                    }
                                    if (result == 0) {
                                        result = ptr2->field_19;
                                        if (result != v_59) {
                                            return (__int64)result;
                                        }
                                        result = ptr2->field_2A;
                                        /* cmp result , v_6a */;
                                        return (__int64)result;
                                    }
                                    result = ptr2->field_20;
                                    if (result != v_60) {
                                        return (__int64)result;
                                    }
                                    return (__int64)result;
                                }
                                result = ptr2->field_10;
                                if (result == v_50) {
                                    return (__int64)result;
                                }
                                break;
                        }
                        return (__int64)result;
                    }
                    if (result == 0) {
                        if (v_48 == 0) {
                            return (__int64)result;
                        }
                        dst2 = (__int64 *)v_58;
                        i3 = v_50;
                        result =  + (__int64)(__int64)ptr2*4;
                        result = (struct Struct_2_t *)((__int64)result + (__int64)ptr2);
                        result = __ROL8__(result, 7);
                        result += (__int64)(__int64)result*8;
                        v_28 = (__int64)result;
                        result = (struct Struct_2_t *)ptr2;
                        result = (struct Struct_2_t *)((__int64)(__int64)result << 17);
                        i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                        i ^= (__int64)ptr2;
                        ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ (__int64)i2);
                        dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                        i = __ROL8__(i, 45);
                        i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
                        result =  + (__int64)(__int64)ptr2*4;
                        result = (struct Struct_2_t *)((__int64)result + (__int64)ptr2);
                        a1 = (size_t *)ptr2;
                        a1 = (size_t *)((__int64)(__int64)a1 << 17);
                        i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                        i ^= (__int64)ptr2;
                        ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ (__int64)i2);
                        ptr->field_10 = ptr2;
                        dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                        ptr->field_8 = dst3;
                        i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)a1);
                        ptr->field_18 = i2;
                        i = __ROL8__(i, 45);
                        ptr->field_20 = i;
                        if ((i2 < 0)) {
                            sub_14002EDF0(0, 144);
                            if (result == 0) JUMPOUT(0x140093f76);
                            ptr2 = (struct Struct_4_t *)result;
                            a1 = (size_t *)v_28;
                            i3 ^= (__int64)a1;
                            result = 0x8000000000000000;
                            *(__int64 *)ptr2 = (__int64)(result);
                            ptr2->field_8 = 1;
                            ptr2->field_10 = i3;
                            ptr2->field_18 = dst2;
                            result = 0x8000000000000001;
                            ptr2->field_30 = result;
                            ptr2->field_38 = 0;
                            ptr2->field_39 = dst2;
                            ptr2->field_48 = 1;
                            ptr2->field_50 = a1;
                            ptr2->field_58 = dst2;
                            ptr2->field_59 = 0x809;
                            ptr2->field_60 = result;
                            ptr2->field_68 = 0;
                            ptr2->field_69 = dst2;
                            ptr2->field_78 = 1;
                            ptr2->field_80 = 0;
                            ptr2->field_88 = dst2;
                            ptr2->field_89 = 0x800;
                            dst2 = 1;
                            i2 = 3;
                            return (__int64)i2;
                        }
                        sub_14002EDF0(0, 96, result);
                        if (result == 0) JUMPOUT(0x140093f85);
                        ptr2 = (struct Struct_4_t *)result;
                        a1 = (size_t *)v_28;
                        i3 ^= (__int64)a1;
                        result = 0x8000000000000000;
                        *(__int64 *)ptr2 = (__int64)(result);
                        ptr2->field_8 = 1;
                        ptr2->field_10 = i3;
                        ptr2->field_18 = dst2;
                        result = 0x8000000000000001;
                        ptr2->field_30 = result;
                        ptr2->field_38 = 0;
                        ptr2->field_39 = dst2;
                        ptr2->field_48 = 1;
                        ptr2->field_50 = a1;
                        ptr2->field_58 = dst2;
                        ptr2->field_59 = 0x809;
                        dst2 = 1;
                        i2 = 2;
                        return (__int64)i2;
                    }
                    if (result != 1) {
                        return (__int64)i2;
                    }
                    result = (struct Struct_2_t *)v_69;
                    if (result > 9) {
                        return (__int64)result;
                    }
                    a1 = &off_1401248A0;
                    switch ((__int64)result) {
                        case 0:
                            dst2 = (__int64 *)v_68;
                            i3 = v_48;
                            result = (struct Struct_2_t *)v_49;
                            v_30 = (__int64)result;
                            a2 = rsp + 72;
                            result = (struct Struct_2_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            v_108 = (__int64)result;
                            v_10e = (int)a1;
                            result = (struct Struct_2_t *)v_58;
                            v_28 = (__int64)result;
                            result = (struct Struct_2_t *)v_59;
                            v_38 = (__int64)result;
                            result = a2[2];
                            a1 = a2[3];
                            v_118 = (__int64)result;
                            v_11e = (int)a1;
                            result = (struct Struct_2_t *)v_6a;
                            v_d0 = (__int64)result;
                            sub_14002EDF0(0, 3, 0x800000000000000D, a4);
                            if (result == 0) JUMPOUT(0x140094c44);
                            v_90 = 3;
                            v_98 = (__int64)result;
                            *(__int64 *)result = (__int64)(dst2);
                            v_a0 = 1;
                            a1 = 1;
                            v_88 = i3;
                            if ((i3 & 1) != 0) {
                                v_70 = (__int64)dst2;
                                if (((v_28 & 1) == 0)) {
                                    result = (struct Struct_2_t *)v_38;
                                    i3 = (__int64)a1;
                                    *(__int64 *)((__int64)a3 + (__int64)a1) = result;
                                    ++i3;
                                    v_a0 = i3;
                                    result =  + (__int64)(__int64)ptr2*4;
                                    result = (struct Struct_2_t *)((__int64)result + (__int64)ptr2);
                                    result = __ROL8__(result, 7);
                                    dst2 = result + (__int64)(__int64)result*8;
                                    result = (struct Struct_2_t *)ptr2;
                                    result = (struct Struct_2_t *)((__int64)(__int64)result << 17);
                                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                                    i ^= (__int64)ptr2;
                                    ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ (__int64)i2);
                                    ptr->field_10 = ptr2;
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                                    ptr->field_8 = dst3;
                                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
                                    i = __ROL8__(i, 45);
                                    ptr->field_18 = i2;
                                    result = (struct Struct_2_t *)dst2;
                                    a1 = 0xAAAAAAAAAAAAAAAB;
                                    result = (struct Struct_2_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                    ptr->field_20 = i;
                                    a2 = (int *)((__int64)(__int64)a2 >> 1);
                                    i2 = a2 + (__int64)(__int64)a2*2;
                                    dst3 = (__int64 *)a3;
                                    sub_140094CC0(ptr, a3, i3, a4);
                                    i = (__int64)result;
                                    dst2 = (__int64 *)((__int64)dst2 - (__int64)i2);
                                    if ((dst2 == 0)) {
                                        if (i3 == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            a2 = (int *)v_98;
                                        }
                                        *(a2 + i3) = i;
                                        ++i3;
                                        dst3 = (__int64 *)a2;
                                        sub_140094CC0(ptr, dst3, i3, a4);
                                        i2 = (__int64 *)result;
                                        sub_14002EDF0(0, 144);
                                        ptr2 = (struct Struct_4_t *)result;
                                        a4 = (int *)v_70;
                                        result = (struct Struct_2_t *)v_88;
                                        if ((result == 0)) JUMPOUT(0x140093f76);
                                        a3 = 0x8000000000000001;
                                        *(__int64 *)ptr2 = (__int64)(a3);
                                        ptr2->field_8 = result;
                                        a3 = (struct Struct_1_t *)result;
                                        dst2 = (__int64 *)v_30;
                                        ptr2->field_9 = dst2;
                                        a2 = rsp + 72;
                                        result = (struct Struct_2_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr2->field_A = result;
                                        ptr2->field_10 = a1;
                                        v6 = v_28;
                                        ptr2->field_18 = v6;
                                        v5 = v_38;
                                        ptr2->field_19 = v5;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr2->field_1A = result;
                                        ptr2->field_20 = a1;
                                        ptr2->field_28 = i;
                                        ptr2->field_29 = 8;
                                        i3 = v_d0;
                                        ptr2->field_2A = i3;
                                        result = 0x8000000000000001;
                                        ptr2->field_30 = result;
                                        ptr2->field_38 = a3;
                                        ptr2->field_39 = dst2;
                                        result = (struct Struct_2_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr2->field_3A = result;
                                        ptr2->field_40 = a1;
                                        ptr2->field_48 = v6;
                                        ptr2->field_49 = v5;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr2->field_50 = a1;
                                        ptr2->field_4A = result;
                                        ptr2->field_58 = i2;
                                        ptr2->field_59 = 7;
                                        ptr2->field_5A = i3;
                                        result = 0x8000000000000001;
                                        ptr2->field_60 = result;
                                        ptr2->field_68 = 0;
                                        ptr2->field_69 = i;
                                        ptr2->field_78 = 0;
                                        ptr2->field_79 = i2;
                                        ptr2->field_88 = a4;
                                        ptr2->field_89 = 0;
                                        ptr2->field_8A = i3;
                                        i2 = 3;
                                        if (v_90 == 0) {
                                            return (__int64)i2;
                                        }
                                        return (__int64)i2;
                                    }
                                    if (dst2 != 1) {
                                        i2 = 3;
                                        if (i3 == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            i2 = (__int64 *)v_90;
                                            a2 = (int *)v_98;
                                        }
                                        *(a2 + i3) = i;
                                        dst2 = i3 + 1;
                                        v_a0 = (__int64)dst2;
                                        dst3 = (__int64 *)a2;
                                        sub_140094CC0(ptr, dst3, dst2, a4);
                                        if (dst2 == i2) {
                                            a1 = rsp + 144;
                                            i2 = (__int64 *)result;
                                            sub_1400FAE10(a1, a2);
                                            result = (struct Struct_2_t *)i2;
                                            a2 = (int *)v_98;
                                        }
                                        v_128 = (__int64)result;
                                        *(a2 + i3 + 1) = result;
                                        dst2 = i3 + 2;
                                        v_a0 = (__int64)dst2;
                                        sub_140094CC0(ptr, dst3, dst2);
                                        dst3 = (__int64 *)v_90;
                                        if (dst2 == dst3) {
                                            a1 = rsp + 144;
                                            i2 = (__int64 *)result;
                                            sub_1400FAE10(a1, a2);
                                            result = (struct Struct_2_t *)i2;
                                            dst3 = (__int64 *)v_90;
                                        }
                                        dst2 = (__int64 *)v_98;
                                        v_cc = (__int64)result;
                                        *(dst2 + i3 + 2) = result;
                                        i2 = i3 + 3;
                                        v_a0 = (__int64)i2;
                                        sub_140094CC0(ptr, dst2, i2);
                                        dst2 = (__int64 *)result;
                                        if (i2 == dst3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1);
                                            a2 = (int *)v_98;
                                        }
                                        *(a2 + i3 + 3) = dst2;
                                        i3 += 4;
                                        dst3 = (__int64 *)a2;
                                        sub_140094CC0(ptr, dst2, i3);
                                        i2 = (__int64 *)result;
                                        sub_14002EDF0(0, 288);
                                        if (result == 0) JUMPOUT(0x140093fe5);
                                        ptr2 = (struct Struct_4_t *)result;
                                        a3 = 0x8000000000000002;
                                        *(__int64 *)result = (__int64)(a3);
                                        a2 = (int *)v_88;
                                        result->field_8 = a2;
                                        v6 = v_30;
                                        result->field_9 = v6;
                                        result = (struct Struct_2_t *)v_108;
                                        a1 = (size_t *)v_10e;
                                        ptr2->field_A = result;
                                        ptr2->field_10 = a1;
                                        ptr2->field_18 = 1;
                                        ptr2->field_19 = i;
                                        ptr2->field_30 = a3;
                                        v5 = v_28;
                                        ptr2->field_38 = v5;
                                        a4 = (int *)v_38;
                                        ptr2->field_39 = a4;
                                        result = (struct Struct_2_t *)v_118;
                                        a1 = (size_t *)v_11e;
                                        ptr2->field_3A = result;
                                        ptr2->field_40 = a1;
                                        ptr2->field_48 = 1;
                                        a1 = (size_t *)v_128;
                                        ptr2->field_49 = a1;
                                        result = 0x8000000000000001;
                                        ptr2->field_60 = result;
                                        i3 = i;
                                        i = (__int64)result;
                                        ptr2->field_68 = 0;
                                        ptr2->field_69 = i3;
                                        ptr2->field_78 = 0;
                                        ptr2->field_79 = a1;
                                        result = (struct Struct_2_t *)v_cc;
                                        ptr2->field_88 = result;
                                        ptr2->field_89 = 7;
                                        i3 = v_d0;
                                        ptr2->field_8A = i3;
                                        ptr2->field_90 = a3;
                                        ptr2->field_98 = 0;
                                        ptr2->field_99 = result;
                                        ptr2->field_A8 = 1;
                                        ptr2->field_A9 = dst2;
                                        ptr2->field_C0 = i;
                                        ptr2->field_C8 = a2;
                                        ptr2->field_C9 = v6;
                                        result = (struct Struct_2_t *)v_108;
                                        a1 = (size_t *)v_10e;
                                        ptr2->field_D0 = a1;
                                        ptr2->field_CA = result;
                                        ptr2->field_D8 = v5;
                                        ptr2->field_D9 = a4;
                                        result = (struct Struct_2_t *)v_118;
                                        a1 = (size_t *)v_11e;
                                        ptr2->field_DA = result;
                                        ptr2->field_E0 = a1;
                                        ptr2->field_E8 = i2;
                                        ptr2->field_E9 = 7;
                                        ptr2->field_EA = i3;
                                        ptr2->field_F0 = i;
                                        ptr2->field_F8 = 0;
                                        ptr2->field_F9 = dst2;
                                        ptr2->field_108 = 0;
                                        ptr2->field_109 = i2;
                                        result = (struct Struct_2_t *)v_70;
                                        ptr2->field_118 = result;
                                        ptr2->field_119 = 0;
                                        ptr2->field_11A = i3;
                                        i2 = 6;
                                        return (__int64)i2;
                                    }
                                    if (i3 == 3) {
                                        a1 = rsp + 144;
                                        sub_1400FAE10(a1, a2, ptr2);
                                        a2 = (int *)v_98;
                                    }
                                    *(a2 + i3) = i;
                                    ++i3;
                                    dst3 = (__int64 *)a2;
                                    sub_140094CC0(ptr, dst3, i3);
                                    i2 = (__int64 *)result;
                                    sub_14002EDF0(0, 192);
                                    if (result == 0) JUMPOUT(0x140093fa5);
                                    ptr2 = (struct Struct_4_t *)result;
                                    a3 = 0x8000000000000001;
                                    *(__int64 *)result = (__int64)(a3);
                                    dst2 = (__int64 *)v_88;
                                    result->field_8 = dst2;
                                    v6 = v_30;
                                    result->field_9 = v6;
                                    a2 = rsp + 72;
                                    result = (struct Struct_2_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr2->field_A = result;
                                    ptr2->field_10 = a1;
                                    v5 = v_28;
                                    ptr2->field_18 = v5;
                                    a4 = (int *)v_38;
                                    ptr2->field_19 = a4;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr2->field_1A = result;
                                    ptr2->field_20 = a1;
                                    ptr2->field_28 = i;
                                    ptr2->field_29 = 9;
                                    i3 = v_d0;
                                    ptr2->field_2A = i3;
                                    ptr2->field_30 = a3;
                                    ptr2->field_38 = dst2;
                                    ptr2->field_39 = v6;
                                    result = (struct Struct_2_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr2->field_3A = result;
                                    ptr2->field_40 = a1;
                                    ptr2->field_48 = v5;
                                    ptr2->field_49 = a4;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr2->field_50 = a1;
                                    ptr2->field_4A = result;
                                    ptr2->field_58 = i2;
                                    ptr2->field_59 = 7;
                                    ptr2->field_5A = i3;
                                    ptr2->field_60 = a3;
                                    ptr2->field_68 = 0;
                                    ptr2->field_69 = i2;
                                    ptr2->field_78 = 1;
                                    ptr2->field_80 = 1;
                                    ptr2->field_88 = i2;
                                    ptr2->field_89 = 10;
                                    ptr2->field_8A = i3;
                                    ptr2->field_90 = a3;
                                    ptr2->field_98 = 0;
                                    ptr2->field_99 = i;
                                    ptr2->field_A8 = 0;
                                    ptr2->field_A9 = i2;
                                    result = (struct Struct_2_t *)v_70;
                                    ptr2->field_B8 = result;
                                    ptr2->field_B9 = 0;
                                    ptr2->field_BA = i3;
                                    i2 = 4;
                                    return (__int64)i2;
                                }
                                i3 = (__int64)a1;
                                return i3;
                            }
                            result = (struct Struct_2_t *)v_30;
                            a3->field_1 = result;
                            v_a0 = 2;
                            a1 = 2;
                            return (__int64)a1;
                        case 1:
                            dst3 = (__int64 *)v_68;
                            ptr2 = (struct Struct_4_t *)v_48;
                            i3 = v_49;
                            dst2 = (__int64 *)v_58;
                            i = v_59;
                            sub_14002EDF0(0, 3, 2, result);
                            if (result == 0) JUMPOUT(0x140094c44);
                            i2 = (__int64 *)result;
                            *(__int64 *)result = (__int64)(dst3);
                            a3 = 1;
                            if (((__int64)ptr2 & 1) != 0) {
                                if (((__int64)dst2 & 1) != 0) {
                                    sub_140094CC0(ptr, i2, a3);
                                    i = (__int64)result;
                                    off_140108030();
                                    off_140108038(result, 0, i2);
                                    sub_14002EDF0(0, 144);
                                    if (result == 0) JUMPOUT(0x140093f76);
                                    ptr2 = (struct Struct_4_t *)result;
                                    a1 = rsp + 72;
                                    xmm0 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                    _mm_storeu_si128((__m128i *)(result + 8), xmm0);
                                    result = (struct Struct_2_t *)v_6a;
                                    xmm0 = _mm_loadu_si128((__m128i *)a1);
                                    _mm_storeu_si128((__m128i *)(ptr2 + 104), xmm0);
                                    a1 = 0x8000000000000002;
                                    *(__int64 *)ptr2 = (__int64)(a1);
                                    ptr2->field_18 = 1;
                                    ptr2->field_19 = i;
                                    a1 = 0x8000000000000001;
                                    ptr2->field_30 = a1;
                                    ptr2->field_38 = 0;
                                    ptr2->field_39 = i;
                                    ptr2->field_48 = 1;
                                    ptr2->field_50 = 1;
                                    ptr2->field_58 = i;
                                    ptr2->field_59 = 0;
                                    ptr2->field_5A = result;
                                    ptr2->field_60 = a1;
                                    ptr2->field_78 = 0;
                                    ptr2->field_79 = i;
                                    ptr2->field_88 = dst3;
                                    ptr2->field_89 = 0;
                                    ptr2->field_8A = result;
                                    return (__int64)a1;
                                }
                                *(__int64 *)((__int64)i2 + (__int64)a3) = i;
                                ++a3;
                                return (__int64)a3;
                            }
                            *(i2 + 1) = i3;
                            a3 = 2;
                            return (__int64)a3;
                        case 2:
                            return (__int64)a3;
                        case 7:
                            dst = (__int64 *)v_68;
                            i3 = v_48;
                            dst2 = (__int64 *)v_49;
                            a2 = rsp + 72;
                            result = (struct Struct_2_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            v_108 = (__int64)result;
                            v_10e = (int)a1;
                            result = (struct Struct_2_t *)v_58;
                            v_28 = (__int64)result;
                            result = (struct Struct_2_t *)v_59;
                            v_38 = (__int64)result;
                            result = a2[2];
                            a1 = a2[3];
                            v_118 = (__int64)result;
                            v_11e = (int)a1;
                            result = (struct Struct_2_t *)v_6a;
                            v_70 = (__int64)result;
                            sub_14002EDF0(0, 3);
                            if (result == 0) JUMPOUT(0x140094c44);
                            v_90 = 3;
                            v_98 = (__int64)result;
                            *(__int64 *)result = (__int64)(dst);
                            v_a0 = 1;
                            a3 = 1;
                            if ((i3 & 1) != 0) {
                                v_88 = (__int64)dst;
                                v_30 = (__int64)dst2;
                                v_d0 = i3;
                                if (((v_28 & 1) == 0)) {
                                    i3 = v_38;
                                    *(__int64 *)((__int64)a4 + (__int64)a3) = i3;
                                    ++a3;
                                    v_a0 = (__int64)a3;
                                    result =  + (__int64)(__int64)ptr2*4;
                                    result = (struct Struct_2_t *)((__int64)result + (__int64)ptr2);
                                    result = __ROL8__(result, 7);
                                    dst2 = result + (__int64)(__int64)result*8;
                                    result = (struct Struct_2_t *)ptr2;
                                    result = (struct Struct_2_t *)((__int64)(__int64)result << 17);
                                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                                    i ^= (__int64)ptr2;
                                    ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ (__int64)i2);
                                    ptr->field_10 = ptr2;
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                                    ptr->field_8 = dst3;
                                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
                                    i = __ROL8__(i, 45);
                                    ptr->field_18 = i2;
                                    result = (struct Struct_2_t *)dst2;
                                    a1 = 0xAAAAAAAAAAAAAAAB;
                                    result = (struct Struct_2_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                    ptr->field_20 = i;
                                    a2 = (int *)((__int64)(__int64)a2 >> 1);
                                    dst = a2 + (__int64)(__int64)a2*2;
                                    i = (__int64)a4;
                                    ptr2 = (struct Struct_4_t *)a3;
                                    sub_140094CC0(ptr, a4, a3);
                                    i2 = (__int64 *)result;
                                    dst2 = (__int64 *)((__int64)dst2 - (__int64)dst);
                                    if ((dst2 == 0)) {
                                        a3 = (struct Struct_1_t *)ptr2;
                                        if (a3 == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2, ptr2);
                                            a2 = (int *)v_98;
                                        }
                                        *(__int64 *)((__int64)a2 + (__int64)a3) = i2;
                                        ++a3;
                                        sub_140094CC0(ptr, i, a3, a4);
                                        i = (__int64)result;
                                        sub_14002EDF0(0, 144);
                                        dst = &off_1401190A3;
                                        v5 = v_30;
                                        if (result == 0) JUMPOUT(0x140093f76);
                                        ptr2 = (struct Struct_4_t *)result;
                                        a3 = 0x8000000000000001;
                                        *(__int64 *)result = (__int64)(a3);
                                        v6 = v_d0;
                                        result->field_8 = v6;
                                        result->field_9 = v5;
                                        a2 = rsp + 72;
                                        result = (struct Struct_2_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr2->field_A = result;
                                        ptr2->field_10 = a1;
                                        dst3 = (__int64 *)v_28;
                                        ptr2->field_18 = dst3;
                                        ptr2->field_19 = i3;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr2->field_1A = result;
                                        ptr2->field_20 = a1;
                                        ptr2->field_28 = i2;
                                        ptr2->field_29 = 8;
                                        a4 = (int *)v_70;
                                        ptr2->field_2A = a4;
                                        ptr2->field_30 = a3;
                                        ptr2->field_38 = v6;
                                        ptr2->field_39 = v5;
                                        result = (struct Struct_2_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr2->field_3A = result;
                                        ptr2->field_40 = a1;
                                        ptr2->field_48 = dst3;
                                        ptr2->field_49 = i3;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr2->field_50 = a1;
                                        ptr2->field_4A = result;
                                        ptr2->field_58 = i;
                                        ptr2->field_59 = 9;
                                        ptr2->field_5A = a4;
                                        ptr2->field_60 = a3;
                                        ptr2->field_68 = 0;
                                        ptr2->field_69 = i2;
                                        ptr2->field_78 = 0;
                                        ptr2->field_79 = i;
                                        result = (struct Struct_2_t *)v_88;
                                        ptr2->field_88 = result;
                                        ptr2->field_89 = 1;
                                        ptr2->field_8A = a4;
                                        i2 = 3;
                                        if (v_90 != 0) {
                                            return (__int64)i2;
                                        }
                                        return (__int64)i2;
                                    }
                                    if (dst2 != 1) {
                                        dst3 = 3;
                                        result = (struct Struct_2_t *)ptr2;
                                        dst = &off_1401190A3;
                                        if (result == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            result = (struct Struct_2_t *)ptr2;
                                            dst3 = (__int64 *)v_90;
                                            a2 = (int *)v_98;
                                        }
                                        *(__int64 *)((__int64)a2 + (__int64)result) = i2;
                                        dst2 = result + 1;
                                        v_a0 = (__int64)dst2;
                                        ptr2 = (struct Struct_4_t *)result;
                                        i = (__int64)a2;
                                        sub_140094CC0(ptr, i, dst2, a4);
                                        i = (__int64)result;
                                        if (dst2 == dst3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            a2 = (int *)v_98;
                                        }
                                        *(__int64 *)((__int64)a2 + (__int64)ptr2 + 1) = i;
                                        ptr2 += 2;
                                        sub_140094CC0(ptr, i, ptr2);
                                        dst3 = (__int64 *)result;
                                        sub_14002EDF0(0, 192);
                                        a1 = (size_t *)v_30;
                                        if (result == 0) JUMPOUT(0x140093fa5);
                                        ptr2 = (struct Struct_4_t *)result;
                                        a2 = 0x8000000000000002;
                                        *(__int64 *)result = (__int64)(a2);
                                        result = (struct Struct_2_t *)v_d0;
                                        ptr2->field_8 = result;
                                        ptr2->field_9 = a1;
                                        result = (struct Struct_2_t *)v_108;
                                        a1 = (size_t *)v_10e;
                                        ptr2->field_A = result;
                                        ptr2->field_10 = a1;
                                        ptr2->field_18 = 1;
                                        ptr2->field_19 = i2;
                                        ptr2->field_30 = a2;
                                        result = (struct Struct_2_t *)v_28;
                                        ptr2->field_38 = result;
                                        ptr2->field_39 = i3;
                                        result = (struct Struct_2_t *)v_118;
                                        a1 = (size_t *)v_11e;
                                        ptr2->field_3A = result;
                                        ptr2->field_40 = a1;
                                        ptr2->field_48 = 1;
                                        ptr2->field_49 = i;
                                        result = 0x8000000000000001;
                                        ptr2->field_60 = result;
                                        ptr2->field_68 = 0;
                                        ptr2->field_69 = i2;
                                        ptr2->field_78 = 0;
                                        ptr2->field_79 = i;
                                        ptr2->field_88 = dst3;
                                        ptr2->field_89 = 8;
                                        return (__int64)result;
                                    }
                                    a3 = (struct Struct_1_t *)ptr2;
                                    dst = &off_1401190A3;
                                    if (a3 == 3) {
                                        a1 = rsp + 144;
                                        sub_1400FAE10(a1);
                                        a2 = (int *)v_98;
                                    }
                                    *(__int64 *)((__int64)a2 + (__int64)a3) = i2;
                                    ++a3;
                                    sub_140094CC0(ptr, i, a3);
                                    i = (__int64)result;
                                    sub_14002EDF0(0, 144);
                                    v5 = v_30;
                                    if (result == 0) JUMPOUT(0x140093f76);
                                    ptr2 = (struct Struct_4_t *)result;
                                    result = 0x8000000000000002;
                                    *(__int64 *)ptr2 = (__int64)(result);
                                    result = (struct Struct_2_t *)v_28;
                                    ptr2->field_8 = result;
                                    ptr2->field_9 = i3;
                                    a2 = rsp + 72;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr2->field_A = result;
                                    ptr2->field_10 = a1;
                                    ptr2->field_18 = 1;
                                    ptr2->field_19 = i2;
                                    a3 = 0x8000000000000001;
                                    ptr2->field_30 = a3;
                                    v6 = v_d0;
                                    ptr2->field_38 = v6;
                                    ptr2->field_39 = v5;
                                    result = (struct Struct_2_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr2->field_3A = result;
                                    ptr2->field_40 = a1;
                                    ptr2->field_48 = 0;
                                    ptr2->field_49 = i2;
                                    ptr2->field_58 = i;
                                    ptr2->field_59 = 7;
                                    a4 = (int *)v_70;
                                    ptr2->field_5A = a4;
                                    ptr2->field_60 = a3;
                                    ptr2->field_68 = v6;
                                    ptr2->field_69 = v5;
                                    result = (struct Struct_2_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr2->field_70 = a1;
                                    ptr2->field_6A = result;
                                    return (__int64)a1;
                                }
                                i3 = v_38;
                                return i3;
                            }
                            *(a4 + 1) = dst2;
                            v_a0 = 2;
                            return v_a0;
                        case 8:
                            dst = (__int64 *)v_68;
                            i3 = v_48;
                            result = (struct Struct_2_t *)v_49;
                            v_38 = (__int64)result;
                            a2 = rsp + 72;
                            result = (struct Struct_2_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            v_108 = (__int64)result;
                            v_10e = (int)a1;
                            result = (struct Struct_2_t *)v_58;
                            v_28 = (__int64)result;
                            dst2 = (__int64 *)v_59;
                            result = a2[2];
                            a1 = a2[3];
                            v_118 = (__int64)result;
                            v_11e = (int)a1;
                            result = (struct Struct_2_t *)v_6a;
                            v_70 = (__int64)result;
                            sub_14002EDF0(0, 3);
                            if (result == 0) JUMPOUT(0x140094c44);
                            v_90 = 3;
                            v_98 = (__int64)result;
                            *(__int64 *)result = (__int64)(dst);
                            v_a0 = 1;
                            a3 = 1;
                            if ((i3 & 1) != 0) {
                                v_88 = (__int64)dst;
                                v_30 = (__int64)dst2;
                                if (((v_28 & 1) != 0)) {
                                    result =  + (__int64)(__int64)ptr2*4;
                                    result = (struct Struct_2_t *)((__int64)result + (__int64)ptr2);
                                    result = __ROL8__(result, 7);
                                    dst2 = result + (__int64)(__int64)result*8;
                                    result = (struct Struct_2_t *)ptr2;
                                    result = (struct Struct_2_t *)((__int64)(__int64)result << 17);
                                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                                    i ^= (__int64)ptr2;
                                    ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ (__int64)i2);
                                    ptr->field_10 = ptr2;
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                                    ptr->field_8 = dst3;
                                    i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
                                    i = __ROL8__(i, 45);
                                    ptr->field_18 = i2;
                                    result = (struct Struct_2_t *)dst2;
                                    a1 = 0xAAAAAAAAAAAAAAAB;
                                    result = (struct Struct_2_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                    ptr->field_20 = i;
                                    a2 = (int *)((__int64)(__int64)a2 >> 1);
                                    dst = a2 + (__int64)(__int64)a2*2;
                                    i = (__int64)a4;
                                    ptr2 = (struct Struct_4_t *)a3;
                                    sub_140094CC0(ptr, a4, a3, result);
                                    i2 = (__int64 *)result;
                                    dst2 = (__int64 *)((__int64)dst2 - (__int64)dst);
                                    if ((dst2 == 0)) {
                                        a3 = (struct Struct_1_t *)ptr2;
                                        if (a3 == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            a2 = (int *)v_98;
                                        }
                                        *(__int64 *)((__int64)a2 + (__int64)a3) = i2;
                                        ++a3;
                                        sub_140094CC0(ptr, i, a3);
                                        i = (__int64)result;
                                        sub_14002EDF0(0, 144);
                                        dst = &off_1401190A3;
                                        v5 = v_30;
                                        if (result == 0) JUMPOUT(0x140093f76);
                                        ptr2 = (struct Struct_4_t *)result;
                                        a3 = 0x8000000000000001;
                                        *(__int64 *)result = (__int64)(a3);
                                        result->field_8 = i3;
                                        dst3 = (__int64 *)v_38;
                                        result->field_9 = dst3;
                                        a2 = rsp + 72;
                                        result = (struct Struct_2_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr2->field_A = result;
                                        ptr2->field_10 = a1;
                                        v6 = v_28;
                                        ptr2->field_18 = v6;
                                        ptr2->field_19 = v5;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr2->field_1A = result;
                                        ptr2->field_20 = a1;
                                        ptr2->field_28 = i2;
                                        ptr2->field_29 = 0;
                                        a4 = (int *)v_70;
                                        ptr2->field_2A = a4;
                                        ptr2->field_30 = a3;
                                        ptr2->field_38 = i3;
                                        ptr2->field_39 = dst3;
                                        result = (struct Struct_2_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr2->field_3A = result;
                                        ptr2->field_40 = a1;
                                        ptr2->field_48 = v6;
                                        ptr2->field_49 = v5;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr2->field_50 = a1;
                                        ptr2->field_4A = result;
                                        ptr2->field_58 = i;
                                        ptr2->field_59 = 7;
                                        ptr2->field_5A = a4;
                                        ptr2->field_60 = a3;
                                        ptr2->field_68 = 0;
                                        ptr2->field_69 = i2;
                                        ptr2->field_78 = 0;
                                        ptr2->field_79 = i;
                                        result = (struct Struct_2_t *)v_88;
                                        ptr2->field_88 = result;
                                        ptr2->field_89 = 1;
                                        ptr2->field_8A = a4;
                                        i2 = 3;
                                        if (v_90 != 0) {
                                            dst3 = (__int64 *)v_98;
                                            off_140108030(a1, a2, 0x8000000000000002, a4);
                                            off_140108038(result, 0, dst3);
                                            dst2 = 1;
                                            return (__int64)dst2;
                                        }
                                        return (__int64)dst2;
                                    }
                                    if (dst2 != 1) {
                                        dst3 = 3;
                                        result = (struct Struct_2_t *)ptr2;
                                        dst = &off_1401190A3;
                                        if (result == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            result = (struct Struct_2_t *)ptr2;
                                            dst3 = (__int64 *)v_90;
                                            a2 = (int *)v_98;
                                        }
                                        *(__int64 *)((__int64)a2 + (__int64)result) = i2;
                                        dst2 = result + 1;
                                        v_a0 = (__int64)dst2;
                                        ptr2 = (struct Struct_4_t *)result;
                                        i = (__int64)a2;
                                        sub_140094CC0(ptr, i, dst2, a4);
                                        i = (__int64)result;
                                        if (dst2 == dst3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            a2 = (int *)v_98;
                                        }
                                        *(__int64 *)((__int64)a2 + (__int64)ptr2 + 1) = i;
                                        ptr2 += 2;
                                        sub_140094CC0(ptr, i, ptr2);
                                        dst3 = (__int64 *)result;
                                        sub_14002EDF0(0, 192);
                                        a3 = (struct Struct_1_t *)v_30;
                                        if (result == 0) JUMPOUT(0x140093fa5);
                                        ptr2 = (struct Struct_4_t *)result;
                                        a2 = 0x8000000000000002;
                                        *(__int64 *)result = (__int64)(a2);
                                        result->field_8 = i3;
                                        result = (struct Struct_2_t *)v_38;
                                        ptr2->field_9 = result;
                                        result = (struct Struct_2_t *)v_108;
                                        a1 = (size_t *)v_10e;
                                        ptr2->field_A = result;
                                        ptr2->field_10 = a1;
                                        ptr2->field_18 = 1;
                                        ptr2->field_19 = i2;
                                        ptr2->field_30 = a2;
                                        result = (struct Struct_2_t *)v_28;
                                        ptr2->field_38 = result;
                                        ptr2->field_39 = a3;
                                        result = (struct Struct_2_t *)v_118;
                                        a1 = (size_t *)v_11e;
                                        ptr2->field_3A = result;
                                        ptr2->field_40 = a1;
                                        ptr2->field_48 = 1;
                                        ptr2->field_49 = i;
                                        result = 0x8000000000000001;
                                        ptr2->field_60 = result;
                                        ptr2->field_68 = 0;
                                        ptr2->field_69 = i2;
                                        ptr2->field_78 = 0;
                                        ptr2->field_79 = i;
                                        ptr2->field_88 = dst3;
                                        ptr2->field_89 = 7;
                                        result = (struct Struct_2_t *)v_70;
                                        ptr2->field_8A = result;
                                        ptr2->field_90 = a2;
                                        ptr2->field_98 = 0;
                                        ptr2->field_99 = dst3;
                                        ptr2->field_A8 = 1;
                                        result = (struct Struct_2_t *)v_88;
                                        ptr2->field_A9 = result;
                                        i2 = 4;
                                        if (v_90 == 0) {
                                            return (__int64)i2;
                                        }
                                        return (__int64)i2;
                                    }
                                    a3 = (struct Struct_1_t *)ptr2;
                                    dst = &off_1401190A3;
                                    if (a3 == 3) {
                                        a1 = rsp + 144;
                                        sub_1400FAE10(a1, a2);
                                        a2 = (int *)v_98;
                                    }
                                    *(__int64 *)((__int64)a2 + (__int64)a3) = i2;
                                    ++a3;
                                    sub_140094CC0(ptr, i, a3);
                                    i = (__int64)result;
                                    sub_14002EDF0(0, 144);
                                    v5 = v_30;
                                    if (result == 0) JUMPOUT(0x140093f76);
                                    ptr2 = (struct Struct_4_t *)result;
                                    *(__int64 *)result = (__int64)(a3);
                                    result->field_8 = i3;
                                    dst3 = (__int64 *)v_38;
                                    result->field_9 = dst3;
                                    a2 = rsp + 72;
                                    result = (struct Struct_2_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr2->field_A = result;
                                    ptr2->field_10 = a1;
                                    v6 = v_28;
                                    ptr2->field_18 = v6;
                                    ptr2->field_19 = v5;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr2->field_1A = result;
                                    ptr2->field_20 = a1;
                                    ptr2->field_28 = i2;
                                    ptr2->field_29 = 9;
                                    a4 = (int *)v_70;
                                    ptr2->field_2A = a4;
                                    ptr2->field_30 = a3;
                                    ptr2->field_38 = i3;
                                    ptr2->field_39 = dst3;
                                    result = (struct Struct_2_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr2->field_3A = result;
                                    ptr2->field_40 = a1;
                                    ptr2->field_48 = v6;
                                    ptr2->field_49 = v5;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr2->field_50 = a1;
                                    ptr2->field_4A = result;
                                    ptr2->field_58 = i;
                                    ptr2->field_59 = 7;
                                    ptr2->field_5A = a4;
                                    ptr2->field_60 = a3;
                                    ptr2->field_68 = 0;
                                    ptr2->field_69 = i2;
                                    ptr2->field_78 = 0;
                                    ptr2->field_79 = i;
                                    result = (struct Struct_2_t *)v_88;
                                    ptr2->field_88 = result;
                                    ptr2->field_89 = 0;
                                    return (__int64)result;
                                }
                                *(__int64 *)((__int64)a4 + (__int64)a3) = dst2;
                                ++a3;
                                v_a0 = (__int64)a3;
                                return v_a0;
                            }
                            result = (struct Struct_2_t *)v_38;
                            *(a4 + 1) = result;
                            v_a0 = 2;
                            a3 = 2;
                            return (__int64)a3;
                        case 9:
                            dst2 = (__int64 *)v_68;
                            i3 = v_48;
                            result = (struct Struct_2_t *)v_49;
                            v_30 = (__int64)result;
                            a2 = rsp + 72;
                            result = (struct Struct_2_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            v_108 = (__int64)result;
                            v_10e = (int)a1;
                            result = (struct Struct_2_t *)v_58;
                            v_28 = (__int64)result;
                            result = (struct Struct_2_t *)v_59;
                            v_38 = (__int64)result;
                            result = a2[2];
                            a1 = a2[3];
                            v_118 = (__int64)result;
                            v_11e = (int)a1;
                            result = (struct Struct_2_t *)v_6a;
                            v_d0 = (__int64)result;
                            sub_14002EDF0(0, 3, 0x8000000000000001, a4);
                            if (result == 0) JUMPOUT(0x140094c44);
                            break;
                    }
                    a3 = (struct Struct_1_t *)result;
                    v_90 = 3;
                    v_98 = (__int64)result;
                    *(__int64 *)result = (__int64)(dst2);
                    v_a0 = 1;
                    a1 = 1;
                    v_88 = i3;
                    if ((i3 & 1) != 0) {
                        v_70 = (__int64)dst2;
                        if (((v_28 & 1) == 0)) {
                            result = (struct Struct_2_t *)v_38;
                            i3 = (__int64)a1;
                            *(__int64 *)((__int64)a3 + (__int64)a1) = result;
                            ++i3;
                            v_a0 = i3;
                            result =  + (__int64)(__int64)ptr2*4;
                            result = (struct Struct_2_t *)((__int64)result + (__int64)ptr2);
                            result = __ROL8__(result, 7);
                            dst2 = result + (__int64)(__int64)result*8;
                            result = (struct Struct_2_t *)ptr2;
                            result = (struct Struct_2_t *)((__int64)(__int64)result << 17);
                            i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)dst3);
                            i ^= (__int64)ptr2;
                            ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 ^ (__int64)i2);
                            ptr->field_10 = ptr2;
                            dst3 = (__int64 *)((__int64)(__int64)dst3 ^ i);
                            ptr->field_8 = dst3;
                            i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
                            i = __ROL8__(i, 45);
                            ptr->field_18 = i2;
                            result = (struct Struct_2_t *)dst2;
                            a1 = 0xAAAAAAAAAAAAAAAB;
                            result = (struct Struct_2_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                            ptr->field_20 = i;
                            a2 = (int *)((__int64)(__int64)a2 >> 1);
                            i2 = a2 + (__int64)(__int64)a2*2;
                            dst3 = (__int64 *)a3;
                            sub_140094CC0(ptr, a3, i3, a4);
                            i = (__int64)result;
                            dst2 = (__int64 *)((__int64)dst2 - (__int64)i2);
                            if ((dst2 == 0)) {
                                if (i3 == 3) {
                                    a1 = rsp + 144;
                                    sub_1400FAE10(a1, a2, ptr2);
                                    a2 = (int *)v_98;
                                }
                                *(a2 + i3) = i;
                                ++i3;
                                dst3 = (__int64 *)a2;
                                sub_140094CC0(ptr, dst3, i3, a4);
                                i2 = (__int64 *)result;
                                sub_14002EDF0(0, 144);
                                ptr2 = (struct Struct_4_t *)result;
                                a4 = (int *)v_70;
                                result = (struct Struct_2_t *)v_88;
                                if ((result == 0)) JUMPOUT(0x140093f76);
                                a3 = 0x8000000000000001;
                                *(__int64 *)ptr2 = (__int64)(a3);
                                ptr2->field_8 = result;
                                a3 = (struct Struct_1_t *)result;
                                dst2 = (__int64 *)v_30;
                                ptr2->field_9 = dst2;
                                a2 = rsp + 72;
                                result = (struct Struct_2_t *)arg_2;
                                a1 = (size_t *)arg_8;
                                ptr2->field_A = result;
                                ptr2->field_10 = a1;
                                v6 = v_28;
                                ptr2->field_18 = v6;
                                v5 = v_38;
                                ptr2->field_19 = v5;
                                result = a2[2];
                                a1 = a2[3];
                                ptr2->field_1A = result;
                                ptr2->field_20 = a1;
                                ptr2->field_28 = i;
                                ptr2->field_29 = 8;
                                i3 = v_d0;
                                ptr2->field_2A = i3;
                                result = 0x8000000000000001;
                                ptr2->field_30 = result;
                                ptr2->field_38 = a3;
                                ptr2->field_39 = dst2;
                                result = (struct Struct_2_t *)arg_2;
                                a1 = (size_t *)arg_8;
                                ptr2->field_3A = result;
                                ptr2->field_40 = a1;
                                ptr2->field_48 = v6;
                                ptr2->field_49 = v5;
                                result = a2[2];
                                a1 = a2[3];
                                ptr2->field_50 = a1;
                                ptr2->field_4A = result;
                                ptr2->field_58 = i2;
                                ptr2->field_59 = 7;
                                ptr2->field_5A = i3;
                                result = 0x8000000000000001;
                                ptr2->field_60 = result;
                                ptr2->field_68 = 0;
                                ptr2->field_69 = i;
                                ptr2->field_78 = 0;
                                ptr2->field_79 = i2;
                                ptr2->field_88 = a4;
                                ptr2->field_89 = 1;
                                ptr2->field_8A = i3;
                                i2 = 3;
                                return (__int64)i2;
                            }
                            if (dst2 != 1) {
                                i2 = 3;
                                if (i3 == 3) {
                                    a1 = rsp + 144;
                                    sub_1400FAE10(a1, a2);
                                    i2 = (__int64 *)v_90;
                                    a2 = (int *)v_98;
                                }
                                *(a2 + i3) = i;
                                dst2 = i3 + 1;
                                v_a0 = (__int64)dst2;
                                dst3 = (__int64 *)a2;
                                sub_140094CC0(ptr, dst3, dst2);
                                if (dst2 == i2) {
                                    a1 = rsp + 144;
                                    i2 = (__int64 *)result;
                                    sub_1400FAE10(a1, a2);
                                    result = (struct Struct_2_t *)i2;
                                    a2 = (int *)v_98;
                                }
                                v_128 = (__int64)result;
                                *(a2 + i3 + 1) = result;
                                dst2 = i3 + 2;
                                v_a0 = (__int64)dst2;
                                sub_140094CC0(ptr, dst3, dst2);
                                dst3 = (__int64 *)v_90;
                                if (dst2 == dst3) {
                                    a1 = rsp + 144;
                                    i2 = (__int64 *)result;
                                    sub_1400FAE10(a1, a2);
                                    result = (struct Struct_2_t *)i2;
                                    dst3 = (__int64 *)v_90;
                                }
                                dst2 = (__int64 *)v_98;
                                v_cc = (__int64)result;
                                *(dst2 + i3 + 2) = result;
                                i2 = i3 + 3;
                                v_a0 = (__int64)i2;
                                sub_140094CC0(ptr, dst2, i2);
                                dst2 = (__int64 *)result;
                                if (i2 == dst3) {
                                    a1 = rsp + 144;
                                    sub_1400FAE10(a1);
                                    a2 = (int *)v_98;
                                }
                                *(a2 + i3 + 3) = dst2;
                                i3 += 4;
                                dst3 = (__int64 *)a2;
                                sub_140094CC0(ptr, dst2, i3);
                                i2 = (__int64 *)result;
                                sub_14002EDF0(0, 288);
                                if (result == 0) JUMPOUT(0x140093fe5);
                                ptr2 = (struct Struct_4_t *)result;
                                *(__int64 *)result = (__int64)(a3);
                                a2 = (int *)v_88;
                                result->field_8 = a2;
                                v6 = v_30;
                                result->field_9 = v6;
                                result = (struct Struct_2_t *)v_108;
                                a1 = (size_t *)v_10e;
                                ptr2->field_A = result;
                                ptr2->field_10 = a1;
                                ptr2->field_18 = 1;
                                ptr2->field_19 = i;
                                ptr2->field_30 = a3;
                                v5 = v_28;
                                ptr2->field_38 = v5;
                                a4 = (int *)v_38;
                                ptr2->field_39 = a4;
                                result = (struct Struct_2_t *)v_118;
                                a1 = (size_t *)v_11e;
                                ptr2->field_3A = result;
                                ptr2->field_40 = a1;
                                ptr2->field_48 = 1;
                                a1 = (size_t *)v_128;
                                ptr2->field_49 = a1;
                                result = 0x8000000000000001;
                                ptr2->field_60 = result;
                                i3 = i;
                                i = (__int64)result;
                                ptr2->field_68 = 0;
                                ptr2->field_69 = i3;
                                ptr2->field_78 = 0;
                                ptr2->field_79 = a1;
                                result = (struct Struct_2_t *)v_cc;
                                ptr2->field_88 = result;
                                ptr2->field_89 = 7;
                                i3 = v_d0;
                                ptr2->field_8A = i3;
                                ptr2->field_90 = a3;
                                ptr2->field_98 = 0;
                                ptr2->field_99 = result;
                                ptr2->field_A8 = 1;
                                ptr2->field_A9 = dst2;
                                ptr2->field_C0 = i;
                                ptr2->field_C8 = a2;
                                ptr2->field_C9 = v6;
                                result = (struct Struct_2_t *)v_108;
                                a1 = (size_t *)v_10e;
                                ptr2->field_D0 = a1;
                                ptr2->field_CA = result;
                                ptr2->field_D8 = v5;
                                ptr2->field_D9 = a4;
                                result = (struct Struct_2_t *)v_118;
                                a1 = (size_t *)v_11e;
                                ptr2->field_DA = result;
                                ptr2->field_E0 = a1;
                                ptr2->field_E8 = i2;
                                ptr2->field_E9 = 7;
                                ptr2->field_EA = i3;
                                ptr2->field_F0 = i;
                                ptr2->field_F8 = 0;
                                ptr2->field_F9 = dst2;
                                ptr2->field_108 = 0;
                                ptr2->field_109 = i2;
                                result = (struct Struct_2_t *)v_70;
                                ptr2->field_118 = result;
                                ptr2->field_119 = 1;
                                return (__int64)result;
                            }
                            if (i3 == 3) {
                                a1 = rsp + 144;
                                sub_1400FAE10(a1, a2, ptr2);
                                a2 = (int *)v_98;
                            }
                            *(a2 + i3) = i;
                            ++i3;
                            dst3 = (__int64 *)a2;
                            sub_140094CC0(ptr, dst3, i3);
                            i2 = (__int64 *)result;
                            sub_14002EDF0(0, 192);
                            if (result == 0) JUMPOUT(0x140093fa5);
                            ptr2 = (struct Struct_4_t *)result;
                            a3 = 0x8000000000000001;
                            *(__int64 *)result = (__int64)(a3);
                            dst2 = (__int64 *)v_88;
                            result->field_8 = dst2;
                            v6 = v_30;
                            result->field_9 = v6;
                            a2 = rsp + 72;
                            result = (struct Struct_2_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            ptr2->field_A = result;
                            ptr2->field_10 = a1;
                            v5 = v_28;
                            ptr2->field_18 = v5;
                            a4 = (int *)v_38;
                            ptr2->field_19 = a4;
                            result = a2[2];
                            a1 = a2[3];
                            ptr2->field_1A = result;
                            ptr2->field_20 = a1;
                            ptr2->field_28 = i;
                            ptr2->field_29 = 0;
                            i3 = v_d0;
                            ptr2->field_2A = i3;
                            ptr2->field_30 = a3;
                            ptr2->field_38 = dst2;
                            ptr2->field_39 = v6;
                            result = (struct Struct_2_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            ptr2->field_3A = result;
                            ptr2->field_40 = a1;
                            ptr2->field_48 = v5;
                            ptr2->field_49 = a4;
                            result = a2[2];
                            a1 = a2[3];
                            ptr2->field_50 = a1;
                            ptr2->field_4A = result;
                            ptr2->field_58 = i2;
                            ptr2->field_59 = 7;
                            ptr2->field_5A = i3;
                            ptr2->field_60 = a3;
                            ptr2->field_68 = 0;
                            ptr2->field_69 = i2;
                            ptr2->field_78 = 1;
                            ptr2->field_80 = 1;
                            ptr2->field_88 = i2;
                            ptr2->field_89 = 10;
                            ptr2->field_8A = i3;
                            ptr2->field_90 = a3;
                            ptr2->field_98 = 0;
                            ptr2->field_99 = i;
                            ptr2->field_A8 = 0;
                            ptr2->field_A9 = i2;
                            result = (struct Struct_2_t *)v_70;
                            ptr2->field_B8 = result;
                            ptr2->field_B9 = 1;
                            ptr2->field_BA = i3;
                            i2 = 4;
                            return (__int64)i2;
                        }
                        i3 = (__int64)a1;
                        return i3;
                    }
                    result = (struct Struct_2_t *)v_30;
                    a3->field_1 = result;
                    v_a0 = 2;
                    a1 = 2;
                    return (__int64)a1;
                }
                a3 = (struct Struct_1_t *)i2;
                a3 = (struct Struct_1_t *)((__int64)(__int64)a3 << 17);
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)i2);
                a4 = (int *)a1;
                a4 = (int *)((__int64)(__int64)a4 ^ (__int64)i2);
                ptr->field_10 = a4;
                a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                ptr->field_8 = a2;
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a3);
                result = __ROL8__(result, 45);
                ptr->field_18 = a1;
                ptr->field_20 = result;
                if (i == v_d8) {
                    a1 = rsp + 216;
                    sub_1400F87E0(a1);
                    v6 = 0xE38E38E38E38E38F;
                }
                result = i2 + (__int64)(__int64)i2*4;
                result = __ROL8__(result, 7);
                result += (__int64)(__int64)result*8;
                a1 = (size_t *)v_e0;
                a2 =  + i*2;
                a2 += i;
                a2 = (int *)((__int64)(__int64)a2 << 4);
                *(__int64 *)((__int64)a1 + (__int64)a2) = a3;
                *(__int64 *)((__int64)a1 + (__int64)a2 + 8) = result;
                ++i;
                ptr->field_38 = ptr->field_38 + 1;
                v_e8 = i;
                ptr->field_28 = ptr->field_28 + 1;
                return v_e8;
            }
            a3 = (struct Struct_1_t *)i2;
            a3 = (struct Struct_1_t *)((__int64)(__int64)a3 << 17);
            a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
            result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)i2);
            a4 = (int *)a1;
            a4 = (int *)((__int64)(__int64)a4 ^ (__int64)i2);
            ptr->field_10 = a4;
            a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
            ptr->field_8 = a2;
            a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a3);
            result = __ROL8__(result, 45);
            ptr->field_18 = a1;
            ptr->field_20 = result;
            a1 = ptr->field_4D;
            if (a1 == 0) JUMPOUT(0x140094006);
            result = i2 + (__int64)(__int64)i2*4;
            result = __ROL8__(result, 7);
            result += (__int64)(__int64)result*8;
            a2 = (int *)result;
            a2 = (int *)((__int64)(__int64)a2 >> 32);
            if ((a2 == 0)) {
                a2 = 0;
                result = __rdx_rax / (__int64)a1; a2 = __rdx_rax % (__int64)a1; /* unsigned */;
                ptr2 = (struct Struct_4_t *)a2;
                i2 = -1;
                dst2 = 0;
                do {
                    a2 = ptr->field_8;
                    result = ptr->field_10;
                    a1 = result + (__int64)(__int64)result*4;
                    a1 = __ROL8__(a1, 7);
                    a1 += (__int64)(__int64)a1*8;
                    a4 = (int *)result;
                    a4 = (int *)((__int64)(__int64)a4 << 17);
                    a3 = ptr->field_18;
                    a3 = (struct Struct_1_t *)((__int64)(__int64)a3 ^ (__int64)a2);
                    v5 = (__int64)a3;
                    v5 ^= (__int64)result;
                    result = (struct Struct_2_t *)((__int64)(__int64)result ^ (__int64)ptr->field_20);
                    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                    a3 = (struct Struct_1_t *)((__int64)(__int64)a3 ^ (__int64)a4);
                    result = __ROL8__(result, 45);
                    a1 = (size_t *)((__int64)(__int64)a1 >> 61);
                    a4 = v5 + v5*4;
                    a4 = __ROL8__(a4, 7);
                    i3 = *(__int64 *)((__int64)a1 + (__int64)dst);
                    a1 = a4 + (__int64)(__int64)a4*8;
                    a4 = (int *)v5;
                    a4 = (int *)((__int64)(__int64)a4 << 17);
                    a3 = (struct Struct_1_t *)((__int64)(__int64)a3 ^ (__int64)a2);
                    result = (struct Struct_2_t *)((__int64)(__int64)result ^ v5);
                    v5 ^= (__int64)a3;
                    ptr->field_10 = v5;
                    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                    ptr->field_8 = a2;
                    a3 = (struct Struct_1_t *)((__int64)(__int64)a3 ^ (__int64)a4);
                    ptr->field_18 = a3;
                    result = __ROL8__(result, 45);
                    ptr->field_20 = result;
                    result = (struct Struct_2_t *)a1;
                    result = (struct Struct_2_t *)((__int64)(__int64)(__int64)result * v6); /* unsigned; high half in a2 */;
                    a2 = (int *)((__int64)(__int64)a2 >> 3);
                    result = a2 + (__int64)(__int64)a2*8;
                    a1 = (size_t *)((__int64)a1 - (__int64)result);
                    result = (struct Struct_2_t *)v_d8;
                    if (i == result) {
                        a1 = rsp + 216;
                        sub_1400F87E0(a1);
                        v6 = 0xE38E38E38E38E38F;
                    }
                    dst3 = (__int64 *)v_e0;
                    result =  + i*2;
                    result += i;
                    result = (struct Struct_2_t *)((__int64)(__int64)result << 4);
                    a1 = 0x800000000000000C;
                    *(__int64 *)((__int64)dst3 + (__int64)result) = a1;
                    result = 1;
                    i += (__int64)result;
                    v_e8 = i;
                    dst2 = (__int64 *)((__int64)dst2 + (__int64)result);
                    ++i2;
                } while (i2 < ptr2);
                xmm0 = _mm_loadu_si128((__m128i *)(ptr + 40));
                xmm1 = _mm_cvtsi64_si128(dst2);
                xmm1 = _mm_shuffle_epi32(xmm1, 68);
                xmm1 = _mm_add_epi64(xmm1, xmm0);
                _mm_storeu_si128((__m128i *)(ptr + 40), xmm1);
                a2 = ptr->field_8;
                i2 = ptr->field_10;
                a1 = ptr->field_18;
                result = ptr->field_20;
                dst2 = 0x8000000000000000;
                return (__int64)dst2;
            }
            a2 = 0;
            result = __rdx_rax / (__int64)a1; a2 = __rdx_rax % (__int64)a1; /* unsigned */;
            ptr2 = (struct Struct_4_t *)a2;
            return (__int64)result;
        }
        dst = (__int64 *)v_100;
        ptr2 = (struct Struct_4_t *)v_f8;
        i = 2;
        a3 = (struct Struct_1_t *)v_80;
    }
    a4 = (int *)v_78;
    result = (struct Struct_2_t *)a4;
    result = (struct Struct_2_t *)((__int64)result - (__int64)a3);
    a1 = 0xAAAAAAAAAAAAAAAB;
    result = (struct Struct_2_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
    if (a4 == a3) JUMPOUT(0x14009305f);
    i2 = (__int64 *)a2;
    dst2 = (__int64 *)a3;
    i2 = (__int64 *)((__int64)(__int64)i2 >> 5);
    dst2 += 32;
    return sub_140093009();
}