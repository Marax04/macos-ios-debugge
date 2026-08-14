// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 7 accesses on `ptr2`
struct Struct_2_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    char field_3; // offset 3
    __int16 field_4; // offset 4
    char _pad_4[1];
    char field_7; // offset 7
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr4`
struct Struct_4_t {
    char _pad_start[100];
    int field_64; // offset 100
    __int64 field_68; // offset 104
    char _pad_68[283];
    __int16 field_18B; // offset 395
    char _pad_18B[1];
    __int64 field_18E; // offset 398
};

__int64 sub_1400F3B20();
__int64 sub_1400F2D20();
__int64 sub_14002EDF0();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400DB140();
__int64 sub_1400DD850();
__int64 sub_1400F3340();
__int64 sub_1400F3600();
__int64 sub_1400F3B80();
__int64 sub_1400F3326();
__int64 sub_1400CB186();
__int64 sub_1400F3869();
__int64 sub_1400F3510();
__int64 sub_1400C45C0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011C140;
extern __int64 off_14011C178;
extern __int64 off_14011D380;
extern __int64 off_14011CA70;
extern __int64 off_14011CA60;
extern __int64 off_14011D3F8;
extern __int64 off_14011B718;
extern __int64 off_14011B700;
extern __int64 off_14011C4D8;
extern __int64 off_14011C4C8;
extern __int64 off_14011C500;
extern __int64 off_14011C4F0;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011B810;
extern __int64 off_14011B7F2;
extern __int64 off_14011C638;
extern __int64 off_14011C618;
extern __int64 off_14011D368;
extern __int64 off_14011C818;
extern __int64 off_14011C7F8;
extern __int64 off_14011C0F8;
extern __int64 off_14011C0E0;
extern __int64 off_14011C128;
extern __int64 off_14011C110;
extern __int64 off_140108A90;
extern __int64 off_14011CA18;
extern __int64 off_14011B958;
extern __int64 off_14011B940;

__int64 __fastcall sub_1400C5990(size_t *a1, size_t *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    int arg_2;
    __int64 arg_3;
    int arg_4;
    int arg_40;
    int arg_5;
    __int64 arg_8;
    __int64 v_10c;
    __int64 v_110;
    __int64 v_128;
    int v_130;
    int v_160;
    int v_168;
    int v_170;
    int v_1d0;
    int v_1d8;
    int v_1e0;
    int v_1e8;
    __int64 v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    __int64 v_50;
    __int64 v_58;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    int v_80;
    __int64 v_88;
    __int64 v_a8;
    __int64 v_b0;
    int v_b8;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    int *v_90;
    struct Struct_4_t *ptr4;
    struct Struct_3_t *ptr3;
    __int64 *result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *i;
    struct Struct_2_t *ptr2;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 *i2;
    __int64 *dst;
    __int64 *dst2;
    __int64 v6;
    __m128i xmm2;

    ptr4 = (struct Struct_4_t *)a4;
    ptr3 = (struct Struct_3_t *)a2;
    v_b8 = (int)a1;
    result = a4[49];
    v_70 = (__int64)result;
    v_28 = (int)a3;
    if (result != 2) {
        result = (__int64 *)v_160;
        if (((__int64)result & 1) == 0) {
            a1 = &off_14011C140;
            a3 = &off_14011C178;
            sub_1400F3B20(a1, 53, a3);
        } else {
            if ((v_70 & 1) == 0) {
                xmm0 = _mm_loadu_si128((__m128i *)(ptr4 + 432));
                xmm1 = _mm_loadu_si128((__m128i *)(ptr4 + 448));
                _mm_store_si128((__m128i *)&v_90, xmm1);
                _mm_store_si128((__m128i *)&v_80, xmm0);
            } else {
                xmm0 = _mm_loadu_si128((__m128i *)(ptr4 + 400));
                xmm1 = _mm_loadu_si128((__m128i *)(ptr4 + 432));
                xmm1 = _mm_xor_si128(xmm1, xmm0);
                _mm_store_si128((__m128i *)&v_80, xmm1);
                xmm0 = _mm_loadu_si128((__m128i *)(ptr4 + 416));
                xmm1 = _mm_loadu_si128((__m128i *)(ptr4 + 448));
                xmm1 = _mm_xor_si128(xmm1, xmm0);
                _mm_store_si128((__m128i *)&v_90, xmm1);
            }
            a2 = ptr3->field_10;
            if (ptr3->field_0 == a2) {
                v_20 = 1;
                sub_1400F2D20(ptr3, ptr, 1, 1);
                a3 = (size_t *)v_28;
                a2 = ptr3->field_10;
            }
            result = ptr3->field_8;
            *(__int64 *)((__int64)result + (__int64)a2) = 82;
            ++a2;
            ptr3->field_10 = a2;
            i = *a3;
            result = i + 1;
            *a3 = result;
            sub_14002EDF0(0, 7, a3, a4);
            if (result != 0) {
                ptr2 = (struct Struct_2_t *)result;
                *result = 0x8148;
                arg_3 = 320;
                arg_2 = 236;
                result = ptr3->field_0;
                a2 = ptr3->field_10;
                result = (__int64 *)((__int64)result - (__int64)a2);
                if (result <= 6) {
                    v_20 = 1;
                    sub_1400F2D20(ptr3, a2, 7, 1);
                    a2 = ptr3->field_10;
                }
                result = ptr3->field_8;
                a1 = ptr2->field_0;
                a3 = ptr2->field_3;
                *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 7;
                ptr3->field_10 = a2;
                off_140108030(a1, a2, a3);
                off_140108038(result, 0, ptr2);
                result = i + 2;
                a1 = (size_t *)v_28;
                *a1 = result;
                sub_14002EDF0(0, 3);
                if (result != 0) {
                    ptr2 = (struct Struct_2_t *)result;
                    *result = 0x3148;
                    arg_2 = 192;
                    result = ptr3->field_0;
                    a2 = ptr3->field_10;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr3, a2, 3, 1);
                        a2 = ptr3->field_10;
                    }
                    result = ptr3->field_8;
                    a1 = ptr2->field_2;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                    a1 = ptr2->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 3;
                    ptr3->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr2);
                    result = i + 3;
                    a1 = (size_t *)v_28;
                    *a1 = result;
                    sub_14002EDF0(0, 3);
                    if (result != 0) {
                        ptr2 = (struct Struct_2_t *)result;
                        *result = 0x8948;
                        arg_2 = 231;
                        result = ptr3->field_0;
                        a2 = ptr3->field_10;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 2) {
                            v_20 = 1;
                            sub_1400F2D20(ptr3, a2, 3, 1);
                            a2 = ptr3->field_10;
                        }
                        result = ptr3->field_8;
                        a1 = ptr2->field_2;
                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                        a1 = ptr2->field_0;
                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                        a2 += 3;
                        ptr3->field_10 = a2;
                        off_140108030(a1, a2);
                        off_140108038(result, 0, ptr2);
                        result = i + 4;
                        a1 = (size_t *)v_28;
                        *a1 = result;
                        sub_14002EDF0(0, 6);
                        if (result != 0) {
                            ptr2 = (struct Struct_2_t *)result;
                            *result = 185;
                            arg_1 = 320;
                            result = ptr3->field_0;
                            a2 = ptr3->field_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 4) {
                                v_20 = 1;
                                sub_1400F2D20(ptr3, a2, 5, 1);
                                a2 = ptr3->field_10;
                            }
                            result = ptr3->field_8;
                            a1 = ptr2->field_4;
                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                            a1 = ptr2->field_0;
                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                            a2 += 5;
                            ptr3->field_10 = a2;
                            off_140108030(a1, a2);
                            off_140108038(result, 0, ptr2);
                            result = ptr3->field_0;
                            a2 = ptr3->field_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 2) {
                                v_20 = 1;
                                sub_1400F2D20(ptr3, a2, 3, 1);
                                a2 = ptr3->field_10;
                            }
                            result = ptr3->field_8;
                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 170;
                            *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                            a2 += 3;
                            ptr3->field_10 = a2;
                            result = ptr3->field_0;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            a3 = (size_t *)v_28;
                            v_60 = (__int64)ptr4;
                            if (result <= 2) {
                                v_20 = 1;
                                sub_1400F2D20(ptr3, a2, 3, 1);
                                a3 = (size_t *)v_28;
                                a2 = ptr3->field_10;
                            }
                            result = ptr3->field_8;
                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 192;
                            *(__int64 *)((__int64)result + (__int64)a2) = 0x314D;
                            a2 += 3;
                            ptr3->field_10 = a2;
                            i += 7;
                            *a3 = i;
                            v7 = 0x7C0C149;
                            ptr4 = 7;
                            a4 = 0x5C0C148;
                            a1 = 5;
                            ptr = 0;
                            i2 = 0;
                            v_50 = (__int64)ptr3;
                            do {
                                v_68 = (__int64)a1;
                                result = *(__int64 *)(rsp + ptr + 128);
                                a2 = (size_t *)v_60;
                                ptr2 = *(__int64 *)((__int64)a2 + (__int64)ptr + 464);
                                dst = (__int64 *)ptr;
                                dst = (__int64 *)((__int64)(__int64)dst ^ 16);
                                dst2 = *(__int64 *)((__int64)a2 + (__int64)dst + 464);
                                i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)result);
                                i2 = __ROR8__(i2, a1);
                                a1 = (size_t *)ptr4;
                                result = __ROL8__(result, a1);
                                v_78 = (__int64)result;
                                result = ptr3->field_0;
                                a2 = ptr3->field_10;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                v_48 = (__int64)a4;
                                v_20 = 1;
                                sub_1400F2D20(ptr3, a2, 2, 1);
                                a4 = (size_t *)v_48;
                                a3 = (size_t *)v_28;
                                a2 = ptr3->field_10;
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0xB848;
                                a2 += 2;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 7) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 8, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                i2 = (__int64 *)((__int64)(__int64)i2 ^ (__int64)ptr2);
                                i2 = (__int64 *)((__int64)i2 - (__int64)dst2);
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = i2;
                                a2 += 8;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0xB948;
                                a2 += 2;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 7) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 8, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = dst2;
                                a2 += 8;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 2) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 200;
                                *(__int64 *)((__int64)result + (__int64)a2) = 328;
                                a2 += 3;
                                ptr3->field_10 = a2;
                                result = i + 3;
                                *a3 = result;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0xB948;
                                a2 += 2;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 7) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 8, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = ptr2;
                                a2 += 8;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 2) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 200;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                                a2 += 3;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 4, 1);
                                    a4 = (size_t *)v_48;
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = a4;
                                a2 += 4;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 2) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 192;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0x314C;
                                a2 += 3;
                                ptr3->field_10 = a2;
                                result = i + 7;
                                *a3 = result;
                                if ((v_70 & 1) == 0) {
                                    sub_14002EDF0(0, 8);
                                    if (result != 0) {
                                        a4 = ptr + 64;
                                        v_30 = 8;
                                        v_38 = (__int64)result;
                                        *result = 0x8948;
                                        v_40 = 2;
                                        a1 = rsp + 48;
                                        sub_1400D4F50(a1, 0, 4, a4);
                                        ptr3 = (struct Struct_3_t *)v_30;
                                        dst2 = (__int64 *)v_38;
                                        i2 = (__int64 *)v_40;
                                        a1 = (size_t *)v_50;
                                        result = *a1;
                                        ptr2 = a1[2];
                                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                                        v_58 = (__int64)i;
                                        if (i2 > result) {
                                            v_20 = 1;
                                            i = (__int64 *)v_50;
                                            sub_1400F2D20(i, ptr2, i2, 1);
                                            ptr2 = (struct Struct_2_t *)arg_10;
                                        }
                                        i = (__int64 *)v_50;
                                        a1 = (size_t *)arg_8;
                                        a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                        sub_1400F27F0(a1, dst2, i2);
                                        ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)i2);
                                        arg_10 = (__int64)ptr2;
                                        ptr3 = (struct Struct_3_t *)i;
                                        if ((ptr3 == 0)) {
                                            result = ptr3->field_0;
                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                            i = (__int64 *)v_58;
                                            i2 = (__int64 *)v_78;
                                            if (result <= 2) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr3, ptr2, 3, 1);
                                                ptr2 = ptr3->field_10;
                                            }
                                            result = ptr3->field_8;
                                            *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 192;
                                            *(__int64 *)((__int64)result + (__int64)ptr2) = 0x8949;
                                            ptr2 += 3;
                                            ptr3->field_10 = ptr2;
                                            i += 9;
                                            a3 = (size_t *)v_28;
                                            *a3 = i;
                                            result = ptr3->field_0;
                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                            a4 = (size_t *)v_48;
                                            a1 = (size_t *)v_68;
                                            if (result <= 3) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr3, ptr2, 4, 1);
                                                a1 = (size_t *)v_68;
                                                a4 = (size_t *)v_48;
                                                a3 = (size_t *)v_28;
                                                ptr2 = ptr3->field_10;
                                            }
                                            result = ptr3->field_8;
                                            *(__int64 *)((__int64)result + (__int64)ptr2) = v7;
                                            ptr2 += 4;
                                            ptr3->field_10 = ptr2;
                                            ptr2 = (struct Struct_2_t *)i;
                                            i = ptr2 + 1;
                                            *a3 = i;
                                            ptr += 8;
                                            v7 += 0x7000000;
                                            ptr4 += 7;
                                            a4 += 0xD000000;
                                            a1 += 13;
                                            result = ptr3->field_0;
                                            a2 = ptr3->field_10;
                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr3, a2, 3, 1);
                                                a3 = (size_t *)v_28;
                                                a2 = ptr3->field_10;
                                            }
                                            ptr4 = (struct Struct_4_t *)v_60;
                                            result = ptr3->field_8;
                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 201;
                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                                            a2 += 3;
                                            ptr3->field_10 = a2;
                                            result = ptr3->field_0;
                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr3, a2, 3, 1);
                                                a3 = (size_t *)v_28;
                                                a2 = ptr3->field_10;
                                            }
                                            result = ptr3->field_8;
                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 192;
                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x314D;
                                            a2 += 3;
                                            ptr3->field_10 = a2;
                                            ptr2 += 3;
                                            *a3 = ptr2;
                                            result = ptr4->field_64;
                                            v_20 = (__int64)result;
                                            a1 = rsp + 192;
                                            a4 = (size_t *)v_168;
                                            sub_1400DB140(a1, ptr3, a3, a4);
                                            a3 = (size_t *)v_28;
                                            result = 16;
                                            v_48 = (__int64)result;
                                            result = 1;
                                            v_68 = (__int64)result;
                                            v_78 = 0;
                                            v_50 = (__int64)ptr3;
                                            if (ptr4->field_68 == 0) {
                                                ptr = ptr4->field_18B;
                                                sub_1400DD850(ptr3, a3, ptr);
                                                if (ptr4->field_18E == 0) {
                                                    result = (__int64 *)v_58;
                                                    a4 = (size_t *)v_50;
                                                    if (ptr != 0) {
                                                        sub_14002EDF0(0, 3, a3, a4);
                                                        if (result == 0) {
                                                            sub_1400F3340(1, 3);
                                                            dst2 += 5;
                                                            a4 = &off_14011D380;
                                                            sub_1400F3600(dst2, a2, result, a4);
                                                            ptr2 += 5;
                                                            a4 = &off_14011D380;
                                                            sub_1400F3600(ptr2, a2, a3, a4);
                                                            v7 += 5;
                                                            a4 = &off_14011D380;
                                                            sub_1400F3600(v7, a2, result, a4);
                                                            dst2 += 4;
                                                            a4 = &off_14011D380;
                                                            sub_1400F3600(dst2, a2, result, a4);
                                                            i += 5;
                                                            a4 = &off_14011D380;
                                                            sub_1400F3600(i, a2, result, a4);
                                                            v6 += 5;
                                                            a4 = &off_14011D380;
                                                            sub_1400F3600(v6, result, a3, a4);
                                                            v_20 = 1;
                                                            a2 = (size_t *)v_58;
                                                            sub_1400F2D20(ptr3, a2, 7, 1);
                                                            a3 = (size_t *)v_28;
                                                            result = ptr3->field_0;
                                                            v7 = ptr3->field_10;
                                                            a1 = ptr3->field_8;
                                                            *(a1 + v7 + 3) = 0;
                                                            *(a1 + v7) = 0x358D48;
                                                            v7 += 7;
                                                            ptr3->field_10 = v7;
                                                            ptr2 = *a3;
                                                            a2 = (size_t *)result;
                                                            a2 -= v7;
                                                            if (a2 <= 1) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, v7, 2, 1);
                                                                a3 = (size_t *)v_28;
                                                                v7 = ptr3->field_10;
                                                                result = ptr3->field_0;
                                                                a1 = ptr3->field_8;
                                                            }
                                                            *(a1 + v7) = 0xC033;
                                                            v7 += 2;
                                                            ptr3->field_10 = v7;
                                                            result -= v7;
                                                            if (result <= 2) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, v7, 3, 1);
                                                                a3 = (size_t *)v_28;
                                                                a1 = ptr3->field_8;
                                                                v7 = ptr3->field_10;
                                                            }
                                                            *(a1 + v7 + 2) = 201;
                                                            *(a1 + v7) = 0x3148;
                                                            v7 += 3;
                                                            ptr3->field_10 = v7;
                                                            result = ptr2 + 3;
                                                            *a3 = result;
                                                            result = ptr3->field_0;
                                                            a1 = (size_t *)result;
                                                            a1 -= v7;
                                                            dst2 = (__int64 *)v7;
                                                            if (a1 <= 3) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, v7, 4, 1);
                                                                a3 = (size_t *)v_28;
                                                                result = ptr3->field_0;
                                                                dst2 = ptr3->field_10;
                                                            }
                                                            a1 = ptr3->field_8;
                                                            *(__int64 *)((__int64)a1 + (__int64)dst2) = 0xE1CB60F;
                                                            dst2 += 4;
                                                            ptr3->field_10 = dst2;
                                                            a2 = (size_t *)result;
                                                            a2 = (size_t *)((__int64)a2 - (__int64)dst2);
                                                            if (a2 <= 1) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, dst2, 2, 1);
                                                                a3 = (size_t *)v_28;
                                                                dst2 = ptr3->field_10;
                                                                result = ptr3->field_0;
                                                                a1 = ptr3->field_8;
                                                            }
                                                            *(__int64 *)((__int64)a1 + (__int64)dst2) = 0xD801;
                                                            dst2 += 2;
                                                            ptr3->field_10 = dst2;
                                                            result = (__int64 *)((__int64)result - (__int64)dst2);
                                                            if (result <= 2) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, dst2, 3, 1);
                                                                a3 = (size_t *)v_28;
                                                                a1 = ptr3->field_8;
                                                                dst2 = ptr3->field_10;
                                                            }
                                                            *(__int64 *)((__int64)a1 + (__int64)dst2 + 2) = 193;
                                                            *(__int64 *)((__int64)a1 + (__int64)dst2) = 0xFF48;
                                                            dst2 += 3;
                                                            ptr3->field_10 = dst2;
                                                            result = ptr3->field_0;
                                                            result = (__int64 *)((__int64)result - (__int64)dst2);
                                                            a1 = (size_t *)dst2;
                                                            if (result <= 6) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, dst2, 7, 1);
                                                                a3 = (size_t *)v_28;
                                                                a1 = ptr3->field_10;
                                                            }
                                                            result = ptr3->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)a1 + 3) = 0;
                                                            *(__int64 *)((__int64)result + (__int64)a1) = 0xF98148;
                                                            i2 = a1 + 7;
                                                            ptr3->field_10 = i2;
                                                            a2 = ptr2 + 7;
                                                            *a3 = a2;
                                                            a1 += 13;
                                                            if (!((a1 < 0))) {
                                                                v7 -= (__int64)a1;
                                                                a1 = (size_t *)v7;
                                                                if (v7 == v7) {
                                                                    a1 = ptr3->field_0;
                                                                    a2 = a1;
                                                                    a2 = (size_t *)((__int64)a2 - (__int64)i2);
                                                                }
                                                                result = &off_14011CA70;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011CA60;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 48;
                                                                sub_1400F3B80(a1, 12, a3, a4);
                                                                sub_1400F3326(1, 7);
                                                                result = &off_14011B718;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011B700;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 48;
                                                                sub_1400F3B80(a1, 20, a3, a4);
                                                                result = &off_14011C4D8;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011C4C8;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 48;
                                                                sub_1400F3B80(a1, 10, a3, a4);
                                                                result = &off_14011C500;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011C4F0;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 48;
                                                                sub_1400F3B80(a1, 11, a3, a4);
                                                                sub_1400F3326(1, 5);
                                                                v_130 = (int)a4;
                                                                v7 = (__int64)a3;
                                                                ptr3 = (struct Struct_3_t *)a2;
                                                                ptr2 = (struct Struct_2_t *)a1;
                                                                i2 = (__int64 *)v_1e8;
                                                                result = (__int64 *)v_1e0;
                                                                v_78 = (__int64)result;
                                                                result = (__int64 *)v_1d8;
                                                                v_128 = (__int64)result;
                                                                result = (__int64 *)v_1d0;
                                                                v_110 = (__int64)result;
                                                                sub_14002EDF0(0, 8);
                                                                if (result == 0) JUMPOUT(0x1400d023c);
                                                                ptr = (struct Struct_1_t *)result;
                                                                *result = 0x24848B48;
                                                                result = ptr2->field_0;
                                                                a2 = ptr2->field_10;
                                                                ptr->field_4 = 208;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                v_40 = (__int64)ptr2;
                                                                if (result <= 7) JUMPOUT(0x1400cf2f5);
                                                                result = ptr2->field_8;
                                                                a1 = ptr->field_0;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                a2 += 8;
                                                                ptr2->field_10 = a2;
                                                                off_140108030(a1, a2);
                                                                off_140108038(result, 0, ptr);
                                                                *(__int64 *)ptr3 = (__int64)(ptr3->field_0 + 1);
                                                                ptr2 = (struct Struct_2_t *)arg_40;
                                                                sub_14002EDF0(0, 7);
                                                                if (result == 0) JUMPOUT(0x1400d0790);
                                                                i = result;
                                                                *result = 72;
                                                                result = (__int64 *)ptr2;
                                                                v_10c = (__int64)i2;
                                                                if (ptr2 == ptr2) JUMPOUT(0x1400cb17b);
                                                                arg_3 = (__int64)ptr2;
                                                                ptr = 7;
                                                                result = 129;
                                                                return sub_1400CB186();
                                                            }
                                                            result = &off_14011B3E0;
                                                            v_20 = (__int64)result;
                                                            a1 = &off_14011B3C3;
                                                            a4 = &off_14011D3F8;
                                                            a3 = rsp + 48;
                                                            sub_1400F3B80(a1, 23, a3, a4);
                                                            result = &off_14011B810;
                                                            v_20 = (__int64)result;
                                                            a1 = &off_14011B7F2;
                                                            a4 = &off_14011D3F8;
                                                            a3 = rsp + 48;
                                                            sub_1400F3B80(a1, 30, a3, a4);
                                                            sub_1400F3326(1, 6);
                                                            sub_1400F3326(1, 3);
                                                            result = &off_14011C638;
                                                            v_20 = (__int64)result;
                                                            a1 = &off_14011C618;
                                                            a4 = &off_14011D3F8;
                                                            a3 = rsp + 48;
                                                            sub_1400F3B80(a1, 28, a3, a4);
                                                            a3 = &off_14011D368;
                                                            sub_1400F3869(ptr4, result, a3);
                                                            sub_1400F3326(1, 11);
                                                            sub_1400F3326(1, 12);
                                                            return (__int64)a3;
                                                        }
                                                        ptr2 = (struct Struct_2_t *)result;
                                                        *result = 0x3148;
                                                        arg_2 = 192;
                                                        result = ptr3->field_0;
                                                        a2 = ptr3->field_10;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        v_70 = (__int64)i2;
                                                        if (result <= 2) {
                                                            do {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, a2, 3, 1);
                                                                a2 = ptr3->field_10;
                                                            } while (true);
                                                        }
                                                        result = ptr3->field_8;
                                                        a1 = ptr2->field_2;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                        a1 = ptr2->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 3;
                                                        ptr3->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr2);
                                                        a1 = (size_t *)v_28;
                                                        ptr = *a1;
                                                        result = ptr + 1;
                                                        *a1 = result;
                                                        sub_14002EDF0(0, 8);
                                                        if (result == 0) {
                                                            sub_1400F3326(1, 8);
                                                        }
                                                        ptr2 = (struct Struct_2_t *)result;
                                                        *result = 0x24848948;
                                                        result = ptr3->field_0;
                                                        a2 = ptr3->field_10;
                                                        ptr2->field_4 = 272;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 7) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr3, a2, 8, 1);
                                                            a2 = ptr3->field_10;
                                                        }
                                                        result = ptr3->field_8;
                                                        a1 = ptr2->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 8;
                                                        ptr3->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr2);
                                                        result = ptr + 2;
                                                        a1 = (size_t *)v_28;
                                                        *a1 = result;
                                                        sub_14002EDF0(0, 8);
                                                        if (result == 0) {
                                                            return (__int64)a1;
                                                        }
                                                        ptr2 = (struct Struct_2_t *)result;
                                                        *result = 0x24848948;
                                                        result = ptr3->field_0;
                                                        a2 = ptr3->field_10;
                                                        ptr2->field_4 = 280;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 7) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr3, a2, 8, 1);
                                                            a2 = ptr3->field_10;
                                                        }
                                                        result = ptr3->field_8;
                                                        a1 = ptr2->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 8;
                                                        ptr3->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr2);
                                                        result = ptr + 3;
                                                        a1 = (size_t *)v_28;
                                                        *a1 = result;
                                                        sub_14002EDF0(0, 8);
                                                        if (result == 0) {
                                                            return (__int64)a1;
                                                        }
                                                        ptr2 = (struct Struct_2_t *)result;
                                                        *result = 0x24848948;
                                                        result = ptr3->field_0;
                                                        a2 = ptr3->field_10;
                                                        ptr2->field_4 = 288;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 7) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr3, a2, 8, 1);
                                                            a2 = ptr3->field_10;
                                                        }
                                                        result = ptr3->field_8;
                                                        a1 = ptr2->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 8;
                                                        ptr3->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr2);
                                                        i2 = ptr + 4;
                                                        result = (__int64 *)v_28;
                                                        *result = i2;
                                                        sub_14002EDF0(0, 8);
                                                        if (result == 0) {
                                                            return (__int64)result;
                                                        }
                                                        ptr2 = (struct Struct_2_t *)result;
                                                        *result = 0x24848948;
                                                        result = ptr3->field_0;
                                                        a2 = ptr3->field_10;
                                                        ptr2->field_4 = 296;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        v_b0 = (__int64)dst2;
                                                        if (result <= 7) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr3, a2, 8, 1);
                                                            a2 = ptr3->field_10;
                                                        }
                                                        result = ptr3->field_8;
                                                        a1 = ptr2->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 8;
                                                        ptr3->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr2);
                                                        ptr += 5;
                                                        result = (__int64 *)v_28;
                                                        *result = ptr;
                                                        ptr2 = 304;
                                                        i = rsp + 128;
                                                        sub_14002EDF0(0, 8);
                                                        while (result != 0) {
                                                            v_80 = 8;
                                                            v_88 = (__int64)result;
                                                            *result = 0x8948;
                                                            v_90 = 2;
                                                            sub_1400D4F50(i, 0, 4, ptr2);
                                                            ptr = (struct Struct_1_t *)v_80;
                                                            dst2 = (__int64 *)v_88;
                                                            v7 = (__int64)v_90;
                                                            result = ptr3->field_0;
                                                            ptr4 = ptr3->field_10;
                                                            result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                            if (v7 > result) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr3, ptr4, v7, 1);
                                                                ptr4 = ptr3->field_10;
                                                            }
                                                            a1 = ptr3->field_8;
                                                            a1 = (size_t *)((__int64)a1 + (__int64)ptr4);
                                                            sub_1400F27F0(a1, dst2, v7);
                                                            ptr4 += v7;
                                                            ptr3->field_10 = ptr4;
                                                            if (ptr == 0) {
                                                                result = i2 + 2;
                                                                a2 = (size_t *)v_28;
                                                                *a2 = result;
                                                                ptr2 += 8;
                                                                ++i2;
                                                                result = ptr3->field_0;
                                                                ptr2 = ptr3->field_10;
                                                                a1 = (size_t *)result;
                                                                a1 = (size_t *)((__int64)a1 - (__int64)ptr2);
                                                                ptr4 = (struct Struct_4_t *)ptr2;
                                                                if (a1 <= 6) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, ptr2, 7, 1);
                                                                    a2 = (size_t *)v_28;
                                                                    result = ptr3->field_0;
                                                                    ptr4 = ptr3->field_10;
                                                                }
                                                                i = ptr3->field_8;
                                                                *(__int64 *)((__int64)i + (__int64)ptr4 + 3) = 0;
                                                                *(__int64 *)((__int64)i + (__int64)ptr4) = 0x358D48;
                                                                v7 = ptr4 + 7;
                                                                ptr3->field_10 = v7;
                                                                result -= v7;
                                                                if (result <= 6) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, v7, 7, 1);
                                                                    a2 = (size_t *)v_28;
                                                                    i = ptr3->field_8;
                                                                    v7 = ptr3->field_10;
                                                                }
                                                                v_60 = (__int64)ptr2;
                                                                *(i + v7 + 3) = 0;
                                                                *(i + v7) = 0x1D8D48;
                                                                v7 += 7;
                                                                ptr3->field_10 = v7;
                                                                result = i2 + 3;
                                                                *a2 = result;
                                                                sub_14002EDF0(0, 8);
                                                                if (result == 0) {
                                                                    return (__int64)result;
                                                                }
                                                                ptr2 = (struct Struct_2_t *)result;
                                                                *(__int64 *)ptr2 = (__int64)(result);
                                                                ptr = ptr3->field_0;
                                                                result = (__int64 *)ptr;
                                                                result -= v7;
                                                                if (result <= 7) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, v7, 8, 1);
                                                                    v7 = ptr3->field_10;
                                                                    ptr = ptr3->field_0;
                                                                    i = ptr3->field_8;
                                                                }
                                                                result = ptr2->field_0;
                                                                *(i + v7) = result;
                                                                v7 += 8;
                                                                ptr3->field_10 = v7;
                                                                off_140108030(0x17824BC8D48);
                                                                off_140108038(result, 0, ptr2);
                                                                result = (__int64 *)ptr;
                                                                result -= v7;
                                                                if (result <= 4) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, v7, 5, 1);
                                                                    ptr = ptr3->field_0;
                                                                    v7 = ptr3->field_10;
                                                                }
                                                                a3 = (size_t *)v_28;
                                                                result = ptr3->field_8;
                                                                *(result + v7 + 4) = 0;
                                                                *(result + v7) = 0x14B9;
                                                                v7 += 5;
                                                                ptr3->field_10 = v7;
                                                                a1 = (size_t *)ptr;
                                                                a1 -= v7;
                                                                a2 = (size_t *)v7;
                                                                if (a1 <= 1) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, v7, 2, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                    ptr = ptr3->field_0;
                                                                    result = ptr3->field_8;
                                                                }
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x68A;
                                                                a2 += 2;
                                                                ptr3->field_10 = a2;
                                                                a1 = i2 + 6;
                                                                *a3 = a1;
                                                                a1 = (size_t *)ptr;
                                                                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                if (a1 <= 1) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                    ptr = ptr3->field_0;
                                                                    result = ptr3->field_8;
                                                                }
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 818;
                                                                a2 += 2;
                                                                ptr3->field_10 = a2;
                                                                result = (__int64 *)ptr;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 1) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    ptr = ptr3->field_0;
                                                                    a2 = ptr3->field_10;
                                                                }
                                                                result = ptr3->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x788;
                                                                a2 += 2;
                                                                ptr3->field_10 = a2;
                                                                a1 = (size_t *)ptr;
                                                                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                if (a1 <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                    ptr = ptr3->field_0;
                                                                    result = ptr3->field_8;
                                                                }
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 198;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xFF48;
                                                                a2 += 3;
                                                                ptr3->field_10 = a2;
                                                                a1 = (size_t *)ptr;
                                                                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                if (a1 <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                    ptr = ptr3->field_0;
                                                                    result = ptr3->field_8;
                                                                }
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 195;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xFF48;
                                                                a2 += 3;
                                                                ptr3->field_10 = a2;
                                                                result = i2 + 10;
                                                                *a3 = result;
                                                                result = (__int64 *)ptr;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    ptr = ptr3->field_0;
                                                                    a2 = ptr3->field_10;
                                                                }
                                                                a1 = ptr3->field_8;
                                                                *(__int64 *)((__int64)a1 + (__int64)a2 + 2) = 199;
                                                                *(__int64 *)((__int64)a1 + (__int64)a2) = 0xFF48;
                                                                a2 += 3;
                                                                ptr3->field_10 = a2;
                                                                ptr = (struct Struct_1_t *)((__int64)ptr - (__int64)a2);
                                                                if (ptr <= 1) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                                                    a3 = (size_t *)v_28;
                                                                    a1 = ptr3->field_8;
                                                                    a2 = ptr3->field_10;
                                                                }
                                                                *(__int64 *)((__int64)a1 + (__int64)a2) = 0xC9FF;
                                                                result = a2 + 2;
                                                                ptr3->field_10 = result;
                                                                a2 += 4;
                                                                if (!((a2 < 0))) {
                                                                    v7 -= (__int64)a2;
                                                                    a2 = (size_t *)v7;
                                                                    if (v7 != v7) {
                                                                        result = &off_14011C818;
                                                                        v_20 = (__int64)result;
                                                                        a1 = &off_14011C7F8;
                                                                        a4 = &off_14011D3F8;
                                                                        a3 = rsp + 48;
                                                                        sub_1400F3B80(a1, 25, a3, a4);
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr3, result, 2, 1);
                                                                        a3 = (size_t *)v_28;
                                                                        a1 = ptr3->field_8;
                                                                        result = ptr3->field_10;
                                                                        v7 <<= 8;
                                                                        v7 |= 117;
                                                                        *(__int64 *)((__int64)a1 + (__int64)result) = v7;
                                                                        result += 2;
                                                                        ptr3->field_10 = result;
                                                                        result = i2 + 13;
                                                                        *a3 = result;
                                                                        sub_14002EDF0(0, 8, a3);
                                                                        if (result == 0) {
                                                                            return (__int64)result;
                                                                        }
                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                        *result = 0x248C8D48;
                                                                        result = ptr3->field_0;
                                                                        a2 = ptr3->field_10;
                                                                        ptr2->field_4 = 376;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                        if (result <= 7) {
                                                                            v_20 = 1;
                                                                            sub_1400F2D20(ptr3, a2, 8, 1);
                                                                            a2 = ptr3->field_10;
                                                                        }
                                                                        result = ptr3->field_8;
                                                                        a1 = ptr2->field_0;
                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                        a2 += 8;
                                                                        ptr3->field_10 = a2;
                                                                        off_140108030(a1, a2);
                                                                        off_140108038(result, 0, ptr2);
                                                                        result = i2 + 14;
                                                                        a1 = (size_t *)v_28;
                                                                        *a1 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        if (result == 0) {
                                                                            return (__int64)a1;
                                                                        }
                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                        *result = 0x24948D48;
                                                                        result = ptr3->field_0;
                                                                        a2 = ptr3->field_10;
                                                                        ptr2->field_4 = 304;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                        if (result <= 7) {
                                                                            v_20 = 1;
                                                                            sub_1400F2D20(ptr3, a2, 8, 1);
                                                                            a2 = ptr3->field_10;
                                                                        }
                                                                        result = ptr3->field_8;
                                                                        a1 = ptr2->field_0;
                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                        a2 += 8;
                                                                        ptr3->field_10 = a2;
                                                                        off_140108030(a1, a2);
                                                                        off_140108038(result, 0, ptr2);
                                                                        result = i2 + 15;
                                                                        a1 = (size_t *)v_28;
                                                                        *a1 = result;
                                                                        sub_14002EDF0(0, 6);
                                                                        if (result != 0) {
                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                            *result = 0xB841;
                                                                            arg_2 = 16;
                                                                            result = ptr3->field_0;
                                                                            a2 = ptr3->field_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                            if (result <= 5) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                a2 = ptr3->field_10;
                                                                            }
                                                                            result = ptr3->field_8;
                                                                            a1 = ptr2->field_4;
                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                            a1 = ptr2->field_0;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                            a2 += 6;
                                                                            ptr3->field_10 = a2;
                                                                            off_140108030(a1, a2);
                                                                            off_140108038(result, 0, ptr2);
                                                                            result = i2 + 16;
                                                                            a1 = (size_t *)v_28;
                                                                            *a1 = result;
                                                                            sub_14002EDF0(0, 8);
                                                                            if (result == 0) {
                                                                                return (__int64)a1;
                                                                            }
                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                            *result = 0x24848B48;
                                                                            result = ptr3->field_0;
                                                                            a2 = ptr3->field_10;
                                                                            ptr2->field_4 = 248;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                            if (result <= 7) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr3, a2, 8, 1);
                                                                                a2 = ptr3->field_10;
                                                                            }
                                                                            result = ptr3->field_8;
                                                                            a1 = ptr2->field_0;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                            a2 += 8;
                                                                            ptr3->field_10 = a2;
                                                                            off_140108030(a1, a2);
                                                                            off_140108038(result, 0, ptr2);
                                                                            result = i2 + 17;
                                                                            a1 = (size_t *)v_28;
                                                                            *a1 = result;
                                                                            sub_14002EDF0(0, 3);
                                                                            if (result != 0) {
                                                                                ptr2 = (struct Struct_2_t *)result;
                                                                                *result = 0xD0FF;
                                                                                result = ptr3->field_0;
                                                                                a2 = ptr3->field_10;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 1) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                    a2 = ptr3->field_10;
                                                                                }
                                                                                result = ptr3->field_8;
                                                                                a1 = ptr2->field_0;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 2;
                                                                                ptr3->field_10 = a2;
                                                                                off_140108030(a1, a2);
                                                                                off_140108038(result, 0, ptr2);
                                                                                result = ptr3->field_0;
                                                                                i = ptr3->field_10;
                                                                                result = (__int64 *)((__int64)result - (__int64)i);
                                                                                if (result <= 1) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr3, i, 2, 1);
                                                                                    i = ptr3->field_10;
                                                                                }
                                                                                a1 = (size_t *)v_28;
                                                                                result = ptr3->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)i) = 0xC085;
                                                                                result = i + 2;
                                                                                ptr3->field_10 = result;
                                                                                result = i2 + 19;
                                                                                *a1 = result;
                                                                                sub_14002EDF0(0, 6);
                                                                                if (result != 0) {
                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                    *result = 0x840F;
                                                                                    arg_2 = 0;
                                                                                    result = ptr3->field_0;
                                                                                    a2 = ptr3->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                    if (result <= 5) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                        a2 = ptr3->field_10;
                                                                                    }
                                                                                    result = ptr3->field_8;
                                                                                    a1 = ptr2->field_4;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                    a1 = ptr2->field_0;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                    a2 += 6;
                                                                                    ptr3->field_10 = a2;
                                                                                    off_140108030(a1, a2);
                                                                                    off_140108038(result, 0, ptr2);
                                                                                    result = i2 + 20;
                                                                                    a1 = (size_t *)v_28;
                                                                                    *a1 = result;
                                                                                    sub_14002EDF0(0, 3);
                                                                                    if (result == 0) {
                                                                                        return (__int64)a1;
                                                                                    }
                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                    *result = 0x314D;
                                                                                    arg_2 = 237;
                                                                                    result = ptr3->field_0;
                                                                                    v7 = ptr3->field_10;
                                                                                    result -= v7;
                                                                                    if (result <= 2) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, v7, 3, 1);
                                                                                        v7 = ptr3->field_10;
                                                                                    }
                                                                                    dst2 = ptr3->field_8;
                                                                                    result = ptr2->field_2;
                                                                                    *(dst2 + v7 + 2) = result;
                                                                                    result = ptr2->field_0;
                                                                                    *(dst2 + v7) = result;
                                                                                    v7 += 3;
                                                                                    ptr3->field_10 = v7;
                                                                                    off_140108030();
                                                                                    off_140108038(result, 0, ptr2);
                                                                                    result = i2 + 21;
                                                                                    a1 = (size_t *)v_28;
                                                                                    *a1 = result;
                                                                                    sub_14002EDF0(0, 8);
                                                                                    if (result == 0) {
                                                                                        return (__int64)a1;
                                                                                    }
                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                    ptr = ptr3->field_0;
                                                                                    result = (__int64 *)ptr;
                                                                                    result -= v7;
                                                                                    v_a8 = (__int64)ptr4;
                                                                                    if (result <= 7) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, v7, 8, 1);
                                                                                        v7 = ptr3->field_10;
                                                                                        ptr = ptr3->field_0;
                                                                                        dst2 = ptr3->field_8;
                                                                                    }
                                                                                    result = ptr2->field_0;
                                                                                    *(dst2 + v7) = result;
                                                                                    v7 += 8;
                                                                                    ptr3->field_10 = v7;
                                                                                    off_140108030(0x130248C8D48);
                                                                                    off_140108038(result, 0, ptr2);
                                                                                    result = (__int64 *)ptr;
                                                                                    result -= v7;
                                                                                    ptr4 = (struct Struct_4_t *)v7;
                                                                                    if (result <= 2) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, v7, 3, 1);
                                                                                        ptr4 = ptr3->field_10;
                                                                                        ptr = ptr3->field_0;
                                                                                        dst2 = ptr3->field_8;
                                                                                    }
                                                                                    *(__int64 *)((__int64)dst2 + (__int64)ptr4 + 2) = 1;
                                                                                    *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0xB60F;
                                                                                    ptr4 += 3;
                                                                                    ptr3->field_10 = ptr4;
                                                                                    result = i2 + 23;
                                                                                    a3 = (size_t *)v_28;
                                                                                    *a3 = result;
                                                                                    result = (__int64 *)ptr;
                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                    if (result <= 1) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, ptr4, 2, 1);
                                                                                        a3 = (size_t *)v_28;
                                                                                        ptr = ptr3->field_0;
                                                                                        ptr4 = ptr3->field_10;
                                                                                    }
                                                                                    result = ptr3->field_8;
                                                                                    *(__int64 *)((__int64)result + (__int64)ptr4) = 0xC084;
                                                                                    a2 = ptr4 + 2;
                                                                                    ptr3->field_10 = a2;
                                                                                    a1 = (size_t *)ptr;
                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                    if (a1 <= 1) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                        a3 = (size_t *)v_28;
                                                                                        a2 = ptr3->field_10;
                                                                                        ptr = ptr3->field_0;
                                                                                        result = ptr3->field_8;
                                                                                    }
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 116;
                                                                                    a2 += 2;
                                                                                    ptr3->field_10 = a2;
                                                                                    a1 = (size_t *)ptr;
                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                    if (a1 <= 1) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                        a3 = (size_t *)v_28;
                                                                                        a2 = ptr3->field_10;
                                                                                        ptr = ptr3->field_0;
                                                                                        result = ptr3->field_8;
                                                                                    }
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 0x302C;
                                                                                    a2 += 2;
                                                                                    ptr3->field_10 = a2;
                                                                                    result = (__int64 *)ptr;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                    if (result <= 3) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                        a3 = (size_t *)v_28;
                                                                                        ptr = ptr3->field_0;
                                                                                        a2 = ptr3->field_10;
                                                                                    }
                                                                                    result = ptr3->field_8;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 0xAED6B4D;
                                                                                    a2 += 4;
                                                                                    ptr3->field_10 = a2;
                                                                                    a1 = i2 + 27;
                                                                                    *a3 = a1;
                                                                                    a1 = (size_t *)ptr;
                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                    if (a1 <= 2) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                        a3 = (size_t *)v_28;
                                                                                        a2 = ptr3->field_10;
                                                                                        ptr = ptr3->field_0;
                                                                                        result = ptr3->field_8;
                                                                                    }
                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 232;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 844;
                                                                                    a2 += 3;
                                                                                    ptr3->field_10 = a2;
                                                                                    ptr = (struct Struct_1_t *)((__int64)ptr - (__int64)a2);
                                                                                    if (ptr <= 2) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                        a3 = (size_t *)v_28;
                                                                                        result = ptr3->field_8;
                                                                                        a2 = ptr3->field_10;
                                                                                    }
                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 193;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 0xFF48;
                                                                                    result = a2 + 3;
                                                                                    ptr3->field_10 = result;
                                                                                    a2 += 5;
                                                                                    if (!((a2 < 0))) {
                                                                                        v7 -= (__int64)a2;
                                                                                        a1 = (size_t *)v7;
                                                                                        if (v7 != v7) {
                                                                                            result = &off_14011C0F8;
                                                                                            v_20 = (__int64)result;
                                                                                            a1 = &off_14011C0E0;
                                                                                            a4 = &off_14011D3F8;
                                                                                            a3 = rsp + 48;
                                                                                            sub_1400F3B80(a1, 18, a3, a4);
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(ptr3, result, 2, 1);
                                                                                            a3 = (size_t *)v_28;
                                                                                            result = ptr3->field_10;
                                                                                            a1 = ptr3->field_8;
                                                                                            v7 <<= 8;
                                                                                            v7 |= 235;
                                                                                            *(__int64 *)((__int64)a1 + (__int64)result) = v7;
                                                                                            result += 2;
                                                                                            ptr3->field_10 = result;
                                                                                            a2 = i2 + 30;
                                                                                            *a3 = a2;
                                                                                            a3 = (size_t *)ptr4;
                                                                                            a3 += 4;
                                                                                            if (!((a3 < 0))) {
                                                                                                a2 = (size_t *)result;
                                                                                                a2 = (size_t *)((__int64)a2 - (__int64)a3);
                                                                                                if (a2 != a2) {
                                                                                                    result = &off_14011C128;
                                                                                                    v_20 = (__int64)result;
                                                                                                    a1 = &off_14011C110;
                                                                                                    a4 = &off_14011D3F8;
                                                                                                    a3 = rsp + 48;
                                                                                                    sub_1400F3B80(a1, 17, a3, a4);
                                                                                                    v_20 = 1;
                                                                                                    sub_1400F2D20(ptr3, ptr4, 11, 1);
                                                                                                    ptr4 = ptr3->field_10;
                                                                                                    ptr = ptr3->field_8;
                                                                                                    result = ptr2->field_7;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4 + 7) = result;
                                                                                                    result = ptr2->field_0;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                    ptr4 += 11;
                                                                                                    ptr3->field_10 = ptr4;
                                                                                                    off_140108030();
                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                    result = i2 + 31;
                                                                                                    a1 = (size_t *)v_28;
                                                                                                    *a1 = result;
                                                                                                    sub_14002EDF0(0, 8);
                                                                                                    if (result == 0) {
                                                                                                        return (__int64)a1;
                                                                                                    }
                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                    *result = 0x24648B4C;
                                                                                                    arg_4 = 32;
                                                                                                    result = ptr3->field_0;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                    if (result <= 4) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr3, ptr4, 5, 1);
                                                                                                        ptr = ptr3->field_8;
                                                                                                        ptr4 = ptr3->field_10;
                                                                                                    }
                                                                                                    result = ptr2->field_4;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4 + 4) = result;
                                                                                                    result = ptr2->field_0;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                    ptr4 += 5;
                                                                                                    ptr3->field_10 = ptr4;
                                                                                                    off_140108030();
                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                    sub_14002EDF0(0, 3);
                                                                                                    if (result == 0) {
                                                                                                        return (__int64)ptr4;
                                                                                                    }
                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                    *result = 0x894C;
                                                                                                    arg_2 = 233;
                                                                                                    result = ptr3->field_0;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                    if (result <= 2) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr3, ptr4, 3, 1);
                                                                                                        ptr = ptr3->field_8;
                                                                                                        ptr4 = ptr3->field_10;
                                                                                                    }
                                                                                                    result = ptr2->field_2;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4 + 2) = result;
                                                                                                    result = ptr2->field_0;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                    ptr4 += 3;
                                                                                                    ptr3->field_10 = ptr4;
                                                                                                    off_140108030();
                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                    result = i2 + 33;
                                                                                                    a1 = (size_t *)v_28;
                                                                                                    *a1 = result;
                                                                                                    sub_14002EDF0(0, 8);
                                                                                                    if (result == 0) {
                                                                                                        return (__int64)a1;
                                                                                                    }
                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                                    result = ptr3->field_0;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                    if (result <= 7) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr3, ptr4, 8, 1);
                                                                                                        ptr4 = ptr3->field_10;
                                                                                                    }
                                                                                                    ptr = ptr3->field_8;
                                                                                                    result = ptr2->field_0;
                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                    ptr4 += 8;
                                                                                                    ptr3->field_10 = ptr4;
                                                                                                    off_140108030(0x13024948D48);
                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                    sub_14002EDF0(0, 6);
                                                                                                    if (result != 0) {
                                                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                                                        *result = 0xB841;
                                                                                                        arg_2 = 64;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                        if (result <= 5) {
                                                                                                            v_20 = 1;
                                                                                                            sub_1400F2D20(ptr3, ptr4, 6, 1);
                                                                                                            ptr = ptr3->field_8;
                                                                                                            ptr4 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr2->field_4;
                                                                                                        *(__int64 *)((__int64)ptr + (__int64)ptr4 + 4) = result;
                                                                                                        result = ptr2->field_0;
                                                                                                        *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                        ptr4 += 6;
                                                                                                        ptr3->field_10 = ptr4;
                                                                                                        off_140108030();
                                                                                                        off_140108038(result, 0, ptr2);
                                                                                                        result = i2 + 35;
                                                                                                        a1 = (size_t *)v_28;
                                                                                                        *a1 = result;
                                                                                                        sub_14002EDF0(0, 8);
                                                                                                        if (result == 0) {
                                                                                                            return (__int64)a1;
                                                                                                        }
                                                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                                                        *(__int64 *)ptr2 = (__int64)(result);
                                                                                                        dst2 = ptr3->field_0;
                                                                                                        result = dst2;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                        if (result <= 7) {
                                                                                                            v_20 = 1;
                                                                                                            sub_1400F2D20(ptr3, ptr4, 8, 1);
                                                                                                            ptr4 = ptr3->field_10;
                                                                                                            dst2 = ptr3->field_0;
                                                                                                            ptr = ptr3->field_8;
                                                                                                        }
                                                                                                        result = ptr2->field_0;
                                                                                                        *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                        ptr4 += 8;
                                                                                                        ptr3->field_10 = ptr4;
                                                                                                        off_140108030(0x18C248C8D4C);
                                                                                                        off_140108038(result, 0, ptr2);
                                                                                                        sub_14002EDF0(0, 12);
                                                                                                        if (result != 0) {
                                                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                                                            *result = 0x2444C748;
                                                                                                            arg_4 = 32;
                                                                                                            arg_5 = 0;
                                                                                                            dst2 = (__int64 *)((__int64)dst2 - (__int64)ptr4);
                                                                                                            if (dst2 <= 8) {
                                                                                                                v_20 = 1;
                                                                                                                sub_1400F2D20(ptr3, ptr4, 9, 1);
                                                                                                                ptr4 = ptr3->field_10;
                                                                                                            }
                                                                                                            ptr = ptr3->field_8;
                                                                                                            result = ptr2->field_8;
                                                                                                            *(__int64 *)((__int64)ptr + (__int64)ptr4 + 8) = result;
                                                                                                            result = ptr2->field_0;
                                                                                                            *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                            ptr4 += 9;
                                                                                                            ptr3->field_10 = ptr4;
                                                                                                            off_140108030();
                                                                                                            off_140108038(result, 0, ptr2);
                                                                                                            result = i2 + 37;
                                                                                                            a1 = (size_t *)v_28;
                                                                                                            *a1 = result;
                                                                                                            sub_14002EDF0(0, 8);
                                                                                                            if (result == 0) {
                                                                                                                return (__int64)a1;
                                                                                                            }
                                                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                                                            *(__int64 *)ptr2 = (__int64)(result);
                                                                                                            result = ptr3->field_0;
                                                                                                            result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                            if (result <= 7) {
                                                                                                                v_20 = 1;
                                                                                                                sub_1400F2D20(ptr3, ptr4, 8, 1);
                                                                                                                ptr = ptr3->field_8;
                                                                                                                ptr4 = ptr3->field_10;
                                                                                                            }
                                                                                                            result = ptr2->field_0;
                                                                                                            *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                            ptr4 += 8;
                                                                                                            ptr3->field_10 = ptr4;
                                                                                                            off_140108030(0x10024848B48);
                                                                                                            off_140108038(result, 0, ptr2);
                                                                                                            sub_14002EDF0(0, 3);
                                                                                                            if (result != 0) {
                                                                                                                ptr2 = (struct Struct_2_t *)result;
                                                                                                                *result = 0xD0FF;
                                                                                                                result = ptr3->field_0;
                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                                if (result <= 1) {
                                                                                                                    v_20 = 1;
                                                                                                                    sub_1400F2D20(ptr3, ptr4, 2, 1);
                                                                                                                    ptr = ptr3->field_8;
                                                                                                                    ptr4 = ptr3->field_10;
                                                                                                                }
                                                                                                                result = ptr2->field_0;
                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                                ptr4 += 2;
                                                                                                                ptr3->field_10 = ptr4;
                                                                                                                off_140108030();
                                                                                                                off_140108038(result, 0, ptr2);
                                                                                                                result = i2 + 39;
                                                                                                                a1 = (size_t *)v_28;
                                                                                                                *a1 = result;
                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                if (result == 0) {
                                                                                                                    return (__int64)a1;
                                                                                                                }
                                                                                                                ptr2 = (struct Struct_2_t *)result;
                                                                                                                *result = 0x2464894C;
                                                                                                                arg_4 = 32;
                                                                                                                result = ptr3->field_0;
                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                                if (result <= 4) {
                                                                                                                    v_20 = 1;
                                                                                                                    sub_1400F2D20(ptr3, ptr4, 5, 1);
                                                                                                                    ptr4 = ptr3->field_10;
                                                                                                                }
                                                                                                                ptr = ptr3->field_8;
                                                                                                                result = ptr2->field_4;
                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr4 + 4) = result;
                                                                                                                result = ptr2->field_0;
                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                                ptr4 += 5;
                                                                                                                ptr3->field_10 = ptr4;
                                                                                                                off_140108030();
                                                                                                                off_140108038(result, 0, ptr2);
                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                if (result == 0) {
                                                                                                                    return (__int64)ptr4;
                                                                                                                }
                                                                                                                ptr2 = (struct Struct_2_t *)result;
                                                                                                                *result = 0x894C;
                                                                                                                arg_2 = 233;
                                                                                                                result = ptr3->field_0;
                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                                if (result <= 2) {
                                                                                                                    v_20 = 1;
                                                                                                                    sub_1400F2D20(ptr3, ptr4, 3, 1);
                                                                                                                    ptr = ptr3->field_8;
                                                                                                                    ptr4 = ptr3->field_10;
                                                                                                                }
                                                                                                                result = ptr2->field_2;
                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr4 + 2) = result;
                                                                                                                result = ptr2->field_0;
                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                                ptr4 += 3;
                                                                                                                ptr3->field_10 = ptr4;
                                                                                                                off_140108030();
                                                                                                                off_140108038(result, 0, ptr2);
                                                                                                                result = i2 + 41;
                                                                                                                a1 = (size_t *)v_28;
                                                                                                                *a1 = result;
                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                if (result == 0) {
                                                                                                                    return (__int64)a1;
                                                                                                                }
                                                                                                                ptr2 = (struct Struct_2_t *)result;
                                                                                                                *(__int64 *)ptr2 = (__int64)(result);
                                                                                                                result = ptr3->field_0;
                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                                if (result <= 7) {
                                                                                                                    v_20 = 1;
                                                                                                                    sub_1400F2D20(ptr3, ptr4, 8, 1);
                                                                                                                    ptr = ptr3->field_8;
                                                                                                                    ptr4 = ptr3->field_10;
                                                                                                                }
                                                                                                                result = ptr2->field_0;
                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                                ptr4 += 8;
                                                                                                                ptr3->field_10 = ptr4;
                                                                                                                off_140108030(0x10824848B48);
                                                                                                                off_140108038(result, 0, ptr2);
                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                if (result != 0) {
                                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                                    *result = 0xD0FF;
                                                                                                                    result = ptr3->field_0;
                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                                    if (result <= 1) {
                                                                                                                        v_20 = 1;
                                                                                                                        sub_1400F2D20(ptr3, ptr4, 2, 1);
                                                                                                                        ptr4 = ptr3->field_10;
                                                                                                                    }
                                                                                                                    ptr = ptr3->field_8;
                                                                                                                    result = ptr2->field_0;
                                                                                                                    *(__int64 *)((__int64)ptr + (__int64)ptr4) = result;
                                                                                                                    ptr4 += 2;
                                                                                                                    ptr3->field_10 = ptr4;
                                                                                                                    off_140108030();
                                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                                    result = i2 + 43;
                                                                                                                    a1 = (size_t *)v_28;
                                                                                                                    *a1 = result;
                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                    if (result == 0) {
                                                                                                                        return (__int64)a1;
                                                                                                                    }
                                                                                                                    *result = 0xBC83;
                                                                                                                    arg_2 = 36;
                                                                                                                    v_80 = 3;
                                                                                                                    v_88 = (__int64)result;
                                                                                                                    v_90 = 3;
                                                                                                                    v_20 = 1;
                                                                                                                    a1 = rsp + 128;
                                                                                                                    sub_1400F2D20(a1, 3, 4, 1);
                                                                                                                    ptr2 = (struct Struct_2_t *)v_88;
                                                                                                                    dst2 = (__int64 *)v_90;
                                                                                                                    *(__int64 *)((__int64)ptr2 + (__int64)dst2) = 396;
                                                                                                                    result = dst2 + 4;
                                                                                                                    v_90 = (int *)result;
                                                                                                                    if (result == v_80) {
                                                                                                                        a1 = rsp + 128;
                                                                                                                        sub_1400F3510(a1);
                                                                                                                        ptr2 = (struct Struct_2_t *)v_88;
                                                                                                                    }
                                                                                                                    *(__int64 *)((__int64)ptr2 + (__int64)dst2 + 4) = 64;
                                                                                                                    dst2 += 5;
                                                                                                                    result = ptr3->field_0;
                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                                    if (dst2 > result) {
                                                                                                                        v_20 = 1;
                                                                                                                        sub_1400F2D20(ptr3, ptr4, dst2, 1);
                                                                                                                        ptr = ptr3->field_8;
                                                                                                                        ptr4 = ptr3->field_10;
                                                                                                                    }
                                                                                                                    a1 = (__int64)ptr + (__int64)ptr4;
                                                                                                                    sub_1400F27F0(a1, ptr2, dst2);
                                                                                                                    ptr4 = (struct Struct_4_t *)((__int64)ptr4 + (__int64)dst2);
                                                                                                                    ptr3->field_10 = ptr4;
                                                                                                                    if (v_80 == 0) {
                                                                                                                        sub_14002EDF0(0, 6);
                                                                                                                        if (result != 0) {
                                                                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                                                                            *result = 0x850F;
                                                                                                                            arg_2 = 0;
                                                                                                                            a1 = ptr3->field_0;
                                                                                                                            a1 = (size_t *)((__int64)a1 - (__int64)ptr4);
                                                                                                                            result = (__int64 *)ptr4;
                                                                                                                            if (a1 <= 5) {
                                                                                                                                v_20 = 1;
                                                                                                                                sub_1400F2D20(ptr3, ptr4, 6, 1);
                                                                                                                                ptr = ptr3->field_8;
                                                                                                                                result = ptr3->field_10;
                                                                                                                            }
                                                                                                                            a1 = ptr2->field_4;
                                                                                                                            *(__int64 *)((__int64)ptr + (__int64)result + 4) = a1;
                                                                                                                            a1 = ptr2->field_0;
                                                                                                                            *(__int64 *)((__int64)ptr + (__int64)result) = a1;
                                                                                                                            result += 6;
                                                                                                                            ptr3->field_10 = result;
                                                                                                                            off_140108030(a1);
                                                                                                                            off_140108038(result, 0, ptr2);
                                                                                                                            i2 += 45;
                                                                                                                            a2 = (size_t *)v_28;
                                                                                                                            *a2 = i2;
                                                                                                                            sub_1400C45C0(ptr3, a2, 304, 272);
                                                                                                                            a2 = (size_t *)i;
                                                                                                                            a2 += 8;
                                                                                                                            if (!((a2 < 0))) {
                                                                                                                                a3 = ptr3->field_10;
                                                                                                                                result = (__int64 *)a3;
                                                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                a1 = (size_t *)result;
                                                                                                                                i2 = (__int64 *)v_70;
                                                                                                                                if (result == result) {
                                                                                                                                    if (a3 < a2) {
                                                                                                                                        i += 4;
                                                                                                                                        a4 = &off_14011D380;
                                                                                                                                        sub_1400F3600(i, a2, a3, a4);
                                                                                                                                        ptr4 += 2;
                                                                                                                                        a4 = &off_14011D380;
                                                                                                                                        sub_1400F3600(ptr4, a2, result, a4);
                                                                                                                                        a1 += 3;
                                                                                                                                        a4 = &off_14011D380;
                                                                                                                                        sub_1400F3600(a1, a2, a3, a4);
                                                                                                                                        i += 10;
                                                                                                                                        a4 = &off_14011D380;
                                                                                                                                        sub_1400F3600(i, a2, a3, a4);
                                                                                                                                        return (__int64)a4;
                                                                                                                                    }
                                                                                                                                    a1 = ptr3->field_8;
                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i + 4) = result;
                                                                                                                                    a2 = (size_t *)ptr4;
                                                                                                                                    a2 += 6;
                                                                                                                                    if (!((a2 < 0))) {
                                                                                                                                        a3 = (size_t *)((__int64)a3 - (__int64)a2);
                                                                                                                                        result = (__int64 *)a3;
                                                                                                                                        if (a3 == a3) {
                                                                                                                                            result = ptr3->field_10;
                                                                                                                                            if (a2 > result) {
                                                                                                                                                return (__int64)result;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)ptr4 + 2) = a3;
                                                                                                                                            sub_14002EDF0(0, 8, a3);
                                                                                                                                            if (result == 0) {
                                                                                                                                                return (__int64)result;
                                                                                                                                            }
                                                                                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                                                                                            *result = 0x24BC8D48;
                                                                                                                                            result = ptr3->field_0;
                                                                                                                                            a2 = ptr3->field_10;
                                                                                                                                            ptr2->field_4 = 304;
                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                            i = (__int64 *)v_a8;
                                                                                                                                            if (result <= 7) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr3, a2, 8, 1);
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            a1 = ptr2->field_0;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                            a2 += 8;
                                                                                                                                            ptr3->field_10 = a2;
                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                            off_140108038(result, 0, ptr2);
                                                                                                                                            result = ptr3->field_0;
                                                                                                                                            a2 = ptr3->field_10;
                                                                                                                                            a1 = (size_t *)v_28;
                                                                                                                                            ptr = *a1;
                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                            if (result <= 1) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                                                                                a1 = (size_t *)v_28;
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xC031;
                                                                                                                                            a2 += 2;
                                                                                                                                            ptr3->field_10 = a2;
                                                                                                                                            result = ptr + 2;
                                                                                                                                            *a1 = result;
                                                                                                                                            if (ptr3->field_0 == a2) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr3, a2, 1, 1);
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 185;
                                                                                                                                            ++a2;
                                                                                                                                            ptr3->field_10 = a2;
                                                                                                                                            result = ptr3->field_0;
                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                            if (result <= 3) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 104;
                                                                                                                                            a2 += 4;
                                                                                                                                            ptr3->field_10 = a2;
                                                                                                                                            result = ptr3->field_0;
                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                            if (result <= 2) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 170;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                                                                                                                                            a2 += 3;
                                                                                                                                            ptr3->field_10 = a2;
                                                                                                                                            sub_14002EDF0(0, 5);
                                                                                                                                            if (result != 0) {
                                                                                                                                                ptr2 = (struct Struct_2_t *)result;
                                                                                                                                                *result = 233;
                                                                                                                                                arg_1 = 40;
                                                                                                                                                result = ptr3->field_0;
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                if (result <= 4) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                                                                    a2 = ptr3->field_10;
                                                                                                                                                }
                                                                                                                                                result = ptr3->field_8;
                                                                                                                                                a1 = ptr2->field_4;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                a1 = ptr2->field_0;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                a2 += 5;
                                                                                                                                                ptr3->field_10 = a2;
                                                                                                                                                off_140108030(a1, a2);
                                                                                                                                                off_140108038(result, 0, ptr2);
                                                                                                                                                result = ptr + 5;
                                                                                                                                                a1 = (size_t *)v_28;
                                                                                                                                                *a1 = result;
                                                                                                                                                result = ptr3->field_0;
                                                                                                                                                dst2 = ptr3->field_10;
                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)dst2);
                                                                                                                                                ptr2 = (struct Struct_2_t *)dst2;
                                                                                                                                                if (result <= 19) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    sub_1400F2D20(ptr3, dst2, 20, 1);
                                                                                                                                                    a1 = (size_t *)v_28;
                                                                                                                                                    ptr2 = ptr3->field_10;
                                                                                                                                                }
                                                                                                                                                result = ptr3->field_8;
                                                                                                                                                xmm0 = _mm_load_si128((__m128i *)&off_140108A90);
                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)ptr2), xmm0);
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)ptr2 + 16) = 0x4E6D3FF8;
                                                                                                                                                ptr2 += 20;
                                                                                                                                                ptr3->field_10 = ptr2;
                                                                                                                                                result = ptr3->field_0;
                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                a3 = (size_t *)ptr2;
                                                                                                                                                a4 = (size_t *)v_50;
                                                                                                                                                if (result <= 19) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    sub_1400F2D20(ptr3, ptr2, 20, 1);
                                                                                                                                                    a4 = (size_t *)v_50;
                                                                                                                                                    a1 = (size_t *)v_28;
                                                                                                                                                    a3 = ptr3->field_10;
                                                                                                                                                }
                                                                                                                                                result = ptr3->field_8;
                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)&off_14011CA18);
                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a3), xmm0);
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a3 + 16) = 0x4E2873BC;
                                                                                                                                                a3 += 20;
                                                                                                                                                ptr3->field_10 = a3;
                                                                                                                                                ptr += 7;
                                                                                                                                                *a1 = ptr;
                                                                                                                                                a1 = (size_t *)v_60;
                                                                                                                                                a2 = a1;
                                                                                                                                                a2 += 7;
                                                                                                                                                if (!((a2 < 0))) {
                                                                                                                                                    dst2 = (__int64 *)((__int64)dst2 - (__int64)a2);
                                                                                                                                                    result = dst2;
                                                                                                                                                    if (dst2 == dst2) {
                                                                                                                                                        if (a2 > a3) {
                                                                                                                                                            return (__int64)result;
                                                                                                                                                        }
                                                                                                                                                        result = ptr3->field_8;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a1 + 3) = dst2;
                                                                                                                                                        a2 = (size_t *)i;
                                                                                                                                                        a2 += 14;
                                                                                                                                                        if (!((a2 < 0))) {
                                                                                                                                                            ptr2 = (struct Struct_2_t *)((__int64)ptr2 - (__int64)a2);
                                                                                                                                                            result = (__int64 *)ptr2;
                                                                                                                                                            dst2 = (__int64 *)v_b0;
                                                                                                                                                            if (ptr2 == ptr2) {
                                                                                                                                                                a3 = ptr3->field_10;
                                                                                                                                                                if (a2 > a3) {
                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                }
                                                                                                                                                                result = ptr3->field_8;
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i + 10) = ptr2;
                                                                                                                                                                result = (__int64 *)v_58;
                                                                                                                                                                a1 = (size_t *)v_b8;
                                                                                                                                                                a2 = (size_t *)v_78;
                                                                                                                                                                *a1 = a2;
                                                                                                                                                                arg_8 = (__int64)result;
                                                                                                                                                                a1[2] = a2;
                                                                                                                                                                a1[3] = dst2;
                                                                                                                                                                a1[4] = a2;
                                                                                                                                                                a1[5] = i2;
                                                                                                                                                                a1[6] = a2;
                                                                                                                                                                a1[7] = a4;
                                                                                                                                                                result = (__int64 *)v_68;
                                                                                                                                                                a1[8] = result;
                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)&v_c0);
                                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)&v_d0);
                                                                                                                                                                xmm2 = _mm_loadu_si128((__m128i *)&v_e0);
                                                                                                                                                                _mm_storeu_si128((__m128i *)(a1 + 72), xmm0);
                                                                                                                                                                _mm_storeu_si128((__m128i *)(a1 + 88), xmm1);
                                                                                                                                                                _mm_storeu_si128((__m128i *)(a1 + 104), xmm2);
                                                                                                                                                                result = (__int64 *)v_f0;
                                                                                                                                                                a1[15] = result;
                                                                                                                                                                result = (__int64 *)v_48;
                                                                                                                                                                a1[16] = result;
                                                                                                                                                                return (__int64)result;
                                                                                                                                                            }
                                                                                                                                                            return (__int64)result;
                                                                                                                                                        }
                                                                                                                                                        return (__int64)result;
                                                                                                                                                    }
                                                                                                                                                    return (__int64)result;
                                                                                                                                                }
                                                                                                                                                return (__int64)result;
                                                                                                                                            }
                                                                                                                                            return (__int64)result;
                                                                                                                                        }
                                                                                                                                        return (__int64)result;
                                                                                                                                    }
                                                                                                                                    return (__int64)result;
                                                                                                                                }
                                                                                                                                return (__int64)result;
                                                                                                                            }
                                                                                                                            return (__int64)result;
                                                                                                                        }
                                                                                                                        return (__int64)result;
                                                                                                                    }
                                                                                                                    off_140108030();
                                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                                    return (__int64)result;
                                                                                                                }
                                                                                                            }
                                                                                                            return (__int64)result;
                                                                                                        }
                                                                                                        return (__int64)result;
                                                                                                    }
                                                                                                    return (__int64)result;
                                                                                                }
                                                                                                ptr4 += 3;
                                                                                                if (ptr4 < result) {
                                                                                                    *(__int64 *)((__int64)a1 + (__int64)ptr4) = a2;
                                                                                                    sub_14002EDF0(0, 11, a2);
                                                                                                    if (result != 0) {
                                                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                                                        *result = 0x84C7;
                                                                                                        arg_2 = 36;
                                                                                                        arg_3 = 396;
                                                                                                        result = ptr3->field_0;
                                                                                                        ptr4 = ptr3->field_10;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr4);
                                                                                                        if (result <= 10) {
                                                                                                            return (__int64)result;
                                                                                                        }
                                                                                                        return (__int64)result;
                                                                                                    }
                                                                                                    return (__int64)result;
                                                                                                }
                                                                                                return (__int64)result;
                                                                                            }
                                                                                            return (__int64)result;
                                                                                        }
                                                                                        a1 = ptr3->field_0;
                                                                                        a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                        if (a1 <= 1) {
                                                                                            return (__int64)a1;
                                                                                        }
                                                                                        return (__int64)a1;
                                                                                    }
                                                                                    return (__int64)a1;
                                                                                }
                                                                                return (__int64)a1;
                                                                            }
                                                                            return (__int64)a1;
                                                                        }
                                                                        return (__int64)a1;
                                                                    }
                                                                    a2 = ptr3->field_0;
                                                                    a2 = (size_t *)((__int64)a2 - (__int64)result);
                                                                    if (a2 <= 1) {
                                                                        return (__int64)a2;
                                                                    }
                                                                    return (__int64)a2;
                                                                }
                                                                return (__int64)a2;
                                                            }
                                                            off_140108030();
                                                            off_140108038(result, 0, dst2);
                                                            return (__int64)a2;
                                                        }
                                                        return (__int64)a2;
                                                    }
                                                    return (__int64)a2;
                                                }
                                                i = ptr3->field_10;
                                                v_60 = (__int64)ptr;
                                                if ((*(__int64 *)ptr3 == i)) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, i, 1, 1);
                                                    i = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i) = 82;
                                                ++i;
                                                ptr3->field_10 = i;
                                                dst = (__int64 *)v_28;
                                                ptr4 = *dst;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i);
                                                if (result <= 8) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, i, 9, 1);
                                                    dst = (__int64 *)v_28;
                                                    i = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                a1 = 0x6025248B4C65;
                                                *(__int64 *)((__int64)result + (__int64)i) = a1;
                                                *(__int64 *)((__int64)result + (__int64)i + 8) = 0;
                                                i += 9;
                                                ptr3->field_10 = i;
                                                result = ptr4 + 2;
                                                *dst = result;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i);
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, i, 5, 1);
                                                    dst = (__int64 *)v_28;
                                                    i = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i + 4) = 24;
                                                *(__int64 *)((__int64)result + (__int64)i) = 0x246C8B4D;
                                                i += 5;
                                                ptr3->field_10 = i;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i);
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, i, 4, 1);
                                                    dst = (__int64 *)v_28;
                                                    i = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i) = 0x10758D4D;
                                                i += 4;
                                                ptr3->field_10 = i;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i);
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, i, 3, 1);
                                                    dst = (__int64 *)v_28;
                                                    i = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i + 2) = 62;
                                                *(__int64 *)((__int64)result + (__int64)i) = 0x8B4D;
                                                i += 3;
                                                ptr3->field_10 = i;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i);
                                                v6 = (__int64)i;
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, i, 3, 1);
                                                    dst = (__int64 *)v_28;
                                                    v6 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(result + v6 + 2) = 63;
                                                *(result + v6) = 0x8B4D;
                                                v6 += 3;
                                                ptr3->field_10 = v6;
                                                result = ptr4 + 6;
                                                *dst = result;
                                                result = ptr3->field_0;
                                                result -= v6;
                                                v_70 = (__int64)i2;
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr3, v6, 3, 1);
                                                    dst = (__int64 *)v_28;
                                                    v6 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(result + v6 + 2) = 247;
                                                *(result + v6) = 0x394D;
                                                i2 = v6 + 3;
                                                ptr3->field_10 = i2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                if (result <= 5) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, i2, 6, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    i2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i2 + 4) = 0;
                                                *(__int64 *)((__int64)result + (__int64)i2) = 0x840F;
                                                i2 += 6;
                                                ptr3->field_10 = i2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, i2, 5, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    i2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i2 + 4) = 88;
                                                *(__int64 *)((__int64)result + (__int64)i2) = 0x4FB70F49;
                                                i2 += 5;
                                                ptr3->field_10 = i2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, i2, 4, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    i2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i2) = 0x60578B49;
                                                i2 += 4;
                                                ptr3->field_10 = i2;
                                                result = ptr4 + 10;
                                                *dst = result;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, i2, 5, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    i2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i2 + 4) = 129;
                                                *(__int64 *)((__int64)result + (__int64)i2) = 0x1C9DC5B8;
                                                i2 += 5;
                                                ptr3->field_10 = i2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, i2, 3, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    i2 = ptr3->field_10;
                                                }
                                                ptr = (struct Struct_1_t *)dst2;
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)i2 + 2) = 246;
                                                *(__int64 *)((__int64)result + (__int64)i2) = 0x3148;
                                                i2 += 3;
                                                ptr3->field_10 = i2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                v7 = (__int64)i2;
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, i2, 3, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    v7 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(result + v7 + 2) = 206;
                                                *(result + v7) = 0x3948;
                                                dst2 = v7 + 3;
                                                ptr3->field_10 = dst2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)dst2);
                                                if (result <= 5) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, dst2, 6, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    dst2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 0;
                                                *(__int64 *)((__int64)result + (__int64)dst2) = 0x840F;
                                                dst2 += 6;
                                                ptr3->field_10 = dst2;
                                                result = ptr4 + 14;
                                                *dst = result;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)dst2);
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, dst2, 4, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    dst2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)dst2) = 0x321CB60F;
                                                dst2 += 4;
                                                ptr3->field_10 = dst2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)dst2);
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, dst2, 3, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    dst2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)dst2 + 2) = 65;
                                                *(__int64 *)((__int64)result + (__int64)dst2) = 0xFB83;
                                                ptr2 = dst2 + 3;
                                                ptr3->field_10 = ptr2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                if (result <= 5) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, ptr2, 6, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    ptr2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr2 + 4) = 0;
                                                *(__int64 *)((__int64)result + (__int64)ptr2) = 0x820F;
                                                ptr2 += 6;
                                                ptr3->field_10 = ptr2;
                                                result = ptr3->field_0;
                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    ptr2 = (struct Struct_2_t *)v6;
                                                    sub_1400F2D20(ptr3, ptr2, 3, 1);
                                                    v6 = (__int64)ptr2;
                                                    dst = (__int64 *)v_28;
                                                    ptr2 = ptr3->field_10;
                                                }
                                                result = ptr3->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 90;
                                                *(__int64 *)((__int64)result + (__int64)ptr2) = 0xFB83;
                                                result = ptr2 + 3;
                                                ptr3->field_10 = result;
                                                a1 = ptr4 + 18;
                                                *dst = a1;
                                                a1 = ptr3->field_0;
                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                if (a1 <= 5) {
                                                    v_20 = 1;
                                                    v_a8 = v6;
                                                    sub_1400F2D20(ptr3, result, 6, 1);
                                                    v6 = v_a8;
                                                    dst = (__int64 *)v_28;
                                                    result = ptr3->field_10;
                                                }
                                                a1 = ptr3->field_8;
                                                *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
                                                *(__int64 *)((__int64)a1 + (__int64)result) = 0x870F;
                                                result += 6;
                                                ptr3->field_10 = result;
                                                a1 = ptr3->field_0;
                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                if (a1 <= 2) {
                                                    v_20 = 1;
                                                    v_a8 = v6;
                                                    sub_1400F2D20(ptr3, result, 3, 1);
                                                    v6 = v_a8;
                                                    dst = (__int64 *)v_28;
                                                    result = ptr3->field_10;
                                                }
                                                a1 = ptr3->field_8;
                                                *(__int64 *)((__int64)a1 + (__int64)result + 2) = 32;
                                                *(__int64 *)((__int64)a1 + (__int64)result) = 0xC383;
                                                result += 3;
                                                ptr3->field_10 = result;
                                                a2 = (size_t *)dst2;
                                                a2 += 9;
                                                if (!((a2 < 0))) {
                                                    a1 = (size_t *)result;
                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                    a3 = a1;
                                                    if (a1 == a1) {
                                                        if (result < a2) {
                                                            return (__int64)a3;
                                                        }
                                                        a2 = ptr3->field_8;
                                                        *(__int64 *)((__int64)a2 + (__int64)dst2 + 5) = a1;
                                                        a2 = (size_t *)ptr2;
                                                        a2 += 9;
                                                        if (!((a2 < 0))) {
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            a1 = (size_t *)result;
                                                            if (result == result) {
                                                                a3 = ptr3->field_10;
                                                                if (a2 > a3) {
                                                                    return (__int64)a3;
                                                                }
                                                                a1 = ptr3->field_8;
                                                                *(__int64 *)((__int64)a1 + (__int64)ptr2 + 5) = result;
                                                                result = ptr3->field_0;
                                                                a2 = ptr3->field_10;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 1) {
                                                                    v_20 = 1;
                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                    sub_1400F2D20(ptr3, a2, 2, 1);
                                                                    v6 = (__int64)ptr2;
                                                                    dst = (__int64 *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                }
                                                                result = ptr3->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xD831;
                                                                a2 += 2;
                                                                ptr3->field_10 = a2;
                                                                result = ptr4 + 21;
                                                                *dst = result;
                                                                result = ptr3->field_0;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 5) {
                                                                    v_20 = 1;
                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                    sub_1400F2D20(ptr3, a2, 6, 1);
                                                                    v6 = (__int64)ptr2;
                                                                    dst = (__int64 *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                }
                                                                result = ptr3->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = 256;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x193C069;
                                                                a2 += 6;
                                                                ptr3->field_10 = a2;
                                                                result = ptr3->field_0;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 3) {
                                                                    v_20 = 1;
                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                    sub_1400F2D20(ptr3, a2, 4, 1);
                                                                    v6 = (__int64)ptr2;
                                                                    dst = (__int64 *)v_28;
                                                                    a2 = ptr3->field_10;
                                                                }
                                                                result = ptr3->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x2C68348;
                                                                result = a2 + 4;
                                                                ptr3->field_10 = result;
                                                                a2 += 9;
                                                                if (!((a2 < 0))) {
                                                                    i2 = (__int64 *)((__int64)i2 - (__int64)a2);
                                                                    if (ptr3->field_0 == result) {
                                                                        v_20 = 1;
                                                                        ptr2 = (struct Struct_2_t *)v6;
                                                                        sub_1400F2D20(ptr3, result, 1, 1);
                                                                        v6 = (__int64)ptr2;
                                                                        dst = (__int64 *)v_28;
                                                                        result = ptr3->field_10;
                                                                    }
                                                                    a1 = ptr3->field_8;
                                                                    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
                                                                    ++result;
                                                                    ptr3->field_10 = result;
                                                                    a1 = (size_t *)i2;
                                                                    if (i2 == i2) {
                                                                        a1 = ptr3->field_0;
                                                                        a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                        if (a1 <= 3) {
                                                                            v_20 = 1;
                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                            sub_1400F2D20(ptr3, result, 4, 1);
                                                                            v6 = (__int64)ptr2;
                                                                            dst = (__int64 *)v_28;
                                                                            result = ptr3->field_10;
                                                                        }
                                                                        a1 = ptr3->field_8;
                                                                        *(__int64 *)((__int64)a1 + (__int64)result) = i2;
                                                                        result += 4;
                                                                        ptr3->field_10 = result;
                                                                        a1 = ptr4 + 24;
                                                                        *dst = a1;
                                                                        a2 = (size_t *)v7;
                                                                        a2 += 9;
                                                                        if (!((a2 < 0))) {
                                                                            a1 = (size_t *)result;
                                                                            a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                            a3 = a1;
                                                                            if (a1 == a1) {
                                                                                if (result < a2) {
                                                                                    return (__int64)a3;
                                                                                }
                                                                                result = ptr3->field_8;
                                                                                *(result + v7 + 5) = a1;
                                                                                a2 = ptr3->field_10;
                                                                                if (ptr3->field_0 == a2) {
                                                                                    v_20 = 1;
                                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                                    sub_1400F2D20(ptr3, a2, 1, 1);
                                                                                    v6 = (__int64)ptr2;
                                                                                    dst = (__int64 *)v_28;
                                                                                    a2 = ptr3->field_10;
                                                                                }
                                                                                result = ptr3->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 61;
                                                                                ++a2;
                                                                                ptr3->field_10 = a2;
                                                                                result = ptr3->field_0;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 3) {
                                                                                    v_20 = 1;
                                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                                    sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                    v6 = (__int64)ptr2;
                                                                                    dst = (__int64 *)v_28;
                                                                                    a2 = ptr3->field_10;
                                                                                }
                                                                                result = ptr3->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xA62A3B3B;
                                                                                i2 = a2 + 4;
                                                                                ptr3->field_10 = i2;
                                                                                a2 += 10;
                                                                                if (!((a2 < 0))) {
                                                                                    i = (__int64 *)((__int64)i - (__int64)a2);
                                                                                    result = ptr3->field_0;
                                                                                    result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                    if (result < 2) {
                                                                                        v_20 = 1;
                                                                                        ptr2 = (struct Struct_2_t *)v6;
                                                                                        sub_1400F2D20(ptr3, i2, 2, 1);
                                                                                        v6 = (__int64)ptr2;
                                                                                        dst = (__int64 *)v_28;
                                                                                        i2 = ptr3->field_10;
                                                                                    }
                                                                                    result = ptr3->field_8;
                                                                                    *(__int64 *)((__int64)result + (__int64)i2) = 0x850F;
                                                                                    i2 += 2;
                                                                                    ptr3->field_10 = i2;
                                                                                    result = i;
                                                                                    if (i == i) {
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = i;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x30678B4D;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 4) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 5, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 4) = 60;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x246C8B45;
                                                                                        i2 += 5;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 229;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 333;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr4 + 29;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 6) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 7, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 3) = 136;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x889D8B41;
                                                                                        i2 += 7;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 229;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x894D;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 221;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 329;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x186D8B41;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr4 + 33;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x1C758B45;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 230;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 333;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x20758B41;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 230;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 332;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr4 + 37;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x247D8B41;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 231;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 332;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x10EC8348;
                                                                                        i2 += 4;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 7) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 8, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x2404C748;
                                                                                        i2 += 8;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr4 + 41;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 8) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 9, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        a1 = 0x82444C748;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = a1;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 8) = 0;
                                                                                        i2 += 9;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2 + 2) = 237;
                                                                                        *(__int64 *)((__int64)result + (__int64)i2) = 0x314D;
                                                                                        i2 += 3;
                                                                                        ptr3->field_10 = i2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                        i = i2;
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, i2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            i = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)i + 2) = 237;
                                                                                        *(__int64 *)((__int64)result + (__int64)i) = 0x3949;
                                                                                        v7 = i + 3;
                                                                                        ptr3->field_10 = v7;
                                                                                        result = ptr3->field_0;
                                                                                        result -= v7;
                                                                                        if (result <= 5) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, v7, 6, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            v7 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(result + v7 + 4) = 0;
                                                                                        *(result + v7) = 0x840F;
                                                                                        v7 += 6;
                                                                                        ptr3->field_10 = v7;
                                                                                        result = ptr4 + 45;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result -= v7;
                                                                                        if (result <= 3) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, v7, 4, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            v7 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(result + v7) = 0xAE1C8B42;
                                                                                        v7 += 4;
                                                                                        ptr3->field_10 = v7;
                                                                                        result = ptr3->field_0;
                                                                                        result -= v7;
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, v7, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            v7 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(result + v7 + 2) = 226;
                                                                                        *(result + v7) = 0x894C;
                                                                                        v7 += 3;
                                                                                        ptr3->field_10 = v7;
                                                                                        result = ptr3->field_0;
                                                                                        result -= v7;
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, v7, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            v7 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(result + v7 + 2) = 218;
                                                                                        *(result + v7) = 328;
                                                                                        v7 += 3;
                                                                                        ptr3->field_10 = v7;
                                                                                        result = ptr3->field_0;
                                                                                        result -= v7;
                                                                                        if (result <= 4) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, v7, 5, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            v7 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(result + v7 + 4) = 129;
                                                                                        *(result + v7) = 0x1C9DC5B8;
                                                                                        v7 += 5;
                                                                                        ptr3->field_10 = v7;
                                                                                        result = ptr4 + 49;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result -= v7;
                                                                                        dst2 = (__int64 *)v7;
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, v7, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            dst2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 2) = 26;
                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = 0xB60F;
                                                                                        dst2 += 3;
                                                                                        ptr3->field_10 = dst2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)dst2);
                                                                                        if (result <= 1) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, dst2, 2, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            dst2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = 0xDB84;
                                                                                        a2 = dst2 + 2;
                                                                                        ptr3->field_10 = a2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 5) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            a2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x840F;
                                                                                        a2 += 6;
                                                                                        ptr3->field_10 = a2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 1) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            a2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xD831;
                                                                                        a2 += 2;
                                                                                        ptr3->field_10 = a2;
                                                                                        result = ptr4 + 53;
                                                                                        *dst = result;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 5) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            a2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = 256;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x193C069;
                                                                                        a2 += 6;
                                                                                        ptr3->field_10 = a2;
                                                                                        result = ptr3->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                            sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                            v6 = (__int64)ptr2;
                                                                                            dst = (__int64 *)v_28;
                                                                                            a2 = ptr3->field_10;
                                                                                        }
                                                                                        result = ptr3->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 194;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xFF48;
                                                                                        result = a2 + 3;
                                                                                        ptr3->field_10 = result;
                                                                                        a2 += 8;
                                                                                        if (!((a2 < 0))) {
                                                                                            v7 -= (__int64)a2;
                                                                                            if (ptr3->field_0 == result) {
                                                                                                v_20 = 1;
                                                                                                ptr2 = (struct Struct_2_t *)v6;
                                                                                                sub_1400F2D20(ptr3, result, 1, 1);
                                                                                                v6 = (__int64)ptr2;
                                                                                                dst = (__int64 *)v_28;
                                                                                                result = ptr3->field_10;
                                                                                            }
                                                                                            a1 = ptr3->field_8;
                                                                                            *(__int64 *)((__int64)a1 + (__int64)result) = 233;
                                                                                            ++result;
                                                                                            ptr3->field_10 = result;
                                                                                            a1 = (size_t *)v7;
                                                                                            if (v7 == v7) {
                                                                                                a1 = ptr3->field_0;
                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                                if (a1 <= 3) {
                                                                                                    v_20 = 1;
                                                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                                                    sub_1400F2D20(ptr3, result, 4, 1);
                                                                                                    v6 = (__int64)ptr2;
                                                                                                    dst = (__int64 *)v_28;
                                                                                                    result = ptr3->field_10;
                                                                                                }
                                                                                                a1 = ptr3->field_8;
                                                                                                *(__int64 *)((__int64)a1 + (__int64)result) = v7;
                                                                                                result += 4;
                                                                                                ptr3->field_10 = result;
                                                                                                a1 = ptr4 + 56;
                                                                                                *dst = a1;
                                                                                                a2 = (size_t *)dst2;
                                                                                                a2 += 8;
                                                                                                if (!((a2 < 0))) {
                                                                                                    a1 = (size_t *)result;
                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                    a3 = a1;
                                                                                                    if (a1 == a1) {
                                                                                                        if (result < a2) {
                                                                                                            return (__int64)a3;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                                                        result = ptr3->field_0;
                                                                                                        a2 = ptr3->field_10;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 4) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        dst2 = (__int64 *)ptr;
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = 111;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x1CB70F42;
                                                                                                        a2 += 5;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 3) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x9E1C8B43;
                                                                                                        result = a2 + 4;
                                                                                                        ptr3->field_10 = result;
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x9E1C8B41;
                                                                                                        result = ptr3->field_0;
                                                                                                        a2 = ptr3->field_10;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 2) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 225;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x894C;
                                                                                                        a2 += 3;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr4 + 58;
                                                                                                        *dst = result;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 2) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 217;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 328;
                                                                                                        a2 += 3;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        if (ptr3->field_0 == a2) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 1, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 61;
                                                                                                        ++a2;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 3) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xE5F4BDDE;
                                                                                                        a2 += 4;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 1) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x575;
                                                                                                        a2 += 2;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr4 + 61;
                                                                                                        *dst = result;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 3) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x240C8948;
                                                                                                        a2 += 4;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        if (ptr3->field_0 == a2) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 1, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 61;
                                                                                                        ++a2;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 3) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x671697A7;
                                                                                                        a2 += 4;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 1) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x575;
                                                                                                        a2 += 2;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr4 + 64;
                                                                                                        *dst = result;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 4) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = 8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x244C8948;
                                                                                                        a2 += 5;
                                                                                                        ptr3->field_10 = a2;
                                                                                                        result = ptr3->field_0;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 2) {
                                                                                                            v_20 = 1;
                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                            sub_1400F2D20(ptr3, a2, 3, 1);
                                                                                                            v6 = (__int64)ptr2;
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            a2 = ptr3->field_10;
                                                                                                        }
                                                                                                        result = ptr3->field_8;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 197;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xFF49;
                                                                                                        result = a2 + 3;
                                                                                                        ptr3->field_10 = result;
                                                                                                        a2 += 8;
                                                                                                        if (!((a2 < 0))) {
                                                                                                            i2 = (__int64 *)((__int64)i2 - (__int64)a2);
                                                                                                            if (ptr3->field_0 == result) {
                                                                                                                v_20 = 1;
                                                                                                                ptr2 = (struct Struct_2_t *)v6;
                                                                                                                sub_1400F2D20(ptr3, result, 1, 1);
                                                                                                                v6 = (__int64)ptr2;
                                                                                                                dst = (__int64 *)v_28;
                                                                                                                result = ptr3->field_10;
                                                                                                            }
                                                                                                            a1 = ptr3->field_8;
                                                                                                            *(__int64 *)((__int64)a1 + (__int64)result) = 233;
                                                                                                            ++result;
                                                                                                            ptr3->field_10 = result;
                                                                                                            a1 = (size_t *)i2;
                                                                                                            if (i2 == i2) {
                                                                                                                a1 = ptr3->field_0;
                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                                                if (a1 <= 3) {
                                                                                                                    v_20 = 1;
                                                                                                                    ptr2 = (struct Struct_2_t *)v6;
                                                                                                                    sub_1400F2D20(ptr3, result, 4, 1);
                                                                                                                    v6 = (__int64)ptr2;
                                                                                                                    dst = (__int64 *)v_28;
                                                                                                                    result = ptr3->field_10;
                                                                                                                }
                                                                                                                a1 = ptr3->field_8;
                                                                                                                *(__int64 *)((__int64)a1 + (__int64)result) = i2;
                                                                                                                result += 4;
                                                                                                                ptr3->field_10 = result;
                                                                                                                a2 = (size_t *)i;
                                                                                                                a2 += 9;
                                                                                                                if (!((a2 < 0))) {
                                                                                                                    a1 = (size_t *)result;
                                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                                    a3 = a1;
                                                                                                                    i2 = (__int64 *)v_70;
                                                                                                                    if (a1 == a1) {
                                                                                                                        if (result < a2) {
                                                                                                                            return (__int64)i2;
                                                                                                                        }
                                                                                                                        result = ptr3->field_8;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)i + 5) = a1;
                                                                                                                        result = ptr3->field_0;
                                                                                                                        a2 = ptr3->field_10;
                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                        if (result <= 3) {
                                                                                                                            v_20 = 1;
                                                                                                                            ptr2 = (struct Struct_2_t *)v6;
                                                                                                                            sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                            v6 = (__int64)ptr2;
                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                            a2 = ptr3->field_10;
                                                                                                                        }
                                                                                                                        a1 = ptr3->field_8;
                                                                                                                        *(__int64 *)((__int64)a1 + (__int64)a2) = 0x30EC8348;
                                                                                                                        a2 += 4;
                                                                                                                        ptr3->field_10 = a2;
                                                                                                                        result = ptr4 + 68;
                                                                                                                        *dst = result;
                                                                                                                        result = 0x3800000030;
                                                                                                                        v_90 = (int *)result;
                                                                                                                        ptr4 += 55;
                                                                                                                        ptr2 = 0;
                                                                                                                        result = 0;
                                                                                                                        do {
                                                                                                                            ptr = v_90[(__int64)result];
                                                                                                                            result = ptr3->field_0;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            v_20 = 1;
                                                                                                                            i = (__int64 *)v6;
                                                                                                                            sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                            v6 = (__int64)i;
                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                            a1 = ptr3->field_8;
                                                                                                                            a2 = ptr3->field_10;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x244C8B48;
                                                                                                                            a2 += 4;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            if (ptr >= 256) {
                                                                                                                                result = &off_14011B958;
                                                                                                                                v_20 = (__int64)result;
                                                                                                                                a1 = &off_14011B940;
                                                                                                                                a4 = &off_14011D3F8;
                                                                                                                                a3 = rsp + 48;
                                                                                                                                sub_1400F3B80(a1, 22, a3, a4);
                                                                                                                                return (__int64)a3;
                                                                                                                            }
                                                                                                                            result = ptr3->field_0;
                                                                                                                            if (result == a2) {
                                                                                                                                v_20 = 1;
                                                                                                                                i = (__int64 *)v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 1, 1);
                                                                                                                                v6 = (__int64)i;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            a1 = ptr3->field_8;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = ptr;
                                                                                                                            i = (__int64 *)a2;
                                                                                                                            ++i;
                                                                                                                            ptr3->field_10 = i;
                                                                                                                            a2 = (size_t *)result;
                                                                                                                            a2 = (size_t *)((__int64)a2 - (__int64)i);
                                                                                                                            if (a2 <= 2) {
                                                                                                                                v_20 = 1;
                                                                                                                                i = (__int64 *)v6;
                                                                                                                                sub_1400F2D20(ptr3, i, 3, 1);
                                                                                                                                v6 = (__int64)i;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                i = ptr3->field_10;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)i + 2) = 201;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)i) = 0x8548;
                                                                                                                            a2 = i + 3;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            a3 = ptr4 + 15;
                                                                                                                            *dst = a3;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            if (result <= 5) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x840F;
                                                                                                                            a2 += 6;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = ptr3->field_0;
                                                                                                                            a1 = (size_t *)result;
                                                                                                                            a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                                            if (a1 <= 4) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            a1 = ptr3->field_8;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x8BA;
                                                                                                                            a2 += 5;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            a3 = (size_t *)result;
                                                                                                                            a3 = (size_t *)((__int64)a3 - (__int64)a2);
                                                                                                                            if (a3 <= 5) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x40B841;
                                                                                                                            a2 += 6;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            if (result <= 4) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 16;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x244C8D4C;
                                                                                                                            a2 += 5;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = ptr4 + 19;
                                                                                                                            *dst = result;
                                                                                                                            result = ptr3->field_0;
                                                                                                                            a1 = (size_t *)result;
                                                                                                                            a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                                            if (a1 <= 3) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            a1 = ptr3->field_8;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x602454FF;
                                                                                                                            a2 += 4;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            a3 = (size_t *)result;
                                                                                                                            a3 = (size_t *)((__int64)a3 - (__int64)a2);
                                                                                                                            if (a3 <= 3) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x244C8B48;
                                                                                                                            a2 += 4;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            if (result == a2) {
                                                                                                                                v_20 = 1;
                                                                                                                                v7 = v6;
                                                                                                                                sub_1400F2D20(ptr3, result, 1, 1);
                                                                                                                                v6 = v7;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = ptr;
                                                                                                                            ++a2;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = ptr3->field_0;
                                                                                                                            a1 = (size_t *)result;
                                                                                                                            a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                                            if (a1 <= 5) {
                                                                                                                                v_20 = 1;
                                                                                                                                ptr = (struct Struct_1_t *)v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 6, 1);
                                                                                                                                v6 = (__int64)ptr;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            a1 = ptr3->field_8;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0x90C3;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0xC03301C7;
                                                                                                                            a2 += 6;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            a3 = ptr4 + 22;
                                                                                                                            *dst = a3;
                                                                                                                            a3 = (size_t *)result;
                                                                                                                            a3 = (size_t *)((__int64)a3 - (__int64)a2);
                                                                                                                            if (a3 <= 4) {
                                                                                                                                v_20 = 1;
                                                                                                                                ptr = (struct Struct_1_t *)v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                                                v6 = (__int64)ptr;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x8BA;
                                                                                                                            a2 += 5;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            if (result <= 4) {
                                                                                                                                v_20 = 1;
                                                                                                                                ptr = (struct Struct_1_t *)v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                                                v6 = (__int64)ptr;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 16;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x24448B44;
                                                                                                                            a2 += 5;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = ptr3->field_0;
                                                                                                                            a1 = (size_t *)result;
                                                                                                                            a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                                                                            if (a1 <= 4) {
                                                                                                                                v_20 = 1;
                                                                                                                                ptr = (struct Struct_1_t *)v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 5, 1);
                                                                                                                                v6 = (__int64)ptr;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                result = ptr3->field_0;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            a1 = ptr3->field_8;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 16;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x244C8D4C;
                                                                                                                            a2 += 5;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            if (result <= 3) {
                                                                                                                                v_20 = 1;
                                                                                                                                ptr = (struct Struct_1_t *)v6;
                                                                                                                                sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                                v6 = (__int64)ptr;
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                a1 = ptr3->field_8;
                                                                                                                                a2 = ptr3->field_10;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x602454FF;
                                                                                                                            a2 += 4;
                                                                                                                            ptr3->field_10 = a2;
                                                                                                                            result = ptr4 + 26;
                                                                                                                            *dst = result;
                                                                                                                            result = i;
                                                                                                                            result += 9;
                                                                                                                            if (!((result < 0))) {
                                                                                                                                a3 = a2;
                                                                                                                                a3 = (size_t *)((__int64)a3 - (__int64)result);
                                                                                                                                a4 = a3;
                                                                                                                                if (a3 == a3) {
                                                                                                                                    if (a2 < result) {
                                                                                                                                        i += 5;
                                                                                                                                        a4 = &off_14011D380;
                                                                                                                                        sub_1400F3600(i, result, a2, a4);
                                                                                                                                        return (__int64)a4;
                                                                                                                                    }
                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i + 5) = a3;
                                                                                                                                    ptr4 += 13;
                                                                                                                                    result = 1;
                                                                                                                                    /* test ptr2 , 1 */;
                                                                                                                                    ptr2 = 1;
                                                                                                                                    result = ptr3->field_0;
                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                    if (result <= 3) {
                                                                                                                                        v_20 = 1;
                                                                                                                                        ptr2 = (struct Struct_2_t *)v6;
                                                                                                                                        sub_1400F2D20(ptr3, a2, 4, 1);
                                                                                                                                        v6 = (__int64)ptr2;
                                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                                        a1 = ptr3->field_8;
                                                                                                                                        a2 = ptr3->field_10;
                                                                                                                                    }
                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)a2) = 0x40C48348;
                                                                                                                                    a2 += 4;
                                                                                                                                    ptr3->field_10 = a2;
                                                                                                                                    result = ptr3->field_0;
                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                    a3 = a2;
                                                                                                                                    if (result <= 1) {
                                                                                                                                        v_20 = 1;
                                                                                                                                        ptr2 = (struct Struct_2_t *)a2;
                                                                                                                                        ptr = (struct Struct_1_t *)v6;
                                                                                                                                        sub_1400F2D20(ptr3, a2, 2, 1);
                                                                                                                                        v6 = (__int64)ptr;
                                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                                        a3 = ptr3->field_10;
                                                                                                                                    }
                                                                                                                                    result = ptr3->field_8;
                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a3) = 0xB0F;
                                                                                                                                    a3 += 2;
                                                                                                                                    ptr3->field_10 = a3;
                                                                                                                                    result = (__int64 *)v6;
                                                                                                                                    result += 9;
                                                                                                                                    if (!((result < 0))) {
                                                                                                                                        a2 = (size_t *)((__int64)a2 - (__int64)result);
                                                                                                                                        a1 = a2;
                                                                                                                                        if (a2 == a2) {
                                                                                                                                            if (result > a3) {
                                                                                                                                                return (__int64)a1;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(result + v6 + 5) = a2;
                                                                                                                                            a2 = ptr3->field_10;
                                                                                                                                            if (ptr3->field_0 == a2) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr3, ptr2, 1, 1);
                                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                                a2 = ptr3->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr3->field_8;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 90;
                                                                                                                                            ++a2;
                                                                                                                                            ptr3->field_10 = a2;
                                                                                                                                            ptr4 += 16;
                                                                                                                                            *dst = ptr4;
                                                                                                                                            ptr = (struct Struct_1_t *)v_60;
                                                                                                                                            return (__int64)ptr;
                                                                                                                                        }
                                                                                                                                        return (__int64)ptr;
                                                                                                                                    }
                                                                                                                                    return (__int64)ptr;
                                                                                                                                }
                                                                                                                                return (__int64)ptr;
                                                                                                                            }
                                                                                                                            return (__int64)ptr;
                                                                                                                        } while ((0 /* unresolved: flags == */));
                                                                                                                        return (__int64)ptr;
                                                                                                                    }
                                                                                                                    return (__int64)ptr;
                                                                                                                }
                                                                                                                return (__int64)ptr;
                                                                                                            }
                                                                                                            return (__int64)ptr;
                                                                                                        }
                                                                                                        return (__int64)ptr;
                                                                                                    }
                                                                                                    return (__int64)ptr;
                                                                                                }
                                                                                                return (__int64)ptr;
                                                                                            }
                                                                                            return (__int64)ptr;
                                                                                        }
                                                                                        return (__int64)ptr;
                                                                                    }
                                                                                    return (__int64)ptr;
                                                                                }
                                                                                return (__int64)ptr;
                                                                            }
                                                                            return (__int64)ptr;
                                                                        }
                                                                        return (__int64)ptr;
                                                                    }
                                                                    return (__int64)ptr;
                                                                }
                                                                return (__int64)ptr;
                                                            }
                                                            return (__int64)ptr;
                                                        }
                                                        return (__int64)ptr;
                                                    }
                                                    return (__int64)ptr;
                                                }
                                                return (__int64)ptr;
                                            }
                                            result = ptr3->field_0;
                                            ptr2 = ptr3->field_10;
                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr3, ptr2, 3, 1);
                                                a3 = (size_t *)v_28;
                                                ptr2 = ptr3->field_10;
                                            }
                                            ptr = (struct Struct_1_t *)v_170;
                                            result = ptr3->field_8;
                                            *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 1;
                                            *(__int64 *)((__int64)result + (__int64)ptr2) = 0xFA83;
                                            ptr2 += 3;
                                            ptr3->field_10 = ptr2;
                                            i = *a3;
                                            a1 = ptr3->field_0;
                                            a1 = (size_t *)((__int64)a1 - (__int64)ptr2);
                                            result = (__int64 *)ptr2;
                                            if (a1 <= 5) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr3, ptr2, 6, 1);
                                                a3 = (size_t *)v_28;
                                                result = ptr3->field_10;
                                            }
                                            a1 = ptr3->field_8;
                                            *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
                                            *(__int64 *)((__int64)a1 + (__int64)result) = 0x850F;
                                            result += 6;
                                            ptr3->field_10 = result;
                                            i += 2;
                                            *a3 = i;
                                            *(__int64 *)ptr = (__int64)(1);
                                            ptr->field_8 = ptr2;
                                            return (__int64)i;
                                        }
                                        off_140108030();
                                        off_140108038(result, 0, dst2);
                                        ptr2 = ptr3->field_10;
                                        return (__int64)ptr2;
                                    }
                                    return (__int64)ptr2;
                                }
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 2) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 3, 1);
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 192;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0x8949;
                                a2 += 3;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 4, 1);
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = v7;
                                a2 += 4;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 4, 1);
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr3->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = 0x24843348;
                                a2 += 4;
                                ptr3->field_10 = a2;
                                result = ptr3->field_0;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr3, a2, 4, 1);
                                    a3 = (size_t *)v_28;
                                    a2 = ptr3->field_10;
                                }
                                result = ptr + 736;
                                a1 = ptr3->field_8;
                                *(__int64 *)((__int64)a1 + (__int64)a2) = result;
                                a2 += 4;
                                ptr3->field_10 = a2;
                                i += 10;
                                *a3 = i;
                                sub_14002EDF0(0, 8, a3, a4);
                                if (result != 0) {
                                    i2 = (__int64 *)ptr3;
                                    a4 = ptr + 64;
                                    v_30 = 8;
                                    v_38 = (__int64)result;
                                    *result = 0x8948;
                                    v_40 = 2;
                                    a1 = rsp + 48;
                                    sub_1400D4F50(a1, 0, 4, a4);
                                    ptr3 = (struct Struct_3_t *)v_30;
                                    ptr2 = (struct Struct_2_t *)v_38;
                                    dst2 = (__int64 *)v_40;
                                    result = *i2;
                                    i2 = (__int64 *)arg_10;
                                    result = (__int64 *)((__int64)result - (__int64)i2);
                                    v_58 = (__int64)i;
                                    if (dst2 > result) {
                                        v_20 = 1;
                                        i = (__int64 *)v_50;
                                        sub_1400F2D20(i, i2, dst2, 1);
                                        i2 = (__int64 *)arg_10;
                                    }
                                    i = (__int64 *)v_50;
                                    a1 = (size_t *)arg_8;
                                    a1 = (size_t *)((__int64)a1 + (__int64)i2);
                                    sub_1400F27F0(a1, ptr2, dst2);
                                    i2 = (__int64 *)((__int64)i2 + (__int64)dst2);
                                    arg_10 = (__int64)i2;
                                    if (ptr3 == 0) {
                                        ptr2 = (struct Struct_2_t *)v_58;
                                        a3 = (size_t *)v_28;
                                        ptr3 = (struct Struct_3_t *)v_50;
                                        a4 = (size_t *)v_48;
                                        a1 = (size_t *)v_68;
                                        i2 = (__int64 *)v_78;
                                        return (__int64)i2;
                                    }
                                    off_140108030();
                                    off_140108038(result, 0, ptr2);
                                    return (__int64)i2;
                                }
                                return (__int64)i2;
                            } while (ptr != 32);
                            return (__int64)i2;
                        }
                        return (__int64)i2;
                    }
                }
                return (__int64)i2;
            }
            return (__int64)i2;
        }
    } else {
        result = ptr3->field_0;
        v7 = ptr3->field_10;
        a1 = (size_t *)result;
        a1 -= v7;
        v_58 = v7;
        if (a1 <= 6) {
            return v_58;
        }
        return v_58;
    }
    do {
        v_20 = 1;
        sub_1400F2D20(ptr3, i2, 2, 1);
        a3 = (size_t *)v_28;
        i2 = ptr3->field_10;
        a1 = ptr3->field_0;
        result = ptr3->field_8;
        do {
            *(__int64 *)((__int64)result + (__int64)i2) = 0x820F;
            i2 += 2;
            ptr3->field_10 = i2;
            a1 = (size_t *)((__int64)a1 - (__int64)i2);
            v_20 = 1;
            sub_1400F2D20(ptr3, i2, 4, 1);
            a3 = (size_t *)v_28;
            result = ptr3->field_8;
            i2 = ptr3->field_10;
            *(__int64 *)((__int64)result + (__int64)i2) = v7;
            i2 += 4;
            ptr3->field_10 = i2;
            result = ptr3->field_0;
            a1 = (size_t *)result;
            a1 = (size_t *)((__int64)a1 - (__int64)i2);
            a2 = (size_t *)i2;
            if (a1 <= 5) {
                v_20 = 1;
                sub_1400F2D20(ptr3, i2, 6, 1);
                a3 = (size_t *)v_28;
                result = ptr3->field_0;
                a2 = ptr3->field_10;
            }
            a1 = ptr3->field_8;
            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x9E8B;
            a2 += 6;
            ptr3->field_10 = a2;
            a4 = (size_t *)result;
            a4 = (size_t *)((__int64)a4 - (__int64)a2);
            if (a4 <= 1) {
                v_20 = 1;
                sub_1400F2D20(ptr3, a2, 2, 1);
                a3 = (size_t *)v_28;
                a2 = ptr3->field_10;
                result = ptr3->field_0;
                a1 = ptr3->field_8;
            }
            *(__int64 *)((__int64)a1 + (__int64)a2) = 0xD839;
            a2 += 2;
            ptr3->field_10 = a2;
            result = (__int64 *)((__int64)result - (__int64)a2);
            a4 = a2;
            if (result <= 5) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a2;
                sub_1400F2D20(ptr3, a2, 6, 1);
                a3 = (size_t *)v_28;
                a1 = ptr3->field_8;
                a4 = ptr3->field_10;
            }
            *(__int64 *)((__int64)a1 + (__int64)a4 + 4) = 0;
            *(__int64 *)((__int64)a1 + (__int64)a4) = 0x850F;
            a4 += 6;
            ptr3->field_10 = a4;
            ptr2 += 11;
            *a3 = ptr2;
            result = 1;
            v_78 = (__int64)result;
            result = 4;
            v_48 = (__int64)result;
            v_68 = 0;
            v_50 = (__int64)a2;
            if (ptr4->field_68 != 0) {
                return v_50;
            }
            return v_50;
        } while (a2 > 1);
        return (__int64)result;
    } while (a2 <= 1);
}