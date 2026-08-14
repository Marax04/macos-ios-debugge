// inferred from 3 accesses on `result`
struct Struct_1_t {
    char _pad_start[2];
    char field_2; // offset 2
    __int64 field_3; // offset 3
    char _pad_3[5];
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();
__int64 sub_14002EDF0();
__int64 sub_1400F3510();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400FAE80();
__int64 sub_1400FAEF0();
__int64 sub_1400E03D0();
__int64 sub_140101C10();
__int64 sub_1400F3B80();
__int64 sub_1400F1570();
__int64 sub_1400F16D0();
__int64 sub_140106B83();
__int64 sub_1401041C4();
__int64 sub_1400F3340();
__int64 sub_1400F3326();
__int64 sub_140104016();
__int64 sub_1400F3869();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;
extern __int64 off_140108AA0;
extern __int64 off_140108AB0;
extern __int64 off_14011D060;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011D0E0;
extern __int64 off_14011D118;
extern __int64 off_14011D0F8;
extern __int64 off_14011D0C8;
extern __int64 off_14011D0AB;
extern __int64 off_14011D130;
extern __int64 off_14011D198;
extern __int64 off_14011D1E0;
extern __int64 off_14011D180;
extern __int64 off_14011D160;
extern __int64 off_14011D1C8;
extern __int64 off_14011D1B0;
extern __int64 off_14011D020;
extern __int64 off_14011D010;
extern __int64 off_14011CFC8;
extern __int64 off_14011CFB0;
extern __int64 off_14011CFF8;
extern __int64 off_14011CFE0;
extern __int64 off_14011D048;
extern __int64 off_14011D038;
extern __int64 off_14011D148;
extern __int64 off_14011D208;
extern __int64 off_14011D1F8;

__int64 __fastcall sub_140104391() {
    __int64 rsp;
    __int64 arg_10;
    int arg_12e;
    int arg_18;
    int arg_3;
    int arg_4;
    int arg_8;
    __int64 v_20;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    int v_47;
    int v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    __int64 v_80;
    int v_88;
    int v_90;
    __int64 v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    __int64 v_b8;
    __int64 v_c0;
    __int64 v_c8;
    int v_d0;
    int v_e0;
    __int64 v_f0;
    __int64 *v_0;
    struct Struct_1_t *result;
    __int64 v4;
    __int64 *dst;
    __int64 *i;
    __int64 *dst2;
    __int64 *dst3;
    __int64 v14;
    __int64 *i3;
    __int64 i4;
    __int64 v15;
    __int64 *i2;
    __m128i xmm0;
    __m128i xmm1;
    __int64 i5;
    __int64 v9;
    __int64 *i6;
    __int64 v10;
    __m128i xmm2;

    result = (struct Struct_1_t *)v_28;
    v4 = v_38;
    result -= v4;
    if (result <= 3) {
        v_20 = 1;
        dst = rsp + 40;
        sub_1400F2D20(dst, v4, 4, 1);
        v4 = v_38;
    }
    result = (struct Struct_1_t *)v_30;
    dst = *i;
    *(__int64 *)(result + v4) = (__int64)(dst);
    v4 += 4;
    v_38 = v4;
    off_140108030(dst, v4);
    off_140108038(result, 0, i);
    sub_14002EDF0(0, 11);
    if (result != 0) {
        i = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x202444C7);
        result = (struct Struct_1_t *)v_28;
        dst2 = (__int64 *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
        if (result <= 7) {
            v_20 = 1;
            dst = rsp + 40;
            sub_1400F2D20(dst, dst2, 8, 1);
            dst2 = (__int64 *)v_38;
        }
        dst3 = (__int64 *)v_30;
        result = *i;
        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
        dst2 += 8;
        v_38 = (__int64)dst2;
        off_140108030();
        off_140108038(result, 0, i);
        dst = (__int64 *)v_28;
        dst = (__int64 *)((__int64)dst - (__int64)dst2);
        v_80 = (__int64)dst2;
        result = (struct Struct_1_t *)dst2;
        if (dst <= 4) {
            v_20 = 1;
            dst = rsp + 40;
            v4 = v_80;
            sub_1400F2D20(dst, v4, 5, 1);
            dst3 = (__int64 *)v_30;
            result = (struct Struct_1_t *)v_38;
        }
        *(__int64 *)((__int64)dst3 + (__int64)result + 4) = 0;
        *(__int64 *)((__int64)dst3 + (__int64)result) = 232;
        result += 5;
        v_38 = (__int64)result;
        sub_14002EDF0(0, 7);
        if (result != 0) {
            i = (__int64 *)result;
            *(__int64 *)result = (__int64)(0x30C48348);
            result = (struct Struct_1_t *)v_28;
            dst3 = (__int64 *)v_38;
            result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
            if (result <= 3) {
                v_20 = 1;
                dst = rsp + 40;
                sub_1400F2D20(dst, dst3, 4, 1);
                dst3 = (__int64 *)v_38;
            }
            result = (struct Struct_1_t *)v_30;
            dst = *i;
            *(__int64 *)((__int64)result + (__int64)dst3) = dst;
            dst3 += 4;
            v_38 = (__int64)dst3;
            off_140108030(dst);
            off_140108038(result, 0, i);
            if (dst3 == v_28) {
                dst = rsp + 40;
                sub_1400F3510(dst);
            }
            result = (struct Struct_1_t *)v_30;
            *(__int64 *)((__int64)result + (__int64)dst3) = 77;
            result = dst3 + 1;
            v_38 = (__int64)result;
            if (result == v_28) {
                dst = rsp + 40;
                sub_1400F3510(dst);
            }
            result = (struct Struct_1_t *)v_30;
            *(__int64 *)((__int64)result + (__int64)dst3 + 1) = 49;
            result = dst3 + 2;
            v_38 = (__int64)result;
            if (result == v_28) {
                dst = rsp + 40;
                sub_1400F3510(dst);
            }
            result = (struct Struct_1_t *)v_30;
            *(__int64 *)((__int64)result + (__int64)dst3 + 2) = 237;
            result = dst3 + 3;
            v_38 = (__int64)result;
            if (result == v_28) {
                dst = rsp + 40;
                sub_1400F3510(dst);
            }
            result = (struct Struct_1_t *)v_30;
            *(__int64 *)((__int64)result + (__int64)dst3 + 3) = 77;
            result = dst3 + 4;
            v_38 = (__int64)result;
            if (result == v_28) {
                dst = rsp + 40;
                sub_1400F3510(dst);
            }
            v14 = (__int64)i2;
            v_50 = (__int64)i3;
            v_47 = v15;
            v_58 = i4;
            result = (struct Struct_1_t *)v_30;
            *(__int64 *)((__int64)result + (__int64)dst3 + 4) = 49;
            result = dst3 + 5;
            v_38 = (__int64)result;
            if (result == v_28) {
                dst = rsp + 40;
                sub_1400F3510(dst);
            }
            result = (struct Struct_1_t *)v_30;
            *(__int64 *)((__int64)result + (__int64)dst3 + 5) = 228;
            dst3 += 6;
            v_38 = (__int64)dst3;
            i = 32;
            i3 = rsp + 184;
            sub_14002EDF0(0, 12);
            while (result != 0) {
                v_b8 = 12;
                v_c0 = (__int64)result;
                *(__int64 *)result = (__int64)(0xC748);
                v_c8 = 2;
                sub_1400D4F50(i3, 0, 4, i);
                i4 = v_b8;
                v15 = v_c8;
                result = (struct Struct_1_t *)i4;
                result -= v15;
                if (result <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(i3, v15, 4, 1);
                    i4 = v_b8;
                    v15 = v_c8;
                }
                dst2 = (__int64 *)v_c0;
                *(dst2 + v15) = 0;
                v15 += 4;
                result = (struct Struct_1_t *)v_28;
                dst3 = (__int64 *)v_38;
                result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                if (v15 > result) {
                    v_20 = 1;
                    dst = rsp + 40;
                    sub_1400F2D20(dst, dst3, v15, 1);
                    dst3 = (__int64 *)v_38;
                }
                i2 = (__int64 *)v_30;
                dst = (__int64)dst3 + (__int64)i2;
                sub_1400F27F0(dst, dst2, v15);
                dst3 += v15;
                v_38 = (__int64)dst3;
                if (i4 == 0) {
                    i += 8;
                    i4 = v_47;
                    i3 = (__int64 *)v_50;
                    if (v14 != 0) {
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result < 4) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 4, 1);
                            i2 = (__int64 *)v_30;
                            dst3 = (__int64 *)v_38;
                        }
                        *(__int64 *)((__int64)i2 + (__int64)dst3) = 0x458B48;
                        dst3 += 4;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 4) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 5, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x24448948;
                        *(__int64 *)((__int64)result + (__int64)dst3 + 4) = 32;
                        dst3 += 5;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 3) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 4, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x8458B48;
                        dst3 += 4;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 4) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 5, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x24448948;
                        *(__int64 *)((__int64)result + (__int64)dst3 + 4) = 40;
                        dst3 += 5;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 3) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 4, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x10458B48;
                        dst3 += 4;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 4) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 5, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x24448948;
                        *(__int64 *)((__int64)result + (__int64)dst3 + 4) = 48;
                        dst3 += 5;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 3) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 4, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x18458B48;
                        dst3 += 4;
                        v_38 = (__int64)dst3;
                        result = (struct Struct_1_t *)v_28;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                        if (result <= 4) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, dst3, 5, 1);
                            dst3 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)((__int64)result + (__int64)dst3) = 0x24448948;
                        *(__int64 *)((__int64)result + (__int64)dst3 + 4) = 56;
                        dst3 += 5;
                        v_38 = (__int64)dst3;
                    }
                    sub_14002EDF0(0, 12);
                    if (result != 0) {
                        i = (__int64 *)result;
                        result = 0x2602484C748;
                        *i = result;
                        result = (struct Struct_1_t *)v_28;
                        arg_8 = 0;
                        v4 = v_38;
                        result -= v4;
                        if (result <= 11) {
                            v_20 = 1;
                            dst = rsp + 40;
                            sub_1400F2D20(dst, v4, 12, 1);
                            v4 = v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        dst = (__int64 *)arg_8;
                        *(__int64 *)(result + v4 + 8) = (__int64)(dst);
                        dst = *i;
                        *(__int64 *)(result + v4) = (__int64)(dst);
                        v4 += 12;
                        v_38 = v4;
                        off_140108030(dst, v4);
                        off_140108038(result, 0, i);
                        sub_14002EDF0(0, 12);
                        if (result != 0) {
                            i = (__int64 *)result;
                            result = 0x2682484C748;
                            *i = result;
                            result = (struct Struct_1_t *)v_28;
                            arg_8 = 0;
                            v4 = v_38;
                            result -= v4;
                            if (result <= 11) {
                                v_20 = 1;
                                dst = rsp + 40;
                                sub_1400F2D20(dst, v4, 12, 1);
                                v4 = v_38;
                            }
                            result = (struct Struct_1_t *)v_30;
                            dst = (__int64 *)arg_8;
                            *(__int64 *)(result + v4 + 8) = (__int64)(dst);
                            dst = *i;
                            *(__int64 *)(result + v4) = (__int64)(dst);
                            v4 += 12;
                            v_38 = v4;
                            off_140108030(dst, v4);
                            off_140108038(result, 0, i);
                            sub_14002EDF0(0, 10);
                            if (result != 0) {
                                i = (__int64 *)result;
                                *(__int64 *)result = (__int64)(0xB848);
                                result->field_2 = -1;
                                dst3 = (__int64 *)v_28;
                                i2 = (__int64 *)v_38;
                                result = (struct Struct_1_t *)dst3;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                if (result <= 9) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 10, 1);
                                    dst3 = (__int64 *)v_28;
                                    i2 = (__int64 *)v_38;
                                }
                                dst2 = (__int64 *)v_30;
                                result = (struct Struct_1_t *)arg_8;
                                *(__int64 *)((__int64)dst2 + (__int64)i2 + 8) = result;
                                result = *i;
                                *(__int64 *)((__int64)dst2 + (__int64)i2) = result;
                                i2 += 10;
                                v_38 = (__int64)i2;
                                off_140108030();
                                off_140108038(result, 0, i);
                                dst3 = (__int64 *)((__int64)dst3 - (__int64)i2);
                                if (dst3 <= 3) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 4, 1);
                                    dst2 = (__int64 *)v_30;
                                    i2 = (__int64 *)v_38;
                                }
                                *(__int64 *)((__int64)dst2 + (__int64)i2) = 0x24848948;
                                i2 += 4;
                                v_38 = (__int64)i2;
                                result = (struct Struct_1_t *)v_28;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 4, 1);
                                    i2 = (__int64 *)v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2) = 880;
                                i2 += 4;
                                v_38 = (__int64)i2;
                                result = (struct Struct_1_t *)v_28;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 4, 1);
                                    i2 = (__int64 *)v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2) = 0x2484C748;
                                i2 += 4;
                                v_38 = (__int64)i2;
                                result = (struct Struct_1_t *)v_28;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 4, 1);
                                    i2 = (__int64 *)v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2) = 0x488;
                                i2 += 4;
                                v_38 = (__int64)i2;
                                result = (struct Struct_1_t *)v_28;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 4, 1);
                                    i2 = (__int64 *)v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2) = 0;
                                result = i2 + 4;
                                v_38 = (__int64)result;
                                if (result == v_28) {
                                    dst = rsp + 40;
                                    sub_1400F3510(dst);
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2 + 4) = 72;
                                result = i2 + 5;
                                v_38 = (__int64)result;
                                if (result == v_28) {
                                    dst = rsp + 40;
                                    sub_1400F3510(dst);
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2 + 5) = 49;
                                result = i2 + 6;
                                v_38 = (__int64)result;
                                if (result == v_28) {
                                    dst = rsp + 40;
                                    sub_1400F3510(dst);
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2 + 6) = 192;
                                i2 += 7;
                                v_38 = (__int64)i2;
                                dst3 = 904;
                                i = rsp + 40;
                                do {
                                    result = (struct Struct_1_t *)v_28;
                                    result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                    v_20 = 1;
                                    sub_1400F2D20(i, i2, 4, 1);
                                    i2 = (__int64 *)v_38;
                                    result = (struct Struct_1_t *)v_30;
                                    *(__int64 *)((__int64)result + (__int64)i2) = 0x24848948;
                                    i2 += 4;
                                    v_38 = (__int64)i2;
                                    result = (struct Struct_1_t *)v_28;
                                    result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                    if (result <= 3) {
                                        v_20 = 1;
                                        sub_1400F2D20(i, i2, 4, 1);
                                        i2 = (__int64 *)v_38;
                                    }
                                    result = (struct Struct_1_t *)v_30;
                                    *(__int64 *)((__int64)result + (__int64)i2) = dst3;
                                    i2 += 4;
                                    v_38 = (__int64)i2;
                                    dst3 += 8;
                                } while (dst3 != 0x488);
                                result = 332;
                                i = 288;
                                if (i4 != 0) i = result;
                                if (v_28 == i2) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 1, 1);
                                    i2 = (__int64 *)v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2) = 233;
                                ++i2;
                                v_38 = (__int64)i2;
                                result = (struct Struct_1_t *)v_28;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 4, 1);
                                    i2 = (__int64 *)v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)((__int64)result + (__int64)i2) = i;
                                i2 += 4;
                                v_38 = (__int64)i2;
                                result = (struct Struct_1_t *)v_28;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)i2);
                                v15 = (__int64)i2;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i2, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xFFFF);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xAAAA);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0x5555);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0x505);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xF0F);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xF0F0);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xFAFA);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0x4411);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xCC33);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0x33CC);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0xBBEE);
                                v15 += 2;
                                v_38 = v15;
                                result = (struct Struct_1_t *)v_28;
                                result -= v15;
                                if (result <= 1) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, v15, 2, 1);
                                    v15 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v15) = (__int64)(0);
                                v15 += 2;
                                v_38 = v15;
                                v4 = i3 + 46;
                                dst3 = (__int64 *)v_28;
                                result = (struct Struct_1_t *)dst3;
                                result -= v15;
                                i = (__int64 *)v15;
                                if (result <= 255) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    i = (__int64 *)v4;
                                    sub_1400F2D20(dst, v15, 256, 1);
                                    v4 = (__int64)i;
                                    dst3 = (__int64 *)v_28;
                                    i = (__int64 *)v_38;
                                }
                                dst2 = (__int64 *)v_30;
                                dst = (__int64)dst2 + (__int64)i;
                                sub_1400F27F0(dst, v4, 256);
                                i += 256;
                                v_38 = (__int64)i;
                                dst3 = (__int64 *)((__int64)dst3 - (__int64)i);
                                v14 = (__int64)i;
                                if (dst3 <= 7) {
                                    v_20 = 1;
                                    dst = rsp + 40;
                                    sub_1400F2D20(dst, i, 8, 1);
                                    dst2 = (__int64 *)v_30;
                                    v14 = v_38;
                                }
                                result = (struct Struct_1_t *)arg_12e;
                                *(dst2 + v14) = result;
                                v14 += 8;
                                v_38 = v14;
                                if (i4 != 0) {
                                    dst2 = i3 + 1;
                                    dst = (__int64 *)v_28;
                                    result = (struct Struct_1_t *)dst;
                                    result -= v14;
                                    dst3 = (__int64 *)v14;
                                    if (result <= 31) {
                                        v_20 = 1;
                                        dst = rsp + 40;
                                        sub_1400F2D20(dst, v14, 32, 1);
                                        dst = (__int64 *)v_28;
                                        dst3 = (__int64 *)v_38;
                                    }
                                    i3 += 33;
                                    result = (struct Struct_1_t *)v_30;
                                    xmm0 = _mm_loadu_si128((__m128i *)dst2);
                                    xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)dst3 + 16), xmm1);
                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)dst3), xmm0);
                                    dst3 += 32;
                                    v_38 = (__int64)dst3;
                                    dst = (__int64 *)((__int64)dst - (__int64)dst3);
                                    i5 = (__int64)dst3;
                                    if (dst <= 11) {
                                        v_20 = 1;
                                        dst = rsp + 40;
                                        sub_1400F2D20(dst, dst3, 12, 1);
                                        result = (struct Struct_1_t *)v_30;
                                        i5 = v_38;
                                    }
                                    dst = (__int64 *)arg_8;
                                    *(__int64 *)(result + i5 + 8) = (__int64)(dst);
                                    dst = *i3;
                                    *(__int64 *)(result + i5) = (__int64)(dst);
                                    i5 += 12;
                                    v_38 = i5;
                                    dst = (__int64 *)v_48;
                                    v4 = (__int64)dst;
                                    v4 += 7;
                                    if (!((v4 < 0))) {
                                        v14 -= v4;
                                        v9 = v_78;
                                        if (v14 == v14) {
                                            dst += 3;
                                            if (dst <= -5) {
                                                if (v4 > i5) {
                                                    i6 = &off_14011D380;
                                                    sub_1400F3600(dst, v4, i5, i6);
                                                } else {
                                                    *(__int64 *)((__int64)result + (__int64)dst) = v14;
                                                    v4 = v9;
                                                    v4 += 7;
                                                    if (!((v4 < 0))) {
                                                        dst3 -= v4;
                                                        result = (struct Struct_1_t *)dst3;
                                                        if (dst3 == dst3) {
                                                            v9 += 3;
                                                            i5 = v_38;
                                                            if (v9 <= -5) {
                                                                if (v4 > i5) {
                                                                    i6 = &off_14011D380;
                                                                    sub_1400F3600(v9, v4, i5, i6);
                                                                } else {
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v9) = (__int64)(dst3);
                                                                    v14 = v_38;
                                                                    xmm0 = _mm_load_si128((__m128i *)&off_140108AA0);
                                                                    _mm_storeu_si128((__m128i *)&v_d0, xmm0);
                                                                    xmm0 = _mm_load_si128((__m128i *)&off_140108AB0);
                                                                    _mm_storeu_si128((__m128i *)&v_e0, xmm0);
                                                                    result = 0x49000000488;
                                                                    v_f0 = (__int64)result;
                                                                    v_b8 = (__int64)i2;
                                                                    v_c0 = v15;
                                                                    v_c8 = (__int64)i;
                                                                    dst = (__int64 *)v_28;
                                                                    result = (struct Struct_1_t *)dst;
                                                                    result -= v14;
                                                                    dst3 = (__int64 *)v14;
                                                                    if (result <= 4) {
                                                                        v_20 = 1;
                                                                        dst = rsp + 40;
                                                                        sub_1400F2D20(dst, v14, 5, 1);
                                                                        dst = (__int64 *)v_28;
                                                                        dst3 = (__int64 *)v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)((__int64)result + (__int64)dst3 + 4) = 55;
                                                                    *(__int64 *)((__int64)result + (__int64)dst3) = 0x4B60F43;
                                                                    dst3 += 5;
                                                                    v_38 = (__int64)dst3;
                                                                    v4 = (__int64)dst;
                                                                    v4 -= (__int64)dst3;
                                                                    if (v4 <= 2) {
                                                                        v_20 = 1;
                                                                        dst = rsp + 40;
                                                                        sub_1400F2D20(dst, dst3, 3, 1);
                                                                        dst3 = (__int64 *)v_38;
                                                                        dst = (__int64 *)v_28;
                                                                        result = (struct Struct_1_t *)v_30;
                                                                    }
                                                                    *(__int64 *)((__int64)result + (__int64)dst3 + 2) = 198;
                                                                    *(__int64 *)((__int64)result + (__int64)dst3) = 0xFF49;
                                                                    i = dst3 + 3;
                                                                    v_38 = (__int64)i;
                                                                    dst = (__int64 *)((__int64)dst - (__int64)i);
                                                                    if (dst <= 2) {
                                                                        v_20 = 1;
                                                                        dst = rsp + 40;
                                                                        sub_1400F2D20(dst, i, 3, 1);
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        i = (__int64 *)v_38;
                                                                    }
                                                                    *(__int64 *)((__int64)result + (__int64)i + 2) = 53;
                                                                    *(__int64 *)((__int64)result + (__int64)i) = 0x8D48;
                                                                    i += 3;
                                                                    v_38 = (__int64)i;
                                                                    dst3 += 10;
                                                                    if (!((dst3 < 0))) {
                                                                        v15 -= (__int64)dst3;
                                                                        dst = (__int64 *)v15;
                                                                        if (v15 == v15) {
                                                                            dst = (__int64 *)v_28;
                                                                            dst = (__int64 *)((__int64)dst - (__int64)i);
                                                                            if (dst <= 3) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, i, 4, 1);
                                                                                result = (struct Struct_1_t *)v_30;
                                                                                i = (__int64 *)v_38;
                                                                            }
                                                                            *(__int64 *)((__int64)result + (__int64)i) = v15;
                                                                            i += 4;
                                                                            v_38 = (__int64)i;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, i, 4, 1);
                                                                                i = (__int64 *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)i) = 0x604B60F;
                                                                            i += 4;
                                                                            v_38 = (__int64)i;
                                                                            v_60 = 0;
                                                                            v_68 = 8;
                                                                            v_70 = 0;
                                                                            v_88 = 0;
                                                                            v_90 = 8;
                                                                            v_98 = 0;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                            if (result <= 1) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, i, 2, 1);
                                                                                i = (__int64 *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)i) = 60;
                                                                            i += 2;
                                                                            v_38 = (__int64)i;
                                                                            dst = rsp + 96;
                                                                            sub_1400FAE80(dst, v4, i5, v14);
                                                                            result = (struct Struct_1_t *)v_68;
                                                                            *(__int64 *)result = (__int64)(i);
                                                                            v_70 = 1;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            v4 = v_38;
                                                                            dst = (__int64 *)result;
                                                                            dst -= v4;
                                                                            if (dst <= 5) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, v4, 6, 1);
                                                                                result = (struct Struct_1_t *)v_28;
                                                                                v4 = v_38;
                                                                            }
                                                                            dst = (__int64 *)v_30;
                                                                            *(dst + v4 + 4) = 0;
                                                                            *(dst + v4) = 0x840F;
                                                                            v4 += 6;
                                                                            v_38 = v4;
                                                                            result -= v4;
                                                                            if (result <= 1) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, v4, 2, 1);
                                                                                dst = (__int64 *)v_30;
                                                                                v4 = v_38;
                                                                            }
                                                                            *(dst + v4) = 316;
                                                                            v4 += 2;
                                                                            v_38 = v4;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result -= v4;
                                                                            if (result <= 1) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, v4, 2, 1);
                                                                                v4 = v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)(result + v4) = (__int64)(0xD75);
                                                                            v4 += 2;
                                                                            v_38 = v4;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result -= v4;
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, v4, 4, 1);
                                                                                v4 = v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)(result + v4) = (__int64)(0x2484FF48);
                                                                            v4 += 4;
                                                                            v_38 = v4;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result -= v4;
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                dst = rsp + 40;
                                                                                sub_1400F2D20(dst, v4, 4, 1);
                                                                                v4 = v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)(result + v4) = (__int64)(0x488);
                                                                            i4 = v4 + 4;
                                                                            v_38 = i4;
                                                                            v4 += 9;
                                                                            if (!((v4 < 0))) {
                                                                                i = (__int64 *)v14;
                                                                                i -= v4;
                                                                                if (v_28 == i4) {
                                                                                    v_20 = 1;
                                                                                    dst = rsp + 40;
                                                                                    sub_1400F2D20(dst, i4, 1, 1);
                                                                                    i4 = v_38;
                                                                                }
                                                                                result = (struct Struct_1_t *)v_30;
                                                                                *(__int64 *)(result + i4) = (__int64)(233);
                                                                                ++i4;
                                                                                v_38 = i4;
                                                                                result = (struct Struct_1_t *)i;
                                                                                if (i == i) {
                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                    result -= i4;
                                                                                    v_48 = v14;
                                                                                    if (result <= 3) {
                                                                                        v_20 = 1;
                                                                                        dst = rsp + 40;
                                                                                        sub_1400F2D20(dst, i4, 4, 1);
                                                                                        i4 = v_38;
                                                                                    }
                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                    *(__int64 *)(result + i4) = (__int64)(i);
                                                                                    i4 += 4;
                                                                                    v_38 = i4;
                                                                                    i = 8;
                                                                                    i3 = 0;
                                                                                    v15 = &off_14011D060;
                                                                                    v14 = rsp + 40;
                                                                                    dst3 = rsp + 136;
                                                                                    i2 = 8;
                                                                                    do {
                                                                                        dst2 = *(i3 + v15);
                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                        result -= i4;
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(v14, i4, 2, 1);
                                                                                        i4 = v_38;
                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                        dst = dst2;
                                                                                        dst = (__int64 *)((__int64)(__int64)dst << 8);
                                                                                        dst = (__int64 *)((__int64)(__int64)dst | 60);
                                                                                        *(__int64 *)(result + i4) = (__int64)(dst);
                                                                                        i4 += 2;
                                                                                        v_38 = i4;
                                                                                        if (i3 == v_88) {
                                                                                            sub_1400FAEF0(dst3, v4);
                                                                                            i2 = (__int64 *)v_90;
                                                                                        }
                                                                                        *(__int64 *)((__int64)i2 + (__int64)i - 8) = i4;
                                                                                        *(__int64 *)((__int64)i2 + (__int64)i) = i3;
                                                                                        ++i3;
                                                                                        v_98 = (__int64)i3;
                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                        dst2 = (__int64 *)v_38;
                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                        if (result <= 5) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(v14, dst2, 6, 1);
                                                                                            dst2 = (__int64 *)v_38;
                                                                                        }
                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 0;
                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = 0x840F;
                                                                                        i4 = dst2 + 6;
                                                                                        v_38 = i4;
                                                                                        i += 16;
                                                                                    } while (i3 != 75);
                                                                                    dst = (__int64 *)v_28;
                                                                                    dst -= i4;
                                                                                    if (dst <= 4) {
                                                                                        v_20 = 1;
                                                                                        dst = rsp + 40;
                                                                                        sub_1400F2D20(dst, i4, 5, 1);
                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                        i4 = v_38;
                                                                                    }
                                                                                    *(__int64 *)(result + i4 + 4) = (__int64)(0);
                                                                                    *(__int64 *)(result + i4) = (__int64)(233);
                                                                                    i4 += 5;
                                                                                    v_38 = i4;
                                                                                    sub_14002EDF0(8, 600);
                                                                                    v_50 = (__int64)result;
                                                                                    if (result != 0) {
                                                                                        i3 = (__int64 *)v_70;
                                                                                        i = 0;
                                                                                        do {
                                                                                            result = &off_14011D060;
                                                                                            i5 = *(__int64 *)((__int64)i + (__int64)result);
                                                                                            result = (struct Struct_1_t *)v_50;
                                                                                            ((__int64 *)result)[(__int64)i] = (__int64)(i4);
                                                                                            dst = rsp + 160;
                                                                                            v4 = rsp + 40;
                                                                                            i6 = rsp + 184;
                                                                                            sub_1400E03D0(dst, v4, i5, i6);
                                                                                            dst3 = (__int64 *)v_a0;
                                                                                            i4 = v_a8;
                                                                                            v15 = v_b0;
                                                                                            result = (struct Struct_1_t *)v_60;
                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i3);
                                                                                            v_20 = 8;
                                                                                            dst = rsp + 96;
                                                                                            sub_1400F2D20(dst, i3, v15, 8);
                                                                                            v14 = v_70;
                                                                                            i5 =  + v15*8;
                                                                                            i2 = (__int64 *)v_68;
                                                                                            dst =  + v14*8;
                                                                                            dst = (__int64 *)((__int64)dst + (__int64)i2);
                                                                                            v_78 = i5;
                                                                                            sub_1400F27F0(dst, i4, i5);
                                                                                            v15 += v14;
                                                                                            v_70 = v15;
                                                                                            if (dst3 == 0) {
                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                i3 = (__int64 *)v_38;
                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)i3);
                                                                                                if (result <= 3) {
                                                                                                    v_20 = 1;
                                                                                                    dst = rsp + 40;
                                                                                                    sub_1400F2D20(dst, i3, 4, 1);
                                                                                                    i3 = (__int64 *)v_38;
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i3) = 0x2484FF48;
                                                                                                i3 += 4;
                                                                                                v_38 = (__int64)i3;
                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)i3);
                                                                                                if (result <= 3) {
                                                                                                    v_20 = 1;
                                                                                                    dst = rsp + 40;
                                                                                                    sub_1400F2D20(dst, i3, 4, 1);
                                                                                                    i3 = (__int64 *)v_38;
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i3) = 0x488;
                                                                                                i4 = i3 + 4;
                                                                                                v_38 = i4;
                                                                                                i3 += 9;
                                                                                                if (!((i3 < 0))) {
                                                                                                    if (v_28 == i4) {
                                                                                                        v_20 = 1;
                                                                                                        dst = rsp + 40;
                                                                                                        sub_1400F2D20(dst, i4, 1, 1);
                                                                                                        i4 = v_38;
                                                                                                    }
                                                                                                    dst3 = (__int64 *)v_48;
                                                                                                    dst3 = (__int64 *)((__int64)dst3 - (__int64)i3);
                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                    *(__int64 *)(result + i4) = (__int64)(233);
                                                                                                    ++i4;
                                                                                                    v_38 = i4;
                                                                                                    result = (struct Struct_1_t *)dst3;
                                                                                                    if (dst3 == dst3) {
                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                        result -= i4;
                                                                                                        if (result <= 3) {
                                                                                                            v_20 = 1;
                                                                                                            dst = rsp + 40;
                                                                                                            sub_1400F2D20(dst, i4, 4, 1);
                                                                                                            i4 = v_38;
                                                                                                        }
                                                                                                        ++i;
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)(result + i4) = (__int64)(dst3);
                                                                                                        i4 += 4;
                                                                                                        v_38 = i4;
                                                                                                        i3 = (__int64 *)v15;
                                                                                                        sub_14002EDF0(0, 8);
                                                                                                        if (result != 0) {
                                                                                                            i = (__int64 *)result;
                                                                                                            *(__int64 *)result = (__int64)(0x24448B48);
                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                            v4 = v_38;
                                                                                                            arg_4 = 32;
                                                                                                            result -= v4;
                                                                                                            if (result <= 4) {
                                                                                                                v_20 = 1;
                                                                                                                dst = rsp + 40;
                                                                                                                sub_1400F2D20(dst, v4, 5, 1);
                                                                                                                v4 = v_38;
                                                                                                            }
                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                            dst = (__int64 *)arg_4;
                                                                                                            *(__int64 *)(result + v4 + 4) = (__int64)(dst);
                                                                                                            dst = *i;
                                                                                                            *(__int64 *)(result + v4) = (__int64)(dst);
                                                                                                            v4 += 5;
                                                                                                            v_38 = v4;
                                                                                                            off_140108030(dst, v4);
                                                                                                            off_140108038(result, 0, i);
                                                                                                            sub_14002EDF0(0, 7);
                                                                                                            if (result != 0) {
                                                                                                                i = (__int64 *)result;
                                                                                                                *(__int64 *)result = (__int64)(0x8148);
                                                                                                                result->field_3 = 0x490;
                                                                                                                result->field_2 = 196;
                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                v4 = v_38;
                                                                                                                result -= v4;
                                                                                                                if (result <= 6) {
                                                                                                                    v_20 = 1;
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F2D20(dst, v4, 7, 1);
                                                                                                                    v4 = v_38;
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                dst = *i;
                                                                                                                i5 = arg_3;
                                                                                                                *(__int64 *)(result + v4 + 3) = (__int64)(i5);
                                                                                                                *(__int64 *)(result + v4) = (__int64)(dst);
                                                                                                                v4 += 7;
                                                                                                                v_38 = v4;
                                                                                                                off_140108030(dst, v4, i5);
                                                                                                                off_140108038(result, 0, i);
                                                                                                                i3 = (__int64 *)v_38;
                                                                                                                if (i3 == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3) = 65;
                                                                                                                result = i3 + 1;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 1) = 95;
                                                                                                                result = i3 + 2;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 2) = 65;
                                                                                                                result = i3 + 3;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 3) = 94;
                                                                                                                result = i3 + 4;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 4) = 65;
                                                                                                                result = i3 + 5;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 5) = 93;
                                                                                                                result = i3 + 6;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 6) = 65;
                                                                                                                result = i3 + 7;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 7) = 92;
                                                                                                                result = i3 + 8;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 8) = 95;
                                                                                                                result = i3 + 9;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 9) = 94;
                                                                                                                result = i3 + 10;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 10) = 93;
                                                                                                                result = i3 + 11;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 11) = 91;
                                                                                                                result = i3 + 12;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    dst = rsp + 40;
                                                                                                                    sub_1400F3510(dst);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)((__int64)result + (__int64)i3 + 12) = 195;
                                                                                                                i3 += 13;
                                                                                                                v_38 = (__int64)i3;
                                                                                                                if (v_47 != 0) {
                                                                                                                    dst = rsp + 160;
                                                                                                                    sub_140101C10(dst);
                                                                                                                    v4 = v_a8;
                                                                                                                    dst3 = (__int64 *)v_b0;
                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                    i = (__int64 *)v_38;
                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                                                                    v_48 = v4;
                                                                                                                    if (dst3 > result) {
                                                                                                                        v_20 = 1;
                                                                                                                        dst = rsp + 40;
                                                                                                                        sub_1400F2D20(dst, i, dst3, 1);
                                                                                                                        v4 = v_48;
                                                                                                                        i = (__int64 *)v_38;
                                                                                                                    }
                                                                                                                    dst = (__int64 *)v_30;
                                                                                                                    dst = (__int64 *)((__int64)dst + (__int64)i);
                                                                                                                    sub_1400F27F0(dst, v4, dst3);
                                                                                                                    i = (__int64 *)((__int64)i + (__int64)dst3);
                                                                                                                    v_38 = (__int64)i;
                                                                                                                    if (v_a0 == 0) {
                                                                                                                        result = (struct Struct_1_t *)v_38;
                                                                                                                        dst = (__int64 *)v_58;
                                                                                                                        arg_10 = (__int64)result;
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                                                        _mm_storeu_si128((__m128i *)dst, xmm0);
                                                                                                                        i6 = (__int64 *)v_80;
                                                                                                                        v4 = (__int64)i6;
                                                                                                                        v4 += 5;
                                                                                                                        if ((v4 < 0)) {
                                                                                                                            result = &off_14011B3E0;
                                                                                                                            v_20 = (__int64)result;
                                                                                                                            dst = &off_14011B3C3;
                                                                                                                            i6 = &off_14011D3F8;
                                                                                                                            i5 = rsp + 70;
                                                                                                                            sub_1400F3B80(dst, 23, i5, i6);
                                                                                                                            i6 = &off_14011D0E0;
                                                                                                                            sub_1400F3600(dst, v4, i5, i6);
                                                                                                                        }
                                                                                                                        i3 -= v4;
                                                                                                                        result = (struct Struct_1_t *)i3;
                                                                                                                        if (i3 == i3) {
                                                                                                                            ++i6;
                                                                                                                            result = (struct Struct_1_t *)v_58;
                                                                                                                            i5 = result->field_10;
                                                                                                                            if (v4 < i6) {
                                                                                                                                return i5;
                                                                                                                            }
                                                                                                                            if (v4 > i5) {
                                                                                                                                return i5;
                                                                                                                            }
                                                                                                                            v4 = v_58;
                                                                                                                            result = (struct Struct_1_t *)arg_8;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst) = i3;
                                                                                                                            i3 = (__int64 *)v4;
                                                                                                                            result = (struct Struct_1_t *)v_60;
                                                                                                                            if (v15 != 0) {
                                                                                                                                i6 = (__int64 *)arg_8;
                                                                                                                                i5 = arg_10;
                                                                                                                                dst = (__int64 *)v_78;
                                                                                                                                v9 = dst + v14*8;
                                                                                                                                v10 = 0;
                                                                                                                                dst = *(i2 + v10);
                                                                                                                                v4 = (__int64)dst;
                                                                                                                                v4 += 6;
                                                                                                                                while (!((v4 < 0))) {
                                                                                                                                    i = (__int64 *)i4;
                                                                                                                                    i -= v4;
                                                                                                                                    dst3 = i;
                                                                                                                                    if (i == i) {
                                                                                                                                        dst += 2;
                                                                                                                                        if (v4 >= dst) {
                                                                                                                                            if (v4 <= i5) {
                                                                                                                                                *(__int64 *)((__int64)i6 + (__int64)dst) = i;
                                                                                                                                                v10 += 8;
                                                                                                                                                if (result == 0) {
                                                                                                                                                    result = (struct Struct_1_t *)v_88;
                                                                                                                                                    i = (__int64 *)v_90;
                                                                                                                                                    i6 = (__int64 *)arg_8;
                                                                                                                                                    i5 = arg_10;
                                                                                                                                                    v9 = 8;
                                                                                                                                                    dst = *(i + v9);
                                                                                                                                                    while (dst < 75) {
                                                                                                                                                        v4 = v_50;
                                                                                                                                                        v10 = v_0[(__int64)dst];
                                                                                                                                                        if (v10 < 0) {
                                                                                                                                                            return v10;
                                                                                                                                                        }
                                                                                                                                                        dst = *(i + v9 - 8);
                                                                                                                                                        v4 = (__int64)dst;
                                                                                                                                                        v4 += 6;
                                                                                                                                                        if ((v4 < 0)) {
                                                                                                                                                            return v4;
                                                                                                                                                        }
                                                                                                                                                        v10 -= v4;
                                                                                                                                                        dst3 = (__int64 *)v10;
                                                                                                                                                        if (v10 == v10) {
                                                                                                                                                            dst += 2;
                                                                                                                                                            if (v4 >= dst) {
                                                                                                                                                                if (v4 <= i5) {
                                                                                                                                                                    *(__int64 *)((__int64)i6 + (__int64)dst) = v10;
                                                                                                                                                                    v9 += 16;
                                                                                                                                                                    if (result == 0) {
                                                                                                                                                                        v4 = (__int64)dst2;
                                                                                                                                                                        v4 += 11;
                                                                                                                                                                        if ((v4 < 0)) {
                                                                                                                                                                            return v4;
                                                                                                                                                                        }
                                                                                                                                                                        i4 -= v4;
                                                                                                                                                                        result = (struct Struct_1_t *)i4;
                                                                                                                                                                        if (i4 != i4) {
                                                                                                                                                                            result = &off_14011D118;
                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                            dst = &off_14011D0F8;
                                                                                                                                                                            i6 = &off_14011D3F8;
                                                                                                                                                                            i5 = rsp + 70;
                                                                                                                                                                            sub_1400F3B80(dst, 27, i5, i6);
                                                                                                                                                                            result = &off_14011D0C8;
                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                            dst = &off_14011D0AB;
                                                                                                                                                                            i6 = &off_14011D3F8;
                                                                                                                                                                            i5 = rsp + 70;
                                                                                                                                                                            sub_1400F3B80(dst, 27, i5, i6);
                                                                                                                                                                            dst2 = (__int64 *)arg_18;
                                                                                                                                                                            result = (struct Struct_1_t *)dst2;
                                                                                                                                                                            ++result;
                                                                                                                                                                            if ((result == 0)) JUMPOUT(0x140106e6e);
                                                                                                                                                                            i = dst;
                                                                                                                                                                            v4 = arg_8;
                                                                                                                                                                            v_20 = v4;
                                                                                                                                                                            i2 = v4 + 1;
                                                                                                                                                                            dst = i2;
                                                                                                                                                                            dst = (__int64 *)((__int64)(__int64)dst >> 3);
                                                                                                                                                                            i4 = (__int64)i2;
                                                                                                                                                                            i4 &= -8;
                                                                                                                                                                            i4 -= (__int64)dst;
                                                                                                                                                                            i5 = i4;
                                                                                                                                                                            if (v4 < 8) i4 = v4;
                                                                                                                                                                            dst = (__int64 *)i4;
                                                                                                                                                                            dst = (__int64 *)((__int64)(__int64)dst >> 1);
                                                                                                                                                                            if (result <= dst) JUMPOUT(0x140106b55);
                                                                                                                                                                            ++i5;
                                                                                                                                                                            if (i5 <= result) i5 = result;
                                                                                                                                                                            dst = rsp + 72;
                                                                                                                                                                            sub_1400F1570(dst, 48, i5);
                                                                                                                                                                            i3 = (__int64 *)v_48;
                                                                                                                                                                            dst3 = (__int64 *)v_50;
                                                                                                                                                                            if (i3 == 0) JUMPOUT(0x140106e5a);
                                                                                                                                                                            result = (struct Struct_1_t *)v_58;
                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                            v_30 = (__int64)i;
                                                                                                                                                                            i2 = *i;
                                                                                                                                                                            v_28 = (__int64)dst2;
                                                                                                                                                                            i6 = (__int64 *)v_20;
                                                                                                                                                                            if (dst2 == 0) JUMPOUT(0x140106b83);
                                                                                                                                                                            xmm0 = _mm_load_si128((__m128i *)i2);
                                                                                                                                                                            v14 = _mm_movemask_epi8(xmm0);
                                                                                                                                                                            v14 = ~v14;
                                                                                                                                                                            result = i2 - 48;
                                                                                                                                                                            v_40 = (__int64)result;
                                                                                                                                                                            i = 0;
                                                                                                                                                                            v15 = v_28;
                                                                                                                                                                            dst2 = i2;
                                                                                                                                                                            do {
                                                                                                                                                                                i4 = __builtin_ctz(v14);
                                                                                                                                                                                i4 += (__int64)i;
                                                                                                                                                                                result = (struct Struct_1_t *)i4;
                                                                                                                                                                                result = (struct Struct_1_t *)(-(__int64)result);
                                                                                                                                                                                dst = result + (__int64)(__int64)result*2;
                                                                                                                                                                                dst = (__int64 *)((__int64)(__int64)dst << 4);
                                                                                                                                                                                dst += v_40;
                                                                                                                                                                                sub_1400F16D0(dst, v4, i5, i6);
                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                dst = (__int64 *)((__int64)(__int64)dst & (__int64)dst3);
                                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)i3 + (__int64)dst));
                                                                                                                                                                                v4 = _mm_movemask_epi8(xmm0);
                                                                                                                                                                                if (v4 == 0) JUMPOUT(0x140106b19);
                                                                                                                                                                                i6 = (__int64 *)v_20;
                                                                                                                                                                                v4 = __builtin_ctz(v4);
                                                                                                                                                                                v4 += (__int64)dst;
                                                                                                                                                                                v4 &= (__int64)dst3;
                                                                                                                                                                                if ((*(i3 + v4) - 0) >= 0) JUMPOUT(0x140106b42);
                                                                                                                                                                                dst = v14 - 1;
                                                                                                                                                                                dst = (__int64 *)((__int64)(__int64)dst & v14);
                                                                                                                                                                                --v15;
                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)(__int64)result >> 57);
                                                                                                                                                                                i5 = v4 - 16;
                                                                                                                                                                                i5 &= (__int64)dst3;
                                                                                                                                                                                *(i3 + v4) = result;
                                                                                                                                                                                *(i3 + i5 + 16) = result;
                                                                                                                                                                                i4 = ~i4;
                                                                                                                                                                                result = i4 + i4*2;
                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                                                                                                                                                                                v4 = ~v4;
                                                                                                                                                                                v4 += v4*2;
                                                                                                                                                                                v4 <<= 4;
                                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)i2 + (__int64)result));
                                                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)i2 + (__int64)result + 16));
                                                                                                                                                                                xmm2 = _mm_loadu_si128((__m128i *)((__int64)i2 + (__int64)result + 32));
                                                                                                                                                                                _mm_storeu_si128((__m128i *)(i3 + v4 + 32), xmm2);
                                                                                                                                                                                _mm_storeu_si128((__m128i *)(i3 + v4 + 16), xmm1);
                                                                                                                                                                                _mm_storeu_si128((__m128i *)(i3 + v4), xmm0);
                                                                                                                                                                                v14 = (__int64)dst;
                                                                                                                                                                            } while (v15 != 0);
                                                                                                                                                                            return sub_140106B83();
                                                                                                                                                                        } else {
                                                                                                                                                                            i5 = arg_10;
                                                                                                                                                                            if (v4 > i5) {
                                                                                                                                                                                dst2 += 7;
                                                                                                                                                                                i6 = &off_14011D130;
                                                                                                                                                                                sub_1400F3600(dst2, v4, i5, i6);
                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                dst = rsp + 40;
                                                                                                                                                                                sub_1400F2D20(dst, dst3, 3, 1);
                                                                                                                                                                                dst3 = (__int64 *)v_38;
                                                                                                                                                                                return sub_1401041C4();
                                                                                                                                                                            } else {
                                                                                                                                                                                result = (struct Struct_1_t *)arg_8;
                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2 + 7) = i4;
                                                                                                                                                                                off_140108030(dst, v4, i5);
                                                                                                                                                                                i5 = v_50;
                                                                                                                                                                                off_140108038(result, 0, i5);
                                                                                                                                                                                return i5;
                                                                                                                                                                            }
                                                                                                                                                                        }
                                                                                                                                                                    }
                                                                                                                                                                    off_140108030(dst, v4, i5, i6);
                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                    return i5;
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                            i6 = &off_14011D198;
                                                                                                                                                            sub_1400F3600(i6, v4, i5, i6);
                                                                                                                                                            i6 = &off_14011D1E0;
                                                                                                                                                            sub_1400F3600(dst, v4, i5, i6);
                                                                                                                                                            sub_1400F3340(1, 3);
                                                                                                                                                            sub_1400F3326(1, 12);
                                                                                                                                                            v_20 = 1;
                                                                                                                                                            dst = rsp + 40;
                                                                                                                                                            sub_1400F2D20(dst, v4, 7, 1);
                                                                                                                                                            v4 = v_38;
                                                                                                                                                            return sub_140104016();
                                                                                                                                                        }
                                                                                                                                                        result = &off_14011D180;
                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                        dst = &off_14011D160;
                                                                                                                                                        i6 = &off_14011D3F8;
                                                                                                                                                        i5 = rsp + 70;
                                                                                                                                                        sub_1400F3B80(dst, 26, i5, i6);
                                                                                                                                                        result = &off_14011D1C8;
                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                        dst = &off_14011D1B0;
                                                                                                                                                        i6 = &off_14011D3F8;
                                                                                                                                                        i5 = rsp + 70;
                                                                                                                                                        sub_1400F3B80(dst, 18, i5, i6);
                                                                                                                                                        sub_1400F3326(1, 10);
                                                                                                                                                        result = &off_14011D020;
                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                        dst = &off_14011D010;
                                                                                                                                                        i6 = &off_14011D3F8;
                                                                                                                                                        i5 = rsp + 70;
                                                                                                                                                        sub_1400F3B80(dst, 15, i5, i6);
                                                                                                                                                        sub_1400F3326(1, 11);
                                                                                                                                                        result = &off_14011CFC8;
                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                        dst = &off_14011CFB0;
                                                                                                                                                        i6 = &off_14011D3F8;
                                                                                                                                                        i5 = rsp + 70;
                                                                                                                                                        sub_1400F3B80(dst, 17, i5, i6);
                                                                                                                                                        result = &off_14011CFF8;
                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                        dst = &off_14011CFE0;
                                                                                                                                                        i6 = &off_14011D3F8;
                                                                                                                                                        i5 = rsp + 70;
                                                                                                                                                        sub_1400F3B80(dst, 19, i5, i6);
                                                                                                                                                        result = &off_14011D048;
                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                        dst = &off_14011D038;
                                                                                                                                                        i6 = &off_14011D3F8;
                                                                                                                                                        i5 = rsp + 70;
                                                                                                                                                        sub_1400F3B80(dst, 10, i5, i6);
                                                                                                                                                        sub_1400F3326(8, 600);
                                                                                                                                                        sub_1400F3326(1, 8);
                                                                                                                                                        return i5;
                                                                                                                                                    }
                                                                                                                                                    i5 = &off_14011D148;
                                                                                                                                                    sub_1400F3869(dst, 75, i5);
                                                                                                                                                    return i5;
                                                                                                                                                }
                                                                                                                                                off_140108030(dst, v4, i5, i6);
                                                                                                                                                off_140108038(result, 0, i2);
                                                                                                                                                return i5;
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                        return i5;
                                                                                                                                    }
                                                                                                                                    return i5;
                                                                                                                                }
                                                                                                                                return i5;
                                                                                                                            }
                                                                                                                            return i5;
                                                                                                                        }
                                                                                                                        return i5;
                                                                                                                    }
                                                                                                                    off_140108030();
                                                                                                                    i5 = v_48;
                                                                                                                    off_140108038(result, 0, i5);
                                                                                                                    return i5;
                                                                                                                } else {
                                                                                                                    result = (struct Struct_1_t *)v_38;
                                                                                                                    i3 = (__int64 *)v_58;
                                                                                                                    arg_10 = (__int64)result;
                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                                                    _mm_storeu_si128((__m128i *)i3, xmm0);
                                                                                                                    result = (struct Struct_1_t *)v_60;
                                                                                                                    if (v15 == 0) {
                                                                                                                        return (__int64)result;
                                                                                                                    }
                                                                                                                    return (__int64)result;
                                                                                                                }
                                                                                                                return (__int64)result;
                                                                                                            }
                                                                                                            do {
                                                                                                                sub_1400F3326(1, 7);
                                                                                                                result = &off_14011D208;
                                                                                                                v_20 = (__int64)result;
                                                                                                                dst = &off_14011D1F8;
                                                                                                                i6 = &off_14011D3F8;
                                                                                                                i5 = rsp + 70;
                                                                                                                sub_1400F3B80(dst, 14, i5, i6);
                                                                                                                return i5;
                                                                                                            } while (true);
                                                                                                        }
                                                                                                        return i5;
                                                                                                    }
                                                                                                    return i5;
                                                                                                }
                                                                                                return i5;
                                                                                            }
                                                                                            off_140108030();
                                                                                            off_140108038(result, 0, i4);
                                                                                            return i5;
                                                                                        } while (i != 75);
                                                                                        return i5;
                                                                                    }
                                                                                    return i5;
                                                                                }
                                                                                return i5;
                                                                            }
                                                                            return i5;
                                                                        }
                                                                        return i5;
                                                                    }
                                                                    return i5;
                                                                }
                                                                return i5;
                                                            }
                                                            return i5;
                                                        }
                                                        return i5;
                                                    }
                                                    return i5;
                                                }
                                                return i5;
                                            }
                                            return i5;
                                        }
                                        return i5;
                                    }
                                    return i5;
                                }
                                return i5;
                            }
                            return i5;
                        }
                    }
                    return i5;
                }
                off_140108030();
                off_140108038(result, 0, dst2);
                return i5;
            }
            return i5;
        }
        return i5;
    }
    return (__int64)result;
}