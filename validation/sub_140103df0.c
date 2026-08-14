// inferred from 9 accesses on `result`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    char field_2; // offset 2
    char field_3; // offset 3
    char field_4; // offset 4
    char field_5; // offset 5
    char field_6; // offset 6
    int field_7; // offset 7
    int field_B; // offset 11
    char _pad_B[1];
    __int64 field_10; // offset 16
};

__int64 sub_1400F3510();
__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3B80();
__int64 sub_1400F3600();
__int64 sub_1400FAE80();
__int64 sub_1400FAEF0();
__int64 sub_1400E03D0();
__int64 sub_140101C10();
__int64 sub_1400F1570();
__int64 sub_1400F16D0();
__int64 sub_140106B83();
__int64 sub_1400F3326();
__int64 sub_1400F3869();
__int64 sub_1400F3340();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140108AA0;
extern __int64 off_140108AB0;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011D0E0;
extern __int64 off_14011D060;
extern __int64 off_14011D198;
extern __int64 off_14011D130;
extern __int64 off_14011D118;
extern __int64 off_14011D0F8;
extern __int64 off_14011D0C8;
extern __int64 off_14011D0AB;
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
extern __int64 off_14011D380;
extern __int64 off_14011D208;
extern __int64 off_14011D1F8;
extern __int64 off_14011D1E0;

__int64 __fastcall sub_140103DF0(size_t *a1, size_t *a2) {
    __int64 rsp;
    __int64 arg_10;
    int arg_12e;
    int arg_2;
    int arg_2d;
    int arg_3;
    int arg_4;
    int arg_8;
    int arg_9;
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
    int v_80;
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
    __int64 *i;
    __int64 i2;
    struct Struct_1_t *result;
    __int64 *i3;
    __int64 i4;
    __int64 v4;
    __int64 *i5;
    __int64 v13;
    __int64 v12;
    __int64 *dst;
    __m128i xmm0;
    __int64 *i6;
    __int64 v7;
    __int64 v8;
    __m128i xmm1;
    __m128i xmm2;

    i = (__int64 *)a2;
    i2 = (__int64)a1;
    v_28 = 0;
    v_30 = 1;
    v_38 = 0;
    a1 = rsp + 40;
    sub_1400F3510(a1);
    result = (struct Struct_1_t *)v_30;
    *(__int64 *)result = (__int64)(83);
    v_38 = 1;
    if (v_28 == 1) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_1 = 85;
    v_38 = 2;
    if (v_28 == 2) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_2 = 86;
    v_38 = 3;
    if (v_28 == 3) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_3 = 87;
    v_38 = 4;
    if (v_28 == 4) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_4 = 65;
    v_38 = 5;
    if (v_28 == 5) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_5 = 84;
    v_38 = 6;
    if (v_28 == 6) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_6 = 65;
    v_38 = 7;
    if (v_28 == 7) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_7 = 85;
    v_38 = 8;
    result = (struct Struct_1_t *)v_28;
    if (result == 8) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
        result = (struct Struct_1_t *)v_28;
    }
    a1 = (size_t *)v_30;
    arg_8 = 65;
    v_38 = 9;
    if (result == 9) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
        result = (struct Struct_1_t *)v_28;
    }
    a1 = (size_t *)v_30;
    arg_9 = 86;
    v_38 = 10;
    if (result == 10) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
        result = (struct Struct_1_t *)v_28;
    }
    a1 = (size_t *)v_30;
    a1[1] = 65;
    v_38 = 11;
    if (result == 11) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_B = 87;
    v_38 = 12;
    sub_14002EDF0(0, 7);
    if (result != 0) {
        i3 = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8148);
        result->field_3 = 0x490;
        result->field_2 = 236;
        result = (struct Struct_1_t *)v_28;
        a2 = (size_t *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
        if (result <= 6) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, a2, 7, 1);
            a2 = (size_t *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = *i3;
        i4 = arg_3;
        *(__int64 *)((__int64)result + (__int64)a2 + 3) = i4;
        *(__int64 *)((__int64)result + (__int64)a2) = a1;
        a2 += 7;
        v_38 = (__int64)a2;
        off_140108030(a1, a2, i4);
        off_140108038(result, 0, i3);
        sub_14002EDF0(0, 3);
        i3 = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8949);
        result->field_2 = 207;
        result = (struct Struct_1_t *)v_28;
        a2 = (size_t *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, a2, 3, 1);
            a2 = (size_t *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
        a1 = *i3;
        *(__int64 *)((__int64)result + (__int64)a2) = a1;
        a2 += 3;
        v_38 = (__int64)a2;
        off_140108030(a1, a2);
        off_140108038(result, 0, i3);
        sub_14002EDF0(0, 3);
        i3 = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8949);
        result->field_2 = 214;
        result = (struct Struct_1_t *)v_28;
        a2 = (size_t *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, a2, 3, 1);
            a2 = (size_t *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
        a1 = *i3;
        *(__int64 *)((__int64)result + (__int64)a2) = a1;
        a2 += 3;
        v_38 = (__int64)a2;
        off_140108030(a1, a2);
        off_140108038(result, 0, i3);
        sub_14002EDF0(0, 3);
        i3 = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x894D);
        result->field_2 = 197;
        result = (struct Struct_1_t *)v_28;
        v4 = v_38;
        result -= v4;
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, v4, 3, 1);
            v4 = v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)(result + v4 + 2) = (__int64)(a1);
        a1 = *i3;
        *(__int64 *)(result + v4) = (__int64)(a1);
        v4 += 3;
        v_38 = v4;
        off_140108030(a1);
        off_140108038(result, 0, i3);
        i5 = (__int64 *)arg_2d;
        if (i5 == 0) {
            do {
                v13 = *i;
                if (v4 != v_28) {
                    result = (struct Struct_1_t *)v_30;
                    *(__int64 *)(result + v4) = (__int64)(77);
                    result = v4 + 1;
                    v_38 = (__int64)result;
                    if (result != v_28) {
                        result = (struct Struct_1_t *)v_30;
                        *(__int64 *)(result + v4 + 1) = (__int64)(49);
                        result = v4 + 2;
                        v_38 = (__int64)result;
                        if (result != v_28) {
                            result = (struct Struct_1_t *)v_30;
                            *(__int64 *)(result + v4 + 2) = (__int64)(237);
                            result = v4 + 3;
                            v_38 = (__int64)result;
                            if (result != v_28) {
                                result = (struct Struct_1_t *)v_30;
                                *(__int64 *)(result + v4 + 3) = (__int64)(77);
                                result = v4 + 4;
                                v_38 = (__int64)result;
                                if (result != v_28) {
                                    v12 = (__int64)i5;
                                    v_50 = (__int64)i;
                                    v_47 = v13;
                                    v_58 = i2;
                                    result = (struct Struct_1_t *)v_30;
                                    *(__int64 *)(result + v4 + 4) = (__int64)(49);
                                    result = v4 + 5;
                                    v_38 = (__int64)result;
                                    if (result != v_28) {
                                        result = (struct Struct_1_t *)v_30;
                                        *(__int64 *)(result + v4 + 5) = (__int64)(228);
                                        v4 += 6;
                                        v_38 = v4;
                                        i3 = 32;
                                        i = rsp + 184;
                                        do {
                                            sub_14002EDF0(0, 12);
                                            v_b8 = 12;
                                            v_c0 = (__int64)result;
                                            *(__int64 *)result = (__int64)(0xC748);
                                            v_c8 = 2;
                                            sub_1400D4F50(i, 0, 4, i3);
                                            i2 = v_b8;
                                            v13 = v_c8;
                                            result = (struct Struct_1_t *)i2;
                                            result -= v13;
                                            if (result <= 3) {
                                                v_20 = 1;
                                                sub_1400F2D20(i, v13, 4, 1);
                                                i2 = v_b8;
                                                v13 = v_c8;
                                            }
                                            dst = (__int64 *)v_c0;
                                            *(dst + v13) = 0;
                                            v13 += 4;
                                            result = (struct Struct_1_t *)v_28;
                                            v4 = v_38;
                                            result -= v4;
                                            if (v13 > result) {
                                                v_20 = 1;
                                                a1 = rsp + 40;
                                                sub_1400F2D20(a1, v4, v13, 1);
                                                v4 = v_38;
                                            }
                                            i5 = (__int64 *)v_30;
                                            a1 = v4 + i5;
                                            sub_1400F27F0(a1, dst, v13);
                                            v4 += v13;
                                            v_38 = v4;
                                            if (i2 == 0) {
                                                i3 += 8;
                                                i2 = v_47;
                                                i = (__int64 *)v_50;
                                                if (v12 == 0) {
                                                    sub_14002EDF0(0, 12);
                                                    i3 = (__int64 *)result;
                                                    result = 0x2602484C748;
                                                    *i3 = result;
                                                    result = (struct Struct_1_t *)v_28;
                                                    arg_8 = 0;
                                                    a2 = (size_t *)v_38;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                    if (result <= 11) {
                                                        v_20 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400F2D20(a1, a2, 12, 1);
                                                        a2 = (size_t *)v_38;
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    a1 = (size_t *)arg_8;
                                                    *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                                                    a1 = *i3;
                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                    a2 += 12;
                                                    v_38 = (__int64)a2;
                                                    off_140108030(a1, a2);
                                                    off_140108038(result, 0, i3);
                                                    sub_14002EDF0(0, 12);
                                                    i3 = (__int64 *)result;
                                                    result = 0x2682484C748;
                                                    *i3 = result;
                                                    result = (struct Struct_1_t *)v_28;
                                                    arg_8 = 0;
                                                    a2 = (size_t *)v_38;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                    if (result <= 11) {
                                                        v_20 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400F2D20(a1, a2, 12, 1);
                                                        a2 = (size_t *)v_38;
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    a1 = (size_t *)arg_8;
                                                    *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                                                    a1 = *i3;
                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                    a2 += 12;
                                                    v_38 = (__int64)a2;
                                                    off_140108030(a1, a2);
                                                    off_140108038(result, 0, i3);
                                                    sub_14002EDF0(0, 10);
                                                    if (result != 0) {
                                                        i3 = (__int64 *)result;
                                                        *(__int64 *)result = (__int64)(0xB848);
                                                        result->field_2 = -1;
                                                        v4 = v_28;
                                                        i5 = (__int64 *)v_38;
                                                        result = (struct Struct_1_t *)v4;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                        if (result <= 9) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, i5, 10, 1);
                                                            v4 = v_28;
                                                            i5 = (__int64 *)v_38;
                                                        }
                                                        dst = (__int64 *)v_30;
                                                        result = (struct Struct_1_t *)arg_8;
                                                        *(__int64 *)((__int64)dst + (__int64)i5 + 8) = result;
                                                        result = *i3;
                                                        *(__int64 *)((__int64)dst + (__int64)i5) = result;
                                                        i5 += 10;
                                                        v_38 = (__int64)i5;
                                                        off_140108030();
                                                        off_140108038(result, 0, i3);
                                                        v4 -= (__int64)i5;
                                                        if (v4 <= 3) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, i5, 4, 1);
                                                            dst = (__int64 *)v_30;
                                                            i5 = (__int64 *)v_38;
                                                        }
                                                        *(__int64 *)((__int64)dst + (__int64)i5) = 0x24848948;
                                                        i5 += 4;
                                                        v_38 = (__int64)i5;
                                                        result = (struct Struct_1_t *)v_28;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, i5, 4, 1);
                                                            i5 = (__int64 *)v_38;
                                                        }
                                                        result = (struct Struct_1_t *)v_30;
                                                        *(__int64 *)((__int64)result + (__int64)i5) = 880;
                                                        i5 += 4;
                                                        v_38 = (__int64)i5;
                                                        result = (struct Struct_1_t *)v_28;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, i5, 4, 1);
                                                            i5 = (__int64 *)v_38;
                                                        }
                                                        result = (struct Struct_1_t *)v_30;
                                                        *(__int64 *)((__int64)result + (__int64)i5) = 0x2484C748;
                                                        i5 += 4;
                                                        v_38 = (__int64)i5;
                                                        result = (struct Struct_1_t *)v_28;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, i5, 4, 1);
                                                            i5 = (__int64 *)v_38;
                                                        }
                                                        result = (struct Struct_1_t *)v_30;
                                                        *(__int64 *)((__int64)result + (__int64)i5) = 0x488;
                                                        i5 += 4;
                                                        v_38 = (__int64)i5;
                                                        result = (struct Struct_1_t *)v_28;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, i5, 4, 1);
                                                            i5 = (__int64 *)v_38;
                                                        }
                                                        result = (struct Struct_1_t *)v_30;
                                                        *(__int64 *)((__int64)result + (__int64)i5) = 0;
                                                        result = i5 + 4;
                                                        v_38 = (__int64)result;
                                                        if (result != v_28) {
                                                            result = (struct Struct_1_t *)v_30;
                                                            *(__int64 *)((__int64)result + (__int64)i5 + 4) = 72;
                                                            result = i5 + 5;
                                                            v_38 = (__int64)result;
                                                            if (result != v_28) {
                                                                result = (struct Struct_1_t *)v_30;
                                                                *(__int64 *)((__int64)result + (__int64)i5 + 5) = 49;
                                                                result = i5 + 6;
                                                                v_38 = (__int64)result;
                                                                if (result != v_28) {
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)((__int64)result + (__int64)i5 + 6) = 192;
                                                                    i5 += 7;
                                                                    v_38 = (__int64)i5;
                                                                    v4 = 904;
                                                                    i3 = rsp + 40;
                                                                    do {
                                                                        result = (struct Struct_1_t *)v_28;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(i3, i5, 4, 1);
                                                                        i5 = (__int64 *)v_38;
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        *(__int64 *)((__int64)result + (__int64)i5) = 0x24848948;
                                                                        i5 += 4;
                                                                        v_38 = (__int64)i5;
                                                                        result = (struct Struct_1_t *)v_28;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                                        if (result <= 3) {
                                                                            v_20 = 1;
                                                                            sub_1400F2D20(i3, i5, 4, 1);
                                                                            i5 = (__int64 *)v_38;
                                                                        }
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        *(__int64 *)((__int64)result + (__int64)i5) = v4;
                                                                        i5 += 4;
                                                                        v_38 = (__int64)i5;
                                                                        v4 += 8;
                                                                    } while (v4 != 0x488);
                                                                    result = 332;
                                                                    i3 = 288;
                                                                    if (i2 != 0) i3 = result;
                                                                    if (v_28 == i5) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, i5, 1, 1);
                                                                        i5 = (__int64 *)v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)((__int64)result + (__int64)i5) = 233;
                                                                    ++i5;
                                                                    v_38 = (__int64)i5;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                                    if (result <= 3) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, i5, 4, 1);
                                                                        i5 = (__int64 *)v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)((__int64)result + (__int64)i5) = i3;
                                                                    i5 += 4;
                                                                    v_38 = (__int64)i5;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)i5);
                                                                    v13 = (__int64)i5;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, i5, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xFFFF);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xAAAA);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0x5555);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0x505);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xF0F);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xF0F0);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xFAFA);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0x4411);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xCC33);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0x33CC);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0xBBEE);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    result -= v13;
                                                                    if (result <= 1) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v13, 2, 1);
                                                                        v13 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    *(__int64 *)(result + v13) = (__int64)(0);
                                                                    v13 += 2;
                                                                    v_38 = v13;
                                                                    a2 = i + 46;
                                                                    v4 = v_28;
                                                                    result = (struct Struct_1_t *)v4;
                                                                    result -= v13;
                                                                    i3 = (__int64 *)v13;
                                                                    if (result <= 255) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        i3 = (__int64 *)a2;
                                                                        sub_1400F2D20(a1, v13, 256, 1);
                                                                        a2 = (size_t *)i3;
                                                                        v4 = v_28;
                                                                        i3 = (__int64 *)v_38;
                                                                    }
                                                                    dst = (__int64 *)v_30;
                                                                    a1 = (__int64)dst + (__int64)i3;
                                                                    sub_1400F27F0(a1, a2, 256);
                                                                    i3 += 256;
                                                                    v_38 = (__int64)i3;
                                                                    v4 -= (__int64)i3;
                                                                    v12 = (__int64)i3;
                                                                    if (v4 <= 7) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, i3, 8, 1);
                                                                        dst = (__int64 *)v_30;
                                                                        v12 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)arg_12e;
                                                                    *(dst + v12) = result;
                                                                    v12 += 8;
                                                                    v_38 = v12;
                                                                    if (i2 == 0) {
                                                                        xmm0 = _mm_load_si128((__m128i *)&off_140108AA0);
                                                                        _mm_storeu_si128((__m128i *)&v_d0, xmm0);
                                                                        xmm0 = _mm_load_si128((__m128i *)&off_140108AB0);
                                                                        _mm_storeu_si128((__m128i *)&v_e0, xmm0);
                                                                        result = 0x49000000488;
                                                                        v_f0 = (__int64)result;
                                                                        v_b8 = (__int64)i5;
                                                                        v_c0 = v13;
                                                                        v_c8 = (__int64)i3;
                                                                        a1 = (size_t *)v_28;
                                                                        result = (struct Struct_1_t *)a1;
                                                                        result -= v12;
                                                                        v4 = v12;
                                                                        if (result <= 4) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, v12, 5, 1);
                                                                            a1 = (size_t *)v_28;
                                                                            v4 = v_38;
                                                                        }
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        *(__int64 *)(result + v4 + 4) = (__int64)(55);
                                                                        *(__int64 *)(result + v4) = (__int64)(0x4B60F43);
                                                                        v4 += 5;
                                                                        v_38 = v4;
                                                                        a2 = a1;
                                                                        a2 -= v4;
                                                                        if (a2 <= 2) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, v4, 3, 1);
                                                                            v4 = v_38;
                                                                            a1 = (size_t *)v_28;
                                                                            result = (struct Struct_1_t *)v_30;
                                                                        }
                                                                        *(__int64 *)(result + v4 + 2) = (__int64)(198);
                                                                        *(__int64 *)(result + v4) = (__int64)(0xFF49);
                                                                        i3 = v4 + 3;
                                                                        v_38 = (__int64)i3;
                                                                        a1 = (size_t *)((__int64)a1 - (__int64)i3);
                                                                        if (a1 <= 2) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, i3, 3, 1);
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            i3 = (__int64 *)v_38;
                                                                        }
                                                                        *(__int64 *)((__int64)result + (__int64)i3 + 2) = 53;
                                                                        *(__int64 *)((__int64)result + (__int64)i3) = 0x8D48;
                                                                        i3 += 3;
                                                                        v_38 = (__int64)i3;
                                                                        v4 += 10;
                                                                        if ((v4 < 0)) {
                                                                            result = &off_14011B3E0;
                                                                            v_20 = (__int64)result;
                                                                            a1 = &off_14011B3C3;
                                                                            i6 = &off_14011D3F8;
                                                                            i4 = rsp + 70;
                                                                            sub_1400F3B80(a1, 23, i4, i6);
                                                                            i6 = &off_14011D0E0;
                                                                            sub_1400F3600(a1, a2, i4, i6);
                                                                        }
                                                                        v13 -= v4;
                                                                        a1 = (size_t *)v13;
                                                                        if (v13 == v13) {
                                                                            a1 = (size_t *)v_28;
                                                                            a1 = (size_t *)((__int64)a1 - (__int64)i3);
                                                                            if (a1 <= 3) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, i3, 4, 1);
                                                                                result = (struct Struct_1_t *)v_30;
                                                                                i3 = (__int64 *)v_38;
                                                                            }
                                                                            *(__int64 *)((__int64)result + (__int64)i3) = v13;
                                                                            i3 += 4;
                                                                            v_38 = (__int64)i3;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i3);
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, i3, 4, 1);
                                                                                i3 = (__int64 *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)i3) = 0x604B60F;
                                                                            i3 += 4;
                                                                            v_38 = (__int64)i3;
                                                                            v_60 = 0;
                                                                            v_68 = 8;
                                                                            v_70 = 0;
                                                                            v_88 = 0;
                                                                            v_90 = 8;
                                                                            v_98 = 0;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i3);
                                                                            if (result <= 1) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, i3, 2, 1);
                                                                                i3 = (__int64 *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)i3) = 60;
                                                                            i3 += 2;
                                                                            v_38 = (__int64)i3;
                                                                            a1 = rsp + 96;
                                                                            sub_1400FAE80(a1, a2, i4, v12);
                                                                            result = (struct Struct_1_t *)v_68;
                                                                            *(__int64 *)result = (__int64)(i3);
                                                                            v_70 = 1;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            a2 = (size_t *)v_38;
                                                                            a1 = (size_t *)result;
                                                                            a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                            if (a1 <= 5) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, a2, 6, 1);
                                                                                result = (struct Struct_1_t *)v_28;
                                                                                a2 = (size_t *)v_38;
                                                                            }
                                                                            a1 = (size_t *)v_30;
                                                                            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x840F;
                                                                            a2 += 6;
                                                                            v_38 = (__int64)a2;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                            if (result <= 1) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, a2, 2, 1);
                                                                                a1 = (size_t *)v_30;
                                                                                a2 = (size_t *)v_38;
                                                                            }
                                                                            *(__int64 *)((__int64)a1 + (__int64)a2) = 316;
                                                                            a2 += 2;
                                                                            v_38 = (__int64)a2;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                            if (result <= 1) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, a2, 2, 1);
                                                                                a2 = (size_t *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xD75;
                                                                            a2 += 2;
                                                                            v_38 = (__int64)a2;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, a2, 4, 1);
                                                                                a2 = (size_t *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x2484FF48;
                                                                            a2 += 4;
                                                                            v_38 = (__int64)a2;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, a2, 4, 1);
                                                                                a2 = (size_t *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x488;
                                                                            i2 = a2 + 4;
                                                                            v_38 = i2;
                                                                            a2 += 9;
                                                                            if ((a2 < 0)) {
                                                                                return (__int64)a2;
                                                                            }
                                                                            i3 = (__int64 *)v12;
                                                                            i3 = (__int64 *)((__int64)i3 - (__int64)a2);
                                                                            if (v_28 == i2) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, i2, 1, 1);
                                                                                i2 = v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)(result + i2) = (__int64)(233);
                                                                            ++i2;
                                                                            v_38 = i2;
                                                                            result = (struct Struct_1_t *)i3;
                                                                            if (i3 == i3) {
                                                                                result = (struct Struct_1_t *)v_28;
                                                                                result -= i2;
                                                                                v_48 = v12;
                                                                                if (result <= 3) {
                                                                                    v_20 = 1;
                                                                                    a1 = rsp + 40;
                                                                                    sub_1400F2D20(a1, i2, 4, 1);
                                                                                    i2 = v_38;
                                                                                }
                                                                                result = (struct Struct_1_t *)v_30;
                                                                                *(__int64 *)(result + i2) = (__int64)(i3);
                                                                                i2 += 4;
                                                                                v_38 = i2;
                                                                                i3 = 8;
                                                                                i = 0;
                                                                                v13 = &off_14011D060;
                                                                                v12 = rsp + 40;
                                                                                v4 = rsp + 136;
                                                                                i5 = 8;
                                                                                do {
                                                                                    dst = *(i + v13);
                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                    result -= i2;
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(v12, i2, 2, 1);
                                                                                    i2 = v_38;
                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                    a1 = (size_t *)dst;
                                                                                    a1 = (size_t *)((__int64)(__int64)a1 << 8);
                                                                                    a1 = (size_t *)((__int64)(__int64)a1 | 60);
                                                                                    *(__int64 *)(result + i2) = (__int64)(a1);
                                                                                    i2 += 2;
                                                                                    v_38 = i2;
                                                                                    if (i == v_88) {
                                                                                        sub_1400FAEF0(v4, a2);
                                                                                        i5 = (__int64 *)v_90;
                                                                                    }
                                                                                    *(__int64 *)((__int64)i5 + (__int64)i3 - 8) = i2;
                                                                                    *(__int64 *)((__int64)i5 + (__int64)i3) = i;
                                                                                    ++i;
                                                                                    v_98 = (__int64)i;
                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                    dst = (__int64 *)v_38;
                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                    if (result <= 5) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(v12, dst, 6, 1);
                                                                                        dst = (__int64 *)v_38;
                                                                                    }
                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 4) = 0;
                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x840F;
                                                                                    i2 = dst + 6;
                                                                                    v_38 = i2;
                                                                                    i3 += 16;
                                                                                } while (i != 75);
                                                                                a1 = (size_t *)v_28;
                                                                                a1 -= i2;
                                                                                if (a1 <= 4) {
                                                                                    v_20 = 1;
                                                                                    a1 = rsp + 40;
                                                                                    sub_1400F2D20(a1, i2, 5, 1);
                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                    i2 = v_38;
                                                                                }
                                                                                *(__int64 *)(result + i2 + 4) = (__int64)(0);
                                                                                *(__int64 *)(result + i2) = (__int64)(233);
                                                                                i2 += 5;
                                                                                v_38 = i2;
                                                                                sub_14002EDF0(8, 600);
                                                                                v_50 = (__int64)result;
                                                                                if (result != 0) {
                                                                                    i = (__int64 *)v_70;
                                                                                    i3 = 0;
                                                                                    do {
                                                                                        result = &off_14011D060;
                                                                                        i4 = *(__int64 *)((__int64)i3 + (__int64)result);
                                                                                        result = (struct Struct_1_t *)v_50;
                                                                                        ((__int64 *)result)[(__int64)i3] = (__int64)(i2);
                                                                                        a1 = rsp + 160;
                                                                                        a2 = rsp + 40;
                                                                                        i6 = rsp + 184;
                                                                                        sub_1400E03D0(a1, a2, i4, i6);
                                                                                        v4 = v_a0;
                                                                                        i2 = v_a8;
                                                                                        v13 = v_b0;
                                                                                        result = (struct Struct_1_t *)v_60;
                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                                        v_20 = 8;
                                                                                        a1 = rsp + 96;
                                                                                        sub_1400F2D20(a1, i, v13, 8);
                                                                                        v12 = v_70;
                                                                                        i4 =  + v13*8;
                                                                                        i5 = (__int64 *)v_68;
                                                                                        a1 =  + v12*8;
                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)i5);
                                                                                        v_78 = i4;
                                                                                        sub_1400F27F0(a1, i2, i4);
                                                                                        v13 += v12;
                                                                                        v_70 = v13;
                                                                                        if (v4 == 0) {
                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                            i = (__int64 *)v_38;
                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                                            if (result <= 3) {
                                                                                                v_20 = 1;
                                                                                                a1 = rsp + 40;
                                                                                                sub_1400F2D20(a1, i, 4, 1);
                                                                                                i = (__int64 *)v_38;
                                                                                            }
                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                            *(__int64 *)((__int64)result + (__int64)i) = 0x2484FF48;
                                                                                            i += 4;
                                                                                            v_38 = (__int64)i;
                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                                            if (result <= 3) {
                                                                                                v_20 = 1;
                                                                                                a1 = rsp + 40;
                                                                                                sub_1400F2D20(a1, i, 4, 1);
                                                                                                i = (__int64 *)v_38;
                                                                                            }
                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                            *(__int64 *)((__int64)result + (__int64)i) = 0x488;
                                                                                            i2 = i + 4;
                                                                                            v_38 = i2;
                                                                                            i += 9;
                                                                                            if ((i < 0)) {
                                                                                                return (__int64)i;
                                                                                            }
                                                                                            if (v_28 == i2) {
                                                                                                v_20 = 1;
                                                                                                a1 = rsp + 40;
                                                                                                sub_1400F2D20(a1, i2, 1, 1);
                                                                                                i2 = v_38;
                                                                                            }
                                                                                            v4 = v_48;
                                                                                            v4 -= (__int64)i;
                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                            *(__int64 *)(result + i2) = (__int64)(233);
                                                                                            ++i2;
                                                                                            v_38 = i2;
                                                                                            result = (struct Struct_1_t *)v4;
                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                            result -= i2;
                                                                                            if (result <= 3) {
                                                                                                v_20 = 1;
                                                                                                a1 = rsp + 40;
                                                                                                sub_1400F2D20(a1, i2, 4, 1);
                                                                                                i2 = v_38;
                                                                                            }
                                                                                            ++i3;
                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                            *(__int64 *)(result + i2) = (__int64)(v4);
                                                                                            i2 += 4;
                                                                                            v_38 = i2;
                                                                                            i = (__int64 *)v13;
                                                                                            sub_14002EDF0(0, 8);
                                                                                            if (result != 0) {
                                                                                                i3 = (__int64 *)result;
                                                                                                *(__int64 *)result = (__int64)(0x24448B48);
                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                a2 = (size_t *)v_38;
                                                                                                arg_4 = 32;
                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                if (result <= 4) {
                                                                                                    v_20 = 1;
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F2D20(a1, a2, 5, 1);
                                                                                                    a2 = (size_t *)v_38;
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                a1 = (size_t *)arg_4;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                a1 = *i3;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                a2 += 5;
                                                                                                v_38 = (__int64)a2;
                                                                                                off_140108030(a1, a2);
                                                                                                off_140108038(result, 0, i3);
                                                                                                sub_14002EDF0(0, 7);
                                                                                                i3 = (__int64 *)result;
                                                                                                *(__int64 *)result = (__int64)(0x8148);
                                                                                                result->field_3 = 0x490;
                                                                                                result->field_2 = 196;
                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                a2 = (size_t *)v_38;
                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                if (result <= 6) {
                                                                                                    v_20 = 1;
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F2D20(a1, a2, 7, 1);
                                                                                                    a2 = (size_t *)v_38;
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                a1 = *i3;
                                                                                                i4 = arg_3;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 3) = i4;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                a2 += 7;
                                                                                                v_38 = (__int64)a2;
                                                                                                off_140108030(a1, a2, i4);
                                                                                                off_140108038(result, 0, i3);
                                                                                                i = (__int64 *)v_38;
                                                                                                if (i == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i) = 65;
                                                                                                result = i + 1;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 1) = 95;
                                                                                                result = i + 2;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 2) = 65;
                                                                                                result = i + 3;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 3) = 94;
                                                                                                result = i + 4;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 4) = 65;
                                                                                                result = i + 5;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 5) = 93;
                                                                                                result = i + 6;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 6) = 65;
                                                                                                result = i + 7;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 7) = 92;
                                                                                                result = i + 8;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 8) = 95;
                                                                                                result = i + 9;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 9) = 94;
                                                                                                result = i + 10;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 10) = 93;
                                                                                                result = i + 11;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 11) = 91;
                                                                                                result = i + 12;
                                                                                                v_38 = (__int64)result;
                                                                                                if (result == v_28) {
                                                                                                    a1 = rsp + 40;
                                                                                                    sub_1400F3510(a1);
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                *(__int64 *)((__int64)result + (__int64)i + 12) = 195;
                                                                                                i += 13;
                                                                                                v_38 = (__int64)i;
                                                                                                if (v_47 != 0) {
                                                                                                    a1 = rsp + 160;
                                                                                                    sub_140101C10(a1);
                                                                                                    a2 = (size_t *)v_a8;
                                                                                                    v4 = v_b0;
                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                    i3 = (__int64 *)v_38;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)i3);
                                                                                                    v_48 = (int)a2;
                                                                                                }
                                                                                                result = (struct Struct_1_t *)v_38;
                                                                                                i = (__int64 *)v_58;
                                                                                                arg_10 = (__int64)result;
                                                                                                xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                                _mm_storeu_si128((__m128i *)i, xmm0);
                                                                                                result = (struct Struct_1_t *)v_60;
                                                                                                if (result == 0) {
                                                                                                    result = (struct Struct_1_t *)v_88;
                                                                                                    i3 = (__int64 *)v_90;
                                                                                                    i6 = (__int64 *)arg_8;
                                                                                                    i4 = arg_10;
                                                                                                    v7 = 8;
                                                                                                    a1 = *(i3 + v7);
                                                                                                    while (a1 < 75) {
                                                                                                        a2 = (size_t *)v_50;
                                                                                                        v8 = v_0[(__int64)a1];
                                                                                                        if (v8 < 0) {
                                                                                                            return v8;
                                                                                                        }
                                                                                                        a1 = *(i3 + v7 - 8);
                                                                                                        a2 = a1;
                                                                                                        a2 += 6;
                                                                                                        if ((a2 < 0)) {
                                                                                                            return (__int64)a2;
                                                                                                        }
                                                                                                        v8 -= (__int64)a2;
                                                                                                        v4 = v8;
                                                                                                        if (v8 == v8) {
                                                                                                            a1 += 2;
                                                                                                            if (a2 < a1) {
                                                                                                                i6 = &off_14011D198;
                                                                                                                sub_1400F3600(i6, a2, i4, i6);
                                                                                                            }
                                                                                                            if (a2 > i4) {
                                                                                                                return (__int64)i6;
                                                                                                            }
                                                                                                            *(__int64 *)((__int64)i6 + (__int64)a1) = v8;
                                                                                                            v7 += 16;
                                                                                                            if (result == 0) {
                                                                                                                a2 = (size_t *)dst;
                                                                                                                a2 += 11;
                                                                                                                if ((a2 < 0)) {
                                                                                                                    return (__int64)a2;
                                                                                                                }
                                                                                                                i2 -= (__int64)a2;
                                                                                                                result = (struct Struct_1_t *)i2;
                                                                                                                if (i2 == i2) {
                                                                                                                    i4 = arg_10;
                                                                                                                    if (a2 > i4) {
                                                                                                                        dst += 7;
                                                                                                                        i6 = &off_14011D130;
                                                                                                                        sub_1400F3600(dst, a2, i4, i6);
                                                                                                                        v_20 = 1;
                                                                                                                        a1 = rsp + 40;
                                                                                                                        sub_1400F2D20(a1, v4, 3, 1);
                                                                                                                        v4 = v_38;
                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                        a1 = (size_t *)arg_2;
                                                                                                                        *(__int64 *)(result + v4 + 2) = (__int64)(a1);
                                                                                                                        a1 = *i3;
                                                                                                                        *(__int64 *)(result + v4) = (__int64)(a1);
                                                                                                                        v4 += 3;
                                                                                                                        v_38 = v4;
                                                                                                                        off_140108030(a1);
                                                                                                                        off_140108038(result, 0, i3);
                                                                                                                    }
                                                                                                                    result = (struct Struct_1_t *)arg_8;
                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 7) = i2;
                                                                                                                    off_140108030(a1, a2, i4);
                                                                                                                    i4 = v_50;
                                                                                                                    off_140108038(result, 0, i4);
                                                                                                                    return i4;
                                                                                                                }
                                                                                                                result = &off_14011D118;
                                                                                                                v_20 = (__int64)result;
                                                                                                                a1 = &off_14011D0F8;
                                                                                                                i6 = &off_14011D3F8;
                                                                                                                i4 = rsp + 70;
                                                                                                                sub_1400F3B80(a1, 27, i4, i6);
                                                                                                                result = &off_14011D0C8;
                                                                                                                v_20 = (__int64)result;
                                                                                                                a1 = &off_14011D0AB;
                                                                                                                i6 = &off_14011D3F8;
                                                                                                                i4 = rsp + 70;
                                                                                                                sub_1400F3B80(a1, 27, i4, i6);
                                                                                                                dst = a1[3];
                                                                                                                result = (struct Struct_1_t *)dst;
                                                                                                                ++result;
                                                                                                                if ((result == 0)) JUMPOUT(0x140106e6e);
                                                                                                                i3 = (__int64 *)a1;
                                                                                                                a2 = (size_t *)arg_8;
                                                                                                                v_20 = (__int64)a2;
                                                                                                                i5 = a2 + 1;
                                                                                                                a1 = (size_t *)i5;
                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 3);
                                                                                                                i2 = (__int64)i5;
                                                                                                                i2 &= -8;
                                                                                                                i2 -= (__int64)a1;
                                                                                                                i4 = i2;
                                                                                                                if (a2 < 8) i2 = a2;
                                                                                                                a1 = (size_t *)i2;
                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 1);
                                                                                                                if (result <= a1) JUMPOUT(0x140106b55);
                                                                                                                ++i4;
                                                                                                                if (i4 <= result) i4 = result;
                                                                                                                a1 = rsp + 72;
                                                                                                                sub_1400F1570(a1, 48, i4);
                                                                                                                i = (__int64 *)v_48;
                                                                                                                v4 = v_50;
                                                                                                                if (i == 0) JUMPOUT(0x140106e5a);
                                                                                                                result = (struct Struct_1_t *)v_58;
                                                                                                                v_38 = (__int64)result;
                                                                                                                v_30 = (__int64)i3;
                                                                                                                i5 = *i3;
                                                                                                                v_28 = (__int64)dst;
                                                                                                                i6 = (__int64 *)v_20;
                                                                                                                if (dst == 0) JUMPOUT(0x140106b83);
                                                                                                                xmm0 = _mm_load_si128((__m128i *)i5);
                                                                                                                v12 = _mm_movemask_epi8(xmm0);
                                                                                                                v12 = ~v12;
                                                                                                                result = i5 - 48;
                                                                                                                v_40 = (__int64)result;
                                                                                                                i3 = 0;
                                                                                                                v13 = v_28;
                                                                                                                dst = i5;
                                                                                                                do {
                                                                                                                    i2 = __builtin_ctz(v12);
                                                                                                                    i2 += (__int64)i3;
                                                                                                                    result = (struct Struct_1_t *)i2;
                                                                                                                    result = (struct Struct_1_t *)(-(__int64)result);
                                                                                                                    a1 = result + (__int64)(__int64)result*2;
                                                                                                                    a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                                                    a1 += v_40;
                                                                                                                    sub_1400F16D0(a1, a2, i4, i6);
                                                                                                                    a1 = (size_t *)result;
                                                                                                                    a1 = (size_t *)((__int64)(__int64)a1 & v4);
                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)i + (__int64)a1));
                                                                                                                    a2 = _mm_movemask_epi8(xmm0);
                                                                                                                    if (a2 == 0) JUMPOUT(0x140106b19);
                                                                                                                    i6 = (__int64 *)v_20;
                                                                                                                    a2 = __builtin_ctz(a2);
                                                                                                                    a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                                                                    a2 = (size_t *)((__int64)(__int64)a2 & v4);
                                                                                                                    if ((*(__int64 *)((__int64)i + (__int64)a2) - 0) >= 0) JUMPOUT(0x140106b42);
                                                                                                                    a1 = v12 - 1;
                                                                                                                    a1 = (size_t *)((__int64)(__int64)a1 & v12);
                                                                                                                    --v13;
                                                                                                                    result = (struct Struct_1_t *)((__int64)(__int64)result >> 57);
                                                                                                                    i4 = a2 - 16;
                                                                                                                    i4 &= v4;
                                                                                                                    *(__int64 *)((__int64)i + (__int64)a2) = result;
                                                                                                                    *(i + i4 + 16) = result;
                                                                                                                    i2 = ~i2;
                                                                                                                    result = i2 + i2*2;
                                                                                                                    result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                                                                                                                    a2 = (size_t *)(~(__int64)a2);
                                                                                                                    a2 += (__int64)(__int64)a2*2;
                                                                                                                    a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)i5 + (__int64)result));
                                                                                                                    xmm1 = _mm_loadu_si128((__m128i *)((__int64)i5 + (__int64)result + 16));
                                                                                                                    xmm2 = _mm_loadu_si128((__m128i *)((__int64)i5 + (__int64)result + 32));
                                                                                                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 + 32), xmm2);
                                                                                                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 + 16), xmm1);
                                                                                                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2), xmm0);
                                                                                                                    v12 = (__int64)a1;
                                                                                                                } while (v13 != 0);
                                                                                                                return sub_140106B83();
                                                                                                            }
                                                                                                            off_140108030(a1, a2, i4, i6);
                                                                                                            off_140108038(result, 0, i3);
                                                                                                            return v12;
                                                                                                        }
                                                                                                        result = &off_14011D180;
                                                                                                        v_20 = (__int64)result;
                                                                                                        a1 = &off_14011D160;
                                                                                                        i6 = &off_14011D3F8;
                                                                                                        i4 = rsp + 70;
                                                                                                        sub_1400F3B80(a1, 26, i4, i6);
                                                                                                        result = &off_14011D1C8;
                                                                                                        v_20 = (__int64)result;
                                                                                                        a1 = &off_14011D1B0;
                                                                                                        i6 = &off_14011D3F8;
                                                                                                        i4 = rsp + 70;
                                                                                                        sub_1400F3B80(a1, 18, i4, i6);
                                                                                                        sub_1400F3326(1, 10);
                                                                                                        result = &off_14011D020;
                                                                                                        v_20 = (__int64)result;
                                                                                                        a1 = &off_14011D010;
                                                                                                        i6 = &off_14011D3F8;
                                                                                                        i4 = rsp + 70;
                                                                                                        sub_1400F3B80(a1, 15, i4, i6);
                                                                                                        sub_1400F3326(1, 11);
                                                                                                        result = &off_14011CFC8;
                                                                                                        v_20 = (__int64)result;
                                                                                                        a1 = &off_14011CFB0;
                                                                                                        i6 = &off_14011D3F8;
                                                                                                        i4 = rsp + 70;
                                                                                                        sub_1400F3B80(a1, 17, i4, i6);
                                                                                                        result = &off_14011CFF8;
                                                                                                        v_20 = (__int64)result;
                                                                                                        a1 = &off_14011CFE0;
                                                                                                        i6 = &off_14011D3F8;
                                                                                                        i4 = rsp + 70;
                                                                                                        sub_1400F3B80(a1, 19, i4, i6);
                                                                                                        result = &off_14011D048;
                                                                                                        v_20 = (__int64)result;
                                                                                                        a1 = &off_14011D038;
                                                                                                        i6 = &off_14011D3F8;
                                                                                                        i4 = rsp + 70;
                                                                                                        sub_1400F3B80(a1, 10, i4, i6);
                                                                                                        sub_1400F3326(8, 600);
                                                                                                        sub_1400F3326(1, 8);
                                                                                                        return i4;
                                                                                                    }
                                                                                                    i4 = &off_14011D148;
                                                                                                    sub_1400F3869(a1, 75, i4);
                                                                                                    return i4;
                                                                                                }
                                                                                                off_140108030(a1, a2, i4, i6);
                                                                                                off_140108038(result, 0, i5);
                                                                                                return i4;
                                                                                            }
                                                                                            return i4;
                                                                                        }
                                                                                        off_140108030();
                                                                                        off_140108038(result, 0, i2);
                                                                                        return i4;
                                                                                    } while (i3 != 75);
                                                                                    return i4;
                                                                                }
                                                                                return i4;
                                                                            }
                                                                            return i4;
                                                                        }
                                                                        return i4;
                                                                    }
                                                                    dst = i + 1;
                                                                    a1 = (size_t *)v_28;
                                                                    result = (struct Struct_1_t *)a1;
                                                                    result -= v12;
                                                                    v4 = v12;
                                                                    if (result <= 31) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v12, 32, 1);
                                                                        a1 = (size_t *)v_28;
                                                                        v4 = v_38;
                                                                    }
                                                                    i += 33;
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)dst);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(dst + 16));
                                                                    _mm_storeu_si128((__m128i *)(result + v4 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)(result + v4), xmm0);
                                                                    v4 += 32;
                                                                    v_38 = v4;
                                                                    a1 -= v4;
                                                                    i4 = v4;
                                                                    if (a1 <= 11) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v4, 12, 1);
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        i4 = v_38;
                                                                    }
                                                                    a1 = (size_t *)arg_8;
                                                                    *(__int64 *)(result + i4 + 8) = (__int64)(a1);
                                                                    a1 = *i;
                                                                    *(__int64 *)(result + i4) = (__int64)(a1);
                                                                    i4 += 12;
                                                                    v_38 = i4;
                                                                    a1 = (size_t *)v_48;
                                                                    a2 = a1;
                                                                    a2 += 7;
                                                                    if ((a2 < 0)) {
                                                                        return (__int64)a2;
                                                                    }
                                                                    v12 -= (__int64)a2;
                                                                    v7 = v_78;
                                                                    if (v12 == v12) {
                                                                        a1 += 3;
                                                                        if (a1 > -5) {
                                                                            i6 = &off_14011D380;
                                                                            sub_1400F3600(a1, a2, i4, i6);
                                                                            return (__int64)i6;
                                                                        }
                                                                        if (a2 > i4) {
                                                                            return (__int64)i6;
                                                                        }
                                                                        *(__int64 *)((__int64)result + (__int64)a1) = v12;
                                                                        a2 = (size_t *)v7;
                                                                        a2 += 7;
                                                                        if ((a2 < 0)) {
                                                                            return (__int64)a2;
                                                                        }
                                                                        v4 -= (__int64)a2;
                                                                        result = (struct Struct_1_t *)v4;
                                                                        if (v4 == v4) {
                                                                            v7 += 3;
                                                                            i4 = v_38;
                                                                            if (v7 > -5) {
                                                                                i6 = &off_14011D380;
                                                                                sub_1400F3600(v7, a2, i4, i6);
                                                                                return (__int64)i6;
                                                                            }
                                                                            if (a2 > i4) {
                                                                                return (__int64)i6;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            *(__int64 *)(result + v7) = (__int64)(v4);
                                                                            v12 = v_38;
                                                                            return v12;
                                                                        }
                                                                        return v12;
                                                                    }
                                                                    return v12;
                                                                }
                                                                a1 = rsp + 40;
                                                                sub_1400F3510(a1);
                                                                return (__int64)a1;
                                                            }
                                                            a1 = rsp + 40;
                                                            sub_1400F3510(a1);
                                                            return (__int64)a1;
                                                        }
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                        return (__int64)a1;
                                                    }
                                                    return (__int64)a1;
                                                }
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result < 4) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 4, 1);
                                                    i5 = (__int64 *)v_30;
                                                    v4 = v_38;
                                                }
                                                *(i5 + v4) = 0x458B48;
                                                v4 += 4;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 5, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x24448948);
                                                *(__int64 *)(result + v4 + 4) = (__int64)(32);
                                                v4 += 5;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 4, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x8458B48);
                                                v4 += 4;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 5, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x24448948);
                                                *(__int64 *)(result + v4 + 4) = (__int64)(40);
                                                v4 += 5;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 4, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x10458B48);
                                                v4 += 4;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 5, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x24448948);
                                                *(__int64 *)(result + v4 + 4) = (__int64)(48);
                                                v4 += 5;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 4, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x18458B48);
                                                v4 += 4;
                                                v_38 = v4;
                                                result = (struct Struct_1_t *)v_28;
                                                result -= v4;
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, v4, 5, 1);
                                                    v4 = v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)(result + v4) = (__int64)(0x24448948);
                                                *(__int64 *)(result + v4 + 4) = (__int64)(56);
                                                v4 += 5;
                                                v_38 = v4;
                                                return v_38;
                                            }
                                            off_140108030();
                                            off_140108038(result, 0, dst);
                                            return v_38;
                                        } while (i3 != 96);
                                        return v_38;
                                    }
                                    a1 = rsp + 40;
                                    sub_1400F3510(a1);
                                    return (__int64)a1;
                                }
                                a1 = rsp + 40;
                                sub_1400F3510(a1);
                                return (__int64)a1;
                            }
                            a1 = rsp + 40;
                            sub_1400F3510(a1);
                            return (__int64)a1;
                        }
                        a1 = rsp + 40;
                        sub_1400F3510(a1);
                        return (__int64)a1;
                    }
                    a1 = rsp + 40;
                    sub_1400F3510(a1);
                    return (__int64)a1;
                }
                a1 = rsp + 40;
                sub_1400F3510(a1);
                return (__int64)a1;
            } while (true);
        }
        sub_14002EDF0(0, 3);
        i3 = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x894C);
        result->field_2 = 205;
        result = (struct Struct_1_t *)v_28;
        v4 = v_38;
        result -= v4;
        if (result <= 2) {
            return (__int64)result;
        }
        return (__int64)result;
    }
    do {
        sub_1400F3326(1, 7);
        do {
            result = &off_14011D208;
            v_20 = (__int64)result;
            a1 = &off_14011D1F8;
            i6 = &off_14011D3F8;
            i4 = rsp + 70;
            sub_1400F3B80(a1, 14, i4, i6);
            do {
                v_20 = 1;
                a1 = rsp + 40;
                sub_1400F2D20(a1, i3, v4, 1);
                a2 = (size_t *)v_48;
                i3 = (__int64 *)v_38;
                do {
                    a1 = (size_t *)v_30;
                    a1 = (size_t *)((__int64)a1 + (__int64)i3);
                    sub_1400F27F0(a1, a2, v4);
                    i3 += v4;
                    result = (struct Struct_1_t *)i3;
                    a1 = (size_t *)v_58;
                    a1[2] = result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                    _mm_storeu_si128((__m128i *)a1, xmm0);
                    i6 = (__int64 *)v_80;
                    a2 = (size_t *)i6;
                    a2 += 5;
                    if ((a2 < 0)) {
                        return (__int64)a2;
                    }
                    i = (__int64 *)((__int64)i - (__int64)a2);
                    result = (struct Struct_1_t *)i;
                    if (i == i) {
                        ++i6;
                        result = (struct Struct_1_t *)v_58;
                        i4 = result->field_10;
                        if (a2 < i6) {
                            return i4;
                        }
                        if (a2 > i4) {
                            return i4;
                        }
                        a2 = (size_t *)v_58;
                        result = (struct Struct_1_t *)arg_8;
                        *(__int64 *)((__int64)result + (__int64)a1) = i;
                        i = (__int64 *)a2;
                        result = (struct Struct_1_t *)v_60;
                        if (v13 != 0) {
                            do {
                                i6 = (__int64 *)arg_8;
                                i4 = arg_10;
                                a1 = (size_t *)v_78;
                                v7 = a1 + v12*8;
                                v8 = 0;
                                a1 = *(i5 + v8);
                                a2 = a1;
                                a2 += 6;
                                while (!((a2 < 0))) {
                                    i3 = (__int64 *)i2;
                                    i3 = (__int64 *)((__int64)i3 - (__int64)a2);
                                    v4 = (__int64)i3;
                                    if (i3 == i3) {
                                        a1 += 2;
                                        if (a2 < a1) {
                                            do {
                                                i6 = &off_14011D1E0;
                                                sub_1400F3600(a1, a2, i4, i6);
                                                do {
                                                    sub_1400F3340(1, 3);
                                                    do {
                                                        sub_1400F3326(1, 12);
                                                        return (__int64)i6;
                                                    } while (result == 0);
                                                } while (result == 0);
                                            } while (true);
                                        }
                                        if (a2 > i4) {
                                            return (__int64)i6;
                                        }
                                        *(__int64 *)((__int64)i6 + (__int64)a1) = i3;
                                        v8 += 8;
                                        return v8;
                                    }
                                    return v8;
                                }
                                return v8;
                            } while (v13 != 0);
                        }
                        return v8;
                    }
                    return v8;
                } while (v4 <= result);
                return (__int64)result;
            } while (v4 > result);
        } while (v4 != v4);
    } while (result == 0);
}