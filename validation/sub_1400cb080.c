// inferred from 2 accesses on `a4`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 6 accesses on `i`
struct Struct_2_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    char field_3; // offset 3
    __int16 field_4; // offset 4
    char _pad_4[1];
    char field_7; // offset 7
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 6 accesses on `ptr2`
struct Struct_4_t {
    char field_0; // offset 0
    char field_1; // offset 1
    char field_2; // offset 2
    int field_3; // offset 3
    char _pad_3[1];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_1400D34C0();
__int64 sub_1400D3870();
__int64 sub_1400DA470();
__int64 sub_1400D6830();
__int64 sub_1400F3510();
__int64 sub_1400D5BD0();
__int64 sub_1400F3600();
__int64 sub_1400D4F50();
__int64 sub_1400D5190();
__int64 sub_1400D5320();
__int64 sub_1400F3B80();
__int64 sub_1400D0B34();
__int64 sub_1400F3326();
__int64 sub_1400D9BD0();
__int64 sub_1400F3340();
__int64 sub_1400D9E70();
__int64 sub_1400DA120();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;
extern __int64 off_14011D2B0;
extern __int64 off_14011D238;
extern __int64 off_14011BC90;
extern __int64 off_14011D3F8;
extern __int64 off_14011CB30;
extern __int64 off_14011CB18;
extern __int64 off_14011CB60;
extern __int64 off_14011CB48;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011B718;
extern __int64 off_14011B700;
extern __int64 off_14011C768;
extern __int64 off_14011C758;
extern __int64 off_14011C790;
extern __int64 off_14011C780;
extern __int64 off_14011C7B8;
extern __int64 off_14011C7A8;
extern __int64 off_14011C7E0;
extern __int64 off_14011C7D0;
extern __int64 off_14011B8D8;
extern __int64 off_14011B8C8;
extern __int64 off_14011B900;
extern __int64 off_14011B8F0;
extern __int64 off_14011B928;
extern __int64 off_14011B918;
extern __int64 off_14011C488;
extern __int64 off_14011C470;
extern __int64 off_14011C4B0;
extern __int64 off_14011C4A0;
extern __int64 off_14011B6C0;
extern __int64 off_14011B6A8;
extern __int64 off_14011B6E8;
extern __int64 off_14011B6D8;
extern __int64 off_14011D220;
extern __int64 off_14011BC68;

__int64 __fastcall sub_1400CB080(size_t *a1, size_t *a2, size_t *a3,struct Struct_1_t *a4) {
    __int64 rsp;
    __int64 arg_1;
    __int64 arg_10;
    int arg_2;
    int arg_2e9;
    __int64 arg_3;
    int arg_30a;
    int arg_38;
    int arg_4;
    int arg_40;
    int arg_44;
    __int64 arg_5;
    int arg_54;
    int arg_58;
    int arg_7;
    int arg_8;
    __int64 v_100;
    __int64 v_10c;
    __int64 v_110;
    __int64 v_118;
    __int64 v_120;
    __int64 v_128;
    int v_130;
    __int64 v_138;
    __int64 v_140;
    __int64 v_148;
    __int64 v_150;
    __int64 v_158;
    __int64 v_160;
    int v_1d0;
    int v_1d8;
    int v_1e0;
    int v_1e8;
    __int64 v_20;
    __int64 v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    __int64 v_50;
    __int64 v_5f;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    int v_80;
    __int64 v_88;
    int v_90;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    __int64 *i2;
    struct Struct_3_t *ptr;
    __int64 *i3;
    __int64 *dst;
    __int64 *result;
    struct Struct_2_t *i;
    struct Struct_4_t *ptr2;
    __int64 *i4;
    __int64 *dst2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    v_130 = (int)a4;
    i2 = (__int64 *)a3;
    ptr = (struct Struct_3_t *)a2;
    i3 = (__int64 *)a1;
    dst = (__int64 *)v_1e8;
    result = (__int64 *)v_1e0;
    v_78 = (__int64)result;
    result = (__int64 *)v_1d8;
    v_128 = (__int64)result;
    result = (__int64 *)v_1d0;
    v_110 = (__int64)result;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        i = (struct Struct_2_t *)result;
        *result = 0x24848B48;
        result = *i3;
        a2 = (size_t *)arg_10;
        i->field_4 = 208;
        result = (__int64 *)((__int64)result - (__int64)a2);
        v_40 = (__int64)i3;
        if (result <= 7) {
            v_20 = 1;
            a1 = (size_t *)v_40;
            sub_1400F2D20(a1, a2, 8, 1);
            i3 = (__int64 *)v_40;
            a2 = (size_t *)arg_10;
        }
        result = (__int64 *)arg_8;
        a1 = i->field_0;
        *(__int64 *)((__int64)result + (__int64)a2) = a1;
        a2 += 8;
        arg_10 = (__int64)a2;
        off_140108030(a1, a2);
        off_140108038(result, 0, i);
        *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
        i3 = (__int64 *)arg_40;
        sub_14002EDF0(0, 7);
        if (result != 0) {
            ptr2 = (struct Struct_4_t *)result;
            *result = 72;
            result = i3;
            v_10c = (__int64)dst;
            if (i3 == i3) {
                ptr2->field_3 = i3;
                i = 4;
                result = 131;
                i3 = (__int64 *)v_40;
                ptr2->field_1 = result;
                ptr2->field_2 = 192;
                result = *i3;
                i4 = (__int64 *)arg_10;
                result = (__int64 *)((__int64)result - (__int64)i4);
                if (i > result) {
                    v_20 = 1;
                    a1 = (size_t *)v_40;
                    sub_1400F2D20(a1, i4, i, 1);
                    i3 = (__int64 *)v_40;
                    i4 = (__int64 *)arg_10;
                }
                a1 = (size_t *)arg_8;
                a1 = (size_t *)((__int64)a1 + (__int64)i4);
                sub_1400F27F0(a1, ptr2, i);
                i4 = (__int64 *)((__int64)i4 + (__int64)i);
                arg_10 = (__int64)i4;
                off_140108030();
                off_140108038(result, 0, ptr2);
                *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
                sub_14002EDF0(0, 8);
                i = (struct Struct_2_t *)result;
                *result = 0x24448948;
                result = *i3;
                a2 = (size_t *)arg_10;
                i->field_4 = 56;
                result = (__int64 *)((__int64)result - (__int64)a2);
                if (result <= 4) {
                    v_20 = 1;
                    a1 = (size_t *)v_40;
                    sub_1400F2D20(a1, a2, 5, 1);
                    i3 = (__int64 *)v_40;
                    a2 = (size_t *)arg_10;
                }
                result = (__int64 *)arg_8;
                a1 = i->field_4;
                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                a1 = i->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 5;
                arg_10 = (__int64)a2;
                off_140108030(a1, a2);
                off_140108038(result, 0, i);
                *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
                i4 = (__int64 *)arg_44;
                sub_14002EDF0(0, 12);
                if (result != 0) {
                    i = (struct Struct_2_t *)result;
                    *result = 0x2444C748;
                    arg_4 = 64;
                    arg_5 = (__int64)i4;
                    result = *i3;
                    a2 = (size_t *)arg_10;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if (result <= 8) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, a2, 9, 1);
                        i3 = (__int64 *)v_40;
                        a2 = (size_t *)arg_10;
                    }
                    result = (__int64 *)arg_8;
                    a1 = i->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                    a1 = i->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 9;
                    arg_10 = (__int64)a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, i);
                    *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
                    sub_1400D34C0(i3, ptr, 4);
                    dst = (__int64 *)arg_58;
                    v_50 = (__int64)ptr;
                    v_70 = (__int64)i2;
                    if (dst != 1) {
                        a3 = i2 + 24;
                        a4 = i2 + 72;
                        sub_1400D3870(i3, ptr, a3, a4);
                        i = (struct Struct_2_t *)arg_30a;
                        i3 = (__int64 *)v_130;
                        result = (i3 == 0) ? 1 : 0;
                        if (arg_2e9 != 1) {
                            result = (__int64 *)arg_54;
                            dst2 = 32;
                            if (result != 0) dst2 = result;
                            ptr = 0;
                            a3 = (size_t *)dst2;
                            if (arg_10 == 0) {
                                a1 = (size_t *)v_40;
                                a2 = (size_t *)v_50;
                                sub_1400D34C0(a1, a2, 2);
                                dst = (__int64 *)((__int64)(__int64)dst & (__int64)i3);
                                if (((__int64)i & (__int64)dst) == 0) {
                                    if ((arg_2e9 & (__int64)i3) != 0) {
                                        v_60 = (__int64)ptr;
                                        sub_14002EDF0(0, 8);
                                        i = (struct Struct_2_t *)result;
                                        *result = 0x24648B4C;
                                        ptr = (struct Struct_3_t *)v_40;
                                        result = ptr->field_0;
                                        a2 = ptr->field_10;
                                        i->field_4 = 56;
                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                    }
                                    i3 = (__int64 *)arg_10;
                                    if (((__int64)ptr & 1) == 0) {
                                        if (i3 == 0) {
                                            return (__int64)i3;
                                        }
                                    } else {
                                        ptr = (struct Struct_3_t *)v_50;
                                        i = (struct Struct_2_t *)v_40;
                                        if (i3 != 0) {
                                            sub_1400D34C0(i, ptr, 4);
                                            a4 = (struct Struct_1_t *)arg_8;
                                            a3 = (size_t *)arg_38;
                                            v_20 = (__int64)i3;
                                            i = (struct Struct_2_t *)v_40;
                                            ptr = (struct Struct_3_t *)v_50;
                                            sub_1400DA470(i, ptr, a3, a4);
                                        }
                                        a1 = (size_t *)i;
                                        a3 = (size_t *)dst2;
                                        return sub_1400D34C0();
                                    }
                                    return (__int64)a3;
                                }
                                a4 = i2 + 779;
                                result = (__int64 *)v_10c;
                                v_30 = (__int64)result;
                                result = (__int64 *)v_128;
                                v_28 = (__int64)result;
                                result = (__int64 *)v_110;
                                v_20 = (__int64)result;
                                a1 = (size_t *)v_40;
                                a2 = (size_t *)v_50;
                                sub_1400D6830(a1, a2, i4, a4);
                                return (__int64)a2;
                            }
                            dst = (__int64 *)((__int64)(__int64)dst & (__int64)i3);
                            if (((__int64)i & (__int64)dst) == 0) {
                                return (__int64)dst;
                            }
                            return (__int64)dst;
                        }
                        a1 = (size_t *)arg_54;
                        dst2 = 32;
                        if (a1 != 0) dst2 = a1;
                        a3 = 2;
                        ptr = (struct Struct_3_t *)i3;
                        if (result != 0) {
                            return (__int64)ptr;
                        }
                        ptr = (struct Struct_3_t *)i3;
                        return (__int64)ptr;
                    }
                    sub_14002EDF0(0, 8);
                    i = (struct Struct_2_t *)result;
                    *result = 0x24448B4C;
                    i3 = (__int64 *)v_40;
                    result = *i3;
                    a2 = (size_t *)arg_10;
                    i->field_4 = 56;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if (result <= 4) {
                        do {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, a2, 5, 1);
                            i3 = (__int64 *)v_40;
                            a2 = (size_t *)arg_10;
                        } while (true);
                    }
                    result = (__int64 *)arg_8;
                    a1 = i->field_4;
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                    a1 = i->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 5;
                    arg_10 = (__int64)a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, i);
                    i2 = ptr->field_0;
                    result = i2 + 1;
                    *(__int64 *)ptr = (__int64)(result);
                    sub_14002EDF0(0, 8);
                    i = (struct Struct_2_t *)result;
                    *result = 0x244C8B4C;
                    result = *i3;
                    a2 = (size_t *)arg_10;
                    i->field_4 = 64;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if (result <= 4) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, a2, 5, 1);
                        i3 = (__int64 *)v_40;
                        a2 = (size_t *)arg_10;
                    }
                    result = (__int64 *)arg_8;
                    a1 = i->field_4;
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                    a1 = i->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 5;
                    arg_10 = (__int64)a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, i);
                    a3 = (size_t *)v_40;
                    i = a3[2];
                    result = i2 + 2;
                    *(__int64 *)ptr = (__int64)(result);
                    result = *a3;
                    result = (__int64 *)((__int64)result - (__int64)i);
                    if (result <= 3) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, i, 4, 1);
                        a3 = (size_t *)v_40;
                        i = a3[2];
                    }
                    result = (__int64 *)arg_8;
                    *(__int64 *)((__int64)result + (__int64)i) = 0x4E9C149;
                    i3 = i + 4;
                    a3[2] = i3;
                    result = *a3;
                    result = (__int64 *)((__int64)result - (__int64)i3);
                    if (result <= 6) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, i3, 7, 1);
                        a3 = (size_t *)v_40;
                        i3 = a3[2];
                    }
                    result = (__int64 *)arg_8;
                    *(__int64 *)((__int64)result + (__int64)i3 + 3) = 0;
                    *(__int64 *)((__int64)result + (__int64)i3) = 0x358D48;
                    i3 += 7;
                    a3[2] = i3;
                    result = *a3;
                    result = (__int64 *)((__int64)result - (__int64)i3);
                    a1 = (size_t *)i3;
                    if (result <= 2) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, i3, 3, 1);
                        a3 = (size_t *)v_40;
                        a1 = a3[2];
                    }
                    result = (__int64 *)arg_8;
                    *(__int64 *)((__int64)result + (__int64)a1 + 2) = 201;
                    *(__int64 *)((__int64)result + (__int64)a1) = 0x854D;
                    a2 = a1 + 3;
                    a3[2] = a2;
                    result = *a3;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    v_100 = (__int64)a1;
                    v_158 = (__int64)i3;
                    if (result <= 5) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, a2, 6, 1);
                        a3 = (size_t *)v_40;
                        a2 = a3[2];
                    }
                    result = (__int64 *)v_70;
                    dst2 = result + 89;
                    ptr2 = result + 729;
                    result = (__int64 *)arg_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x840F;
                    a2 += 6;
                    a3[2] = a2;
                    result = i2 + 6;
                    *(__int64 *)ptr = (__int64)(result);
                    i3 = 0;
                    do {
                        result = *a3;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, a2, 5, 1);
                        a3 = (size_t *)v_40;
                        a2 = a3[2];
                        result = (__int64 *)arg_8;
                        *(__int64 *)((__int64)result + (__int64)a2) = 0x40B60F41;
                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = i3;
                        a2 += 5;
                        a3[2] = a2;
                        result = *a3;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 2) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, a2, 3, 1);
                            a3 = (size_t *)v_40;
                            a2 = a3[2];
                        }
                        result = (__int64 *)arg_8;
                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                        *(__int64 *)((__int64)result + (__int64)a2) = 0x8488;
                        a2 += 3;
                        a3[2] = a2;
                        result = *a3;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 3) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, a2, 4, 1);
                            a3 = (size_t *)v_40;
                            a2 = a3[2];
                        }
                        result = i3 + 72;
                        a1 = (size_t *)arg_8;
                        *(__int64 *)((__int64)a1 + (__int64)a2) = result;
                        a2 += 4;
                        a3[2] = a2;
                        ++i3;
                    } while (i3 != 16);
                    v_150 = (__int64)i;
                    sub_14002EDF0(0, 12);
                    if (result != 0) {
                        i = (struct Struct_2_t *)result;
                        *result = 0x2444C748;
                        arg_4 = 88;
                        arg_5 = 0;
                        i3 = (__int64 *)v_40;
                        result = *i3;
                        a2 = (size_t *)arg_10;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 8) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, a2, 9, 1);
                            i3 = (__int64 *)v_40;
                            a2 = (size_t *)arg_10;
                        }
                        result = (__int64 *)arg_8;
                        a1 = i->field_8;
                        *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                        a1 = i->field_0;
                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                        a2 += 9;
                        arg_10 = (__int64)a2;
                        off_140108030(a1, a2);
                        off_140108038(result, 0, i);
                        result = i2 + 39;
                        *(__int64 *)ptr = (__int64)(result);
                        sub_14002EDF0(0, 12);
                        if (result != 0) {
                            i = (struct Struct_2_t *)result;
                            *result = 0x2444C748;
                            arg_4 = 96;
                            arg_5 = 0;
                            result = *i3;
                            a2 = (size_t *)arg_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 8) {
                                v_20 = 1;
                                a1 = (size_t *)v_40;
                                sub_1400F2D20(a1, a2, 9, 1);
                                i3 = (__int64 *)v_40;
                                a2 = (size_t *)arg_10;
                            }
                            result = (__int64 *)arg_8;
                            a1 = i->field_8;
                            *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                            a1 = i->field_0;
                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                            a2 += 9;
                            arg_10 = (__int64)a2;
                            off_140108030(a1, a2);
                            off_140108038(result, 0, i);
                            a3 = (size_t *)v_40;
                            i3 = a3[2];
                            if (i3 == *a3) {
                                sub_1400F3510(a3, a2, a3);
                                a3 = (size_t *)v_40;
                            }
                            result = (__int64 *)arg_8;
                            *(__int64 *)((__int64)result + (__int64)i3) = 77;
                            result = i3 + 1;
                            a3[2] = result;
                            if (result == *a3) {
                                sub_1400F3510(a3, a2, a3);
                                a3 = (size_t *)v_40;
                            }
                            result = (__int64 *)arg_8;
                            *(__int64 *)((__int64)result + (__int64)i3 + 1) = 49;
                            result = i3 + 2;
                            a3[2] = result;
                            if (result == *a3) {
                                sub_1400F3510(a3, a2, a3);
                                a3 = (size_t *)v_40;
                            }
                            result = (__int64 *)arg_8;
                            *(__int64 *)((__int64)result + (__int64)i3 + 2) = 210;
                            i3 += 3;
                            v_118 = (__int64)i3;
                            a3[2] = i3;
                            result = i2 + 41;
                            *(__int64 *)ptr = (__int64)(result);
                            i3 = (__int64 *)a3;
                            sub_14002EDF0(0, 7, a3);
                            if (result != 0) {
                                i = (struct Struct_2_t *)result;
                                *result = 0x10FA8349;
                                result = *i3;
                                a2 = (size_t *)arg_10;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 3) {
                                    v_20 = 1;
                                    a1 = (size_t *)v_40;
                                    sub_1400F2D20(a1, a2, 4, 1);
                                    i3 = (__int64 *)v_40;
                                    a2 = (size_t *)arg_10;
                                }
                                result = (__int64 *)arg_8;
                                a1 = i->field_0;
                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                a2 += 4;
                                arg_10 = (__int64)a2;
                                off_140108030(a1, a2);
                                off_140108038(result, 0, i);
                                result = i2 + 42;
                                *(__int64 *)ptr = (__int64)(result);
                                result = (__int64 *)arg_10;
                                v_160 = (__int64)result;
                                sub_14002EDF0(0, 6);
                                if (result != 0) {
                                    i = (struct Struct_2_t *)result;
                                    *result = 0x840F;
                                    arg_2 = 0;
                                    result = *i3;
                                    a2 = (size_t *)arg_10;
                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                    v_138 = (__int64)i4;
                                    if (result <= 5) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, a2, 6, 1);
                                        i3 = (__int64 *)v_40;
                                        a2 = (size_t *)arg_10;
                                    }
                                    v_148 = (__int64)ptr2;
                                    v_5f = (__int64)dst;
                                    result = (__int64 *)arg_8;
                                    a1 = i->field_4;
                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                    a1 = i->field_0;
                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                    a2 += 6;
                                    arg_10 = (__int64)a2;
                                    i4 = i3;
                                    off_140108030(a1, a2);
                                    off_140108038(result, 0, i);
                                    result = i2 + 43;
                                    *(__int64 *)ptr = (__int64)(result);
                                    sub_14002EDF0(0, 9);
                                    if (result != 0) {
                                        v_80 = 9;
                                        v_88 = (__int64)result;
                                        *result = 0xF42;
                                        arg_2 = 182;
                                        v_90 = 3;
                                        v_20 = 72;
                                        a1 = rsp + 128;
                                        sub_1400D5BD0(a1, 1, 2, 0);
                                        i3 = (__int64 *)v_80;
                                        ptr2 = (struct Struct_4_t *)v_88;
                                        i = (struct Struct_2_t *)v_90;
                                        result = *i4;
                                        dst = (__int64 *)arg_10;
                                        result = (__int64 *)((__int64)result - (__int64)dst);
                                        if (i > result) {
                                            v_20 = 1;
                                            a1 = (size_t *)v_40;
                                            sub_1400F2D20(a1, dst, i, 1);
                                            i4 = (__int64 *)v_40;
                                            dst = (__int64 *)arg_10;
                                        }
                                        a1 = (size_t *)arg_8;
                                        a1 = (size_t *)((__int64)a1 + (__int64)dst);
                                        sub_1400F27F0(a1, ptr2, i);
                                        a3 = (size_t *)v_40;
                                        dst = (__int64 *)((__int64)dst + (__int64)i);
                                        a3[2] = dst;
                                        if (i3 == 0) {
                                            result = *a3;
                                            result = (__int64 *)((__int64)result - (__int64)dst);
                                            v_140 = (__int64)dst2;
                                            if (result <= 1) {
                                                v_20 = 1;
                                                a1 = (size_t *)v_40;
                                                sub_1400F2D20(a1, dst, 2, 1);
                                                a3 = (size_t *)v_40;
                                                dst = a3[2];
                                            }
                                            result = (__int64 *)arg_8;
                                            *(__int64 *)((__int64)result + (__int64)dst) = 0xC984;
                                            dst2 = dst + 2;
                                            a3[2] = dst2;
                                            result = i2 + 45;
                                            *(__int64 *)ptr = (__int64)(result);
                                            result = *a3;
                                            result = (__int64 *)((__int64)result - (__int64)dst2);
                                            if (result <= 5) {
                                                v_20 = 1;
                                                a1 = (size_t *)v_40;
                                                sub_1400F2D20(a1, dst2, 6, 1);
                                                a3 = (size_t *)v_40;
                                                dst2 = a3[2];
                                            }
                                            result = (__int64 *)arg_8;
                                            *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 0;
                                            *(__int64 *)((__int64)result + (__int64)dst2) = 0x840F;
                                            result = dst2 + 6;
                                            a3[2] = result;
                                            if (result == *a3) {
                                                sub_1400F3510(a3, a2, a3);
                                                a3 = (size_t *)v_40;
                                            }
                                            result = (__int64 *)arg_8;
                                            *(__int64 *)((__int64)result + (__int64)dst2 + 6) = 77;
                                            result = dst2 + 7;
                                            a3[2] = result;
                                            if (result == *a3) {
                                                sub_1400F3510(a3, a2, a3);
                                                a3 = (size_t *)v_40;
                                            }
                                            result = (__int64 *)arg_8;
                                            *(__int64 *)((__int64)result + (__int64)dst2 + 7) = 49;
                                            result = dst2 + 8;
                                            a3[2] = result;
                                            if (result == *a3) {
                                                sub_1400F3510(a3, a2, a3);
                                                a3 = (size_t *)v_40;
                                            }
                                            result = (__int64 *)arg_8;
                                            *(__int64 *)((__int64)result + (__int64)dst2 + 8) = 219;
                                            dst2 += 9;
                                            a3[2] = dst2;
                                            result = i2 + 47;
                                            *(__int64 *)ptr = (__int64)(result);
                                            i3 = (__int64 *)a3;
                                            sub_14002EDF0(0, 7, a3);
                                            if (result != 0) {
                                                i = (struct Struct_2_t *)result;
                                                *result = 0x10FB8349;
                                                result = *i3;
                                                a2 = (size_t *)arg_10;
                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    a1 = (size_t *)v_40;
                                                    sub_1400F2D20(a1, a2, 4, 1);
                                                    i3 = (__int64 *)v_40;
                                                    a2 = (size_t *)arg_10;
                                                }
                                                result = (__int64 *)arg_8;
                                                a1 = i->field_0;
                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                a2 += 4;
                                                arg_10 = (__int64)a2;
                                                off_140108030(a1, a2);
                                                off_140108038(result, 0, i);
                                                result = i2 + 48;
                                                *(__int64 *)ptr = (__int64)(result);
                                                ptr2 = (struct Struct_4_t *)arg_10;
                                                sub_14002EDF0(0, 6);
                                                if (result != 0) {
                                                    i = (struct Struct_2_t *)result;
                                                    *result = 0x840F;
                                                    arg_2 = 0;
                                                    result = *i3;
                                                    a2 = (size_t *)arg_10;
                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                    if (result <= 5) {
                                                        v_20 = 1;
                                                        a1 = (size_t *)v_40;
                                                        sub_1400F2D20(a1, a2, 6, 1);
                                                        i3 = (__int64 *)v_40;
                                                        a2 = (size_t *)arg_10;
                                                    }
                                                    result = (__int64 *)arg_8;
                                                    a1 = i->field_4;
                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                    a1 = i->field_0;
                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                    a2 += 6;
                                                    arg_10 = (__int64)a2;
                                                    off_140108030(a1, a2);
                                                    off_140108038(result, 0, i);
                                                    result = i2 + 49;
                                                    *(__int64 *)ptr = (__int64)(result);
                                                    sub_14002EDF0(0, 9);
                                                    if (result != 0) {
                                                        i = (struct Struct_2_t *)result;
                                                        *result = 0x4B60F42;
                                                        result = *i3;
                                                        a2 = (size_t *)arg_10;
                                                        i->field_4 = 30;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 4) {
                                                            v_20 = 1;
                                                            a1 = (size_t *)v_40;
                                                            sub_1400F2D20(a1, a2, 5, 1);
                                                            i3 = (__int64 *)v_40;
                                                            a2 = (size_t *)arg_10;
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        a1 = i->field_4;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                        a1 = i->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 5;
                                                        arg_10 = (__int64)a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, i);
                                                        a3 = (size_t *)v_40;
                                                        a2 = a3[2];
                                                        result = i2 + 50;
                                                        *(__int64 *)ptr = (__int64)(result);
                                                        result = *a3;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 1) {
                                                            v_20 = 1;
                                                            a1 = (size_t *)v_40;
                                                            sub_1400F2D20(a1, a2, 2, 1);
                                                            a3 = (size_t *)v_40;
                                                            a2 = a3[2];
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xC288;
                                                        a2 += 2;
                                                        a3[2] = a2;
                                                        result = *a3;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 1) {
                                                            v_20 = 1;
                                                            a1 = (size_t *)v_40;
                                                            sub_1400F2D20(a1, a2, 2, 1);
                                                            a3 = (size_t *)v_40;
                                                            a2 = a3[2];
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xC888;
                                                        a2 += 2;
                                                        a3[2] = a2;
                                                        result = *a3;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 1) {
                                                            v_20 = 1;
                                                            a1 = (size_t *)v_40;
                                                            sub_1400F2D20(a1, a2, 2, 1);
                                                            a3 = (size_t *)v_40;
                                                            a2 = a3[2];
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xE2F6;
                                                        a2 += 2;
                                                        a3[2] = a2;
                                                        result = *a3;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 1) {
                                                            v_20 = 1;
                                                            a1 = (size_t *)v_40;
                                                            sub_1400F2D20(a1, a2, 2, 1);
                                                            a3 = (size_t *)v_40;
                                                            a2 = a3[2];
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xC288;
                                                        a2 += 2;
                                                        a3[2] = a2;
                                                        result = i2 + 54;
                                                        *(__int64 *)ptr = (__int64)(result);
                                                        i3 = (__int64 *)a3;
                                                        sub_14002EDF0(0, 3, a3);
                                                        i = (struct Struct_2_t *)result;
                                                        *result = 0x894C;
                                                        arg_2 = 211;
                                                        result = *i3;
                                                        a2 = (size_t *)arg_10;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 2) {
                                                            v_20 = 1;
                                                            a1 = (size_t *)v_40;
                                                            sub_1400F2D20(a1, a2, 3, 1);
                                                            a3 = (size_t *)v_40;
                                                            a2 = a3[2];
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        a1 = i->field_2;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                        a1 = i->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 3;
                                                        a3[2] = a2;
                                                        off_140108030(a1, a2, i3);
                                                        off_140108038(result, 0, i);
                                                        a3 = (size_t *)v_40;
                                                        result = i2 + 55;
                                                        *(__int64 *)ptr = (__int64)(result);
                                                        i3 = a3[2];
                                                        if (i3 == *a3) {
                                                            sub_1400F3510(a3, a2, a3);
                                                            a3 = (size_t *)v_40;
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)i3) = 76;
                                                        result = i3 + 1;
                                                        a3[2] = result;
                                                        if (result == *a3) {
                                                            sub_1400F3510(a3, a2, a3);
                                                            a3 = (size_t *)v_40;
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)i3 + 1) = 1;
                                                        result = i3 + 2;
                                                        a3[2] = result;
                                                        if (result == *a3) {
                                                            sub_1400F3510(a3, a2, a3);
                                                            a3 = (size_t *)v_40;
                                                        }
                                                        result = (__int64 *)arg_8;
                                                        *(__int64 *)((__int64)result + (__int64)i3 + 2) = 219;
                                                        i3 += 3;
                                                        a3[2] = i3;
                                                        i3 = (__int64 *)a3;
                                                        sub_14002EDF0(0, 7, a3);
                                                        if (result != 0) {
                                                            i = (struct Struct_2_t *)result;
                                                            *result = 0x10FB8348;
                                                            result = *i3;
                                                            a2 = (size_t *)arg_10;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 3) {
                                                                v_20 = 1;
                                                                a1 = (size_t *)v_40;
                                                                sub_1400F2D20(a1, a2, 4, 1);
                                                                i3 = (__int64 *)v_40;
                                                                a2 = (size_t *)arg_10;
                                                            }
                                                            result = (__int64 *)arg_8;
                                                            a1 = i->field_0;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                            a2 += 4;
                                                            arg_10 = (__int64)a2;
                                                            off_140108030(a1, a2);
                                                            off_140108038(result, 0, i);
                                                            v_60 = (__int64)i2;
                                                            result = i2 + 57;
                                                            *(__int64 *)ptr = (__int64)(result);
                                                            i2 = (__int64 *)arg_10;
                                                            sub_14002EDF0(0, 6);
                                                            if (result != 0) {
                                                                i = (struct Struct_2_t *)result;
                                                                *result = 0x820F;
                                                                arg_2 = 0;
                                                                result = *i3;
                                                                a2 = (size_t *)arg_10;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 5) {
                                                                    v_20 = 1;
                                                                    a1 = (size_t *)v_40;
                                                                    sub_1400F2D20(a1, a2, 6, 1);
                                                                    i3 = (__int64 *)v_40;
                                                                    a2 = (size_t *)arg_10;
                                                                }
                                                                result = (__int64 *)arg_8;
                                                                a1 = i->field_4;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                a1 = i->field_0;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                a2 += 6;
                                                                arg_10 = (__int64)a2;
                                                                off_140108030(a1, a2);
                                                                off_140108038(result, 0, i);
                                                                sub_14002EDF0(0, 7);
                                                                if (result != 0) {
                                                                    i = (struct Struct_2_t *)result;
                                                                    *result = 0x10EB8348;
                                                                    result = *i3;
                                                                    a2 = (size_t *)arg_10;
                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                    v_120 = (__int64)ptr2;
                                                                    if (result <= 3) {
                                                                        v_20 = 1;
                                                                        a1 = (size_t *)v_40;
                                                                        sub_1400F2D20(a1, a2, 4, 1);
                                                                        i4 = (__int64 *)v_40;
                                                                        a2 = (size_t *)arg_10;
                                                                        v_68 = (__int64)dst;
                                                                        result = (__int64 *)arg_8;
                                                                        a1 = i->field_0;
                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                        a2 += 4;
                                                                        arg_10 = (__int64)a2;
                                                                        off_140108030(a1, a2);
                                                                        off_140108038(result, 0, i);
                                                                        result = (__int64 *)v_60;
                                                                        result += 59;
                                                                        *(__int64 *)ptr = (__int64)(result);
                                                                        sub_14002EDF0(0, 9);
                                                                        if (result != 0) {
                                                                            v_80 = 9;
                                                                            v_88 = (__int64)result;
                                                                            *result = 0xB60F;
                                                                            v_90 = 2;
                                                                            v_20 = 88;
                                                                            a1 = rsp + 128;
                                                                            sub_1400D5BD0(a1, 0, 3, 0);
                                                                            i3 = (__int64 *)v_80;
                                                                            dst = (__int64 *)v_88;
                                                                            i = (struct Struct_2_t *)v_90;
                                                                            result = *i4;
                                                                            ptr2 = (struct Struct_4_t *)arg_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                            if (i > result) {
                                                                                v_20 = 1;
                                                                                a1 = (size_t *)v_40;
                                                                                sub_1400F2D20(a1, ptr2, i, 1);
                                                                                i4 = (__int64 *)v_40;
                                                                                ptr2 = (struct Struct_4_t *)arg_10;
                                                                            }
                                                                            a1 = (size_t *)arg_8;
                                                                            a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                                                            sub_1400F27F0(a1, dst, i);
                                                                            a3 = (size_t *)v_40;
                                                                            ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)i);
                                                                            a3[2] = ptr2;
                                                                            if (i3 == 0) {
                                                                                result = *a3;
                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                i4 = i2;
                                                                                if (result <= 1) {
                                                                                    v_20 = 1;
                                                                                    a1 = (size_t *)v_40;
                                                                                    sub_1400F2D20(a1, ptr2, 2, 1);
                                                                                    a3 = (size_t *)v_40;
                                                                                    ptr2 = a3[2];
                                                                                }
                                                                                i3 = (__int64 *)v_50;
                                                                                i2 = (__int64 *)v_60;
                                                                                result = (__int64 *)arg_8;
                                                                                *(__int64 *)((__int64)result + (__int64)ptr2) = 0xD028;
                                                                                ptr2 += 2;
                                                                                a3[2] = ptr2;
                                                                                result = i2 + 61;
                                                                                *i3 = result;
                                                                                result = *a3;
                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                if (result <= 2) {
                                                                                    v_20 = 1;
                                                                                    a1 = (size_t *)v_40;
                                                                                    sub_1400F2D20(a1, ptr2, 3, 1);
                                                                                    a3 = (size_t *)v_40;
                                                                                    ptr2 = a3[2];
                                                                                }
                                                                                result = (__int64 *)arg_8;
                                                                                *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 28;
                                                                                *(__int64 *)((__int64)result + (__int64)ptr2) = 0x8488;
                                                                                ptr2 += 3;
                                                                                a3[2] = ptr2;
                                                                                result = *a3;
                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                if (result <= 3) {
                                                                                    v_20 = 1;
                                                                                    a1 = (size_t *)v_40;
                                                                                    sub_1400F2D20(a1, ptr2, 4, 1);
                                                                                    a3 = (size_t *)v_40;
                                                                                    ptr2 = a3[2];
                                                                                }
                                                                                result = (__int64 *)arg_8;
                                                                                *(__int64 *)((__int64)result + (__int64)ptr2) = 88;
                                                                                result = ptr2 + 4;
                                                                                a3[2] = result;
                                                                                ptr = (struct Struct_3_t *)a3;
                                                                                sub_14002EDF0(0, 5, a3);
                                                                                if (result != 0) {
                                                                                    i = (struct Struct_2_t *)result;
                                                                                    *result = 233;
                                                                                    arg_1 = 0;
                                                                                    result = ptr->field_0;
                                                                                    a2 = ptr->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                    if (result <= 4) {
                                                                                        v_20 = 1;
                                                                                        a1 = (size_t *)v_40;
                                                                                        sub_1400F2D20(a1, a2, 5, 1);
                                                                                        ptr = (struct Struct_3_t *)v_40;
                                                                                        a2 = ptr->field_10;
                                                                                    }
                                                                                    result = ptr->field_8;
                                                                                    a1 = i->field_4;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                    a1 = i->field_0;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                    a2 += 5;
                                                                                    ptr->field_10 = a2;
                                                                                    off_140108030(a1, a2);
                                                                                    off_140108038(result, 0, i);
                                                                                    result = i2 + 63;
                                                                                    *i3 = result;
                                                                                    a2 = (size_t *)i4;
                                                                                    a2 += 6;
                                                                                    if (!((a2 < 0))) {
                                                                                        a3 = ptr->field_10;
                                                                                        result = (__int64 *)a3;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        a1 = (size_t *)result;
                                                                                        if (result == result) {
                                                                                            if (a3 < a2) {
                                                                                                i4 += 2;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(i4, a2, a3, a4);
                                                                                                ptr2 += 5;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(ptr2, a2, i4, a4);
                                                                                                ptr += 2;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(ptr, a2, a3, a4);
                                                                                                a1 = (size_t *)v_68;
                                                                                                a1 += 4;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(a1, a2, a3, a4);
                                                                                                dst2 += 5;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(dst2, a2, ptr2, a4);
                                                                                                a1 += 7;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(a1, a2, a3, a4);
                                                                                                i2 += 5;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(i2, a2, a3, a4);
                                                                                                ptr2 += 6;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(ptr2, a2, i, a4);
                                                                                                i4 += 10;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(i4, a2, a3, a4);
                                                                                                a1 += 3;
                                                                                                a4 = &off_14011D380;
                                                                                                sub_1400F3600(a1, a2, a3, a4);
                                                                                            }
                                                                                            a1 = ptr->field_8;
                                                                                            *(__int64 *)((__int64)a1 + (__int64)i4 + 2) = result;
                                                                                            sub_14002EDF0(0, 9, a3);
                                                                                            if (result != 0) {
                                                                                                v_80 = 9;
                                                                                                v_88 = (__int64)result;
                                                                                                *result = 0xB60F;
                                                                                                v_90 = 2;
                                                                                                v_20 = 88;
                                                                                                a1 = rsp + 128;
                                                                                                sub_1400D5BD0(a1, 0, 3, 0);
                                                                                                i3 = (__int64 *)v_80;
                                                                                                dst = (__int64 *)v_88;
                                                                                                i = (struct Struct_2_t *)v_90;
                                                                                                result = ptr->field_0;
                                                                                                i4 = ptr->field_10;
                                                                                                result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                if (i > result) {
                                                                                                    v_20 = 1;
                                                                                                    a1 = (size_t *)v_40;
                                                                                                    sub_1400F2D20(a1, i4, i, 1);
                                                                                                    ptr = (struct Struct_3_t *)v_40;
                                                                                                    i4 = ptr->field_10;
                                                                                                }
                                                                                                a1 = ptr->field_8;
                                                                                                a1 = (size_t *)((__int64)a1 + (__int64)i4);
                                                                                                sub_1400F27F0(a1, dst, i);
                                                                                                a3 = (size_t *)v_40;
                                                                                                i4 = (__int64 *)((__int64)i4 + (__int64)i);
                                                                                                a3[2] = i4;
                                                                                                if (i3 == 0) {
                                                                                                    result = *a3;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                    if (result <= 1) {
                                                                                                        v_20 = 1;
                                                                                                        a1 = (size_t *)v_40;
                                                                                                        sub_1400F2D20(a1, i4, 2, 1);
                                                                                                        a3 = (size_t *)v_40;
                                                                                                        i4 = a3[2];
                                                                                                    }
                                                                                                    dst = (__int64 *)v_50;
                                                                                                    result = (__int64 *)arg_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)i4) = 0xD000;
                                                                                                    i4 += 2;
                                                                                                    a3[2] = i4;
                                                                                                    result = *a3;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                    if (result <= 2) {
                                                                                                        v_20 = 1;
                                                                                                        a1 = (size_t *)v_40;
                                                                                                        sub_1400F2D20(a1, i4, 3, 1);
                                                                                                        a3 = (size_t *)v_40;
                                                                                                        i4 = a3[2];
                                                                                                    }
                                                                                                    result = (__int64 *)arg_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)i4 + 2) = 28;
                                                                                                    *(__int64 *)((__int64)result + (__int64)i4) = 0x8488;
                                                                                                    i4 += 3;
                                                                                                    a3[2] = i4;
                                                                                                    result = *a3;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                    if (result <= 3) {
                                                                                                        v_20 = 1;
                                                                                                        a1 = (size_t *)v_40;
                                                                                                        sub_1400F2D20(a1, i4, 4, 1);
                                                                                                        a3 = (size_t *)v_40;
                                                                                                        i4 = a3[2];
                                                                                                    }
                                                                                                    result = (__int64 *)arg_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)i4) = 88;
                                                                                                    i4 += 4;
                                                                                                    a3[2] = i4;
                                                                                                    a2 = (size_t *)ptr2;
                                                                                                    a2 += 9;
                                                                                                    if (!((a2 < 0))) {
                                                                                                        result = i4;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        a1 = (size_t *)result;
                                                                                                        if (result == result) {
                                                                                                            if (i4 < a2) {
                                                                                                                return (__int64)a1;
                                                                                                            }
                                                                                                            a1 = (size_t *)arg_8;
                                                                                                            *(__int64 *)((__int64)a1 + (__int64)ptr2 + 5) = result;
                                                                                                            result = *a3;
                                                                                                            a2 = a3[2];
                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                            if (result <= 2) {
                                                                                                                v_20 = 1;
                                                                                                                a1 = (size_t *)v_40;
                                                                                                                sub_1400F2D20(a1, a2, 3, 1);
                                                                                                                a3 = (size_t *)v_40;
                                                                                                                a2 = a3[2];
                                                                                                            }
                                                                                                            ptr = (struct Struct_3_t *)v_120;
                                                                                                            result = (__int64 *)arg_8;
                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 195;
                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xFF49;
                                                                                                            result = a2 + 3;
                                                                                                            a3[2] = result;
                                                                                                            a2 += 8;
                                                                                                            if (!((a2 < 0))) {
                                                                                                                dst2 = (__int64 *)((__int64)dst2 - (__int64)a2);
                                                                                                                result = dst2;
                                                                                                                if (dst2 == dst2) {
                                                                                                                    sub_14002EDF0(0, 5, a3);
                                                                                                                    if (result != 0) {
                                                                                                                        i = (struct Struct_2_t *)result;
                                                                                                                        *result = 233;
                                                                                                                        arg_1 = (__int64)dst2;
                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                        result = *a3;
                                                                                                                        a2 = a3[2];
                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                        if (result <= 4) {
                                                                                                                            v_20 = 1;
                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                            sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                            a3 = (size_t *)v_40;
                                                                                                                            a2 = a3[2];
                                                                                                                        }
                                                                                                                        dst2 = (__int64 *)v_100;
                                                                                                                        result = (__int64 *)arg_8;
                                                                                                                        a1 = i->field_4;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                        a1 = i->field_0;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                        a2 += 5;
                                                                                                                        a3[2] = a2;
                                                                                                                        i3 = (__int64 *)a3;
                                                                                                                        off_140108030(a1, a2, a3);
                                                                                                                        off_140108038(result, 0, i);
                                                                                                                        result = i2 + 68;
                                                                                                                        *dst = result;
                                                                                                                        a2 = (size_t *)ptr;
                                                                                                                        a2 += 6;
                                                                                                                        if (!((a2 < 0))) {
                                                                                                                            a3 = (size_t *)arg_10;
                                                                                                                            result = (__int64 *)a3;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            a1 = (size_t *)result;
                                                                                                                            if (result == result) {
                                                                                                                                i3 = (__int64 *)v_118;
                                                                                                                                if (a3 < a2) {
                                                                                                                                    return (__int64)i3;
                                                                                                                                }
                                                                                                                                a1 = a4->field_8;
                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)ptr + 2) = result;
                                                                                                                                a2 = (size_t *)v_68;
                                                                                                                                a2 += 8;
                                                                                                                                if (!((a2 < 0))) {
                                                                                                                                    a3 = ((__int64 *)a4)[2];
                                                                                                                                    result = (__int64 *)a3;
                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                    if (result == result) {
                                                                                                                                        if (a3 < a2) {
                                                                                                                                            return (__int64)a1;
                                                                                                                                        }
                                                                                                                                        a1 = a4->field_8;
                                                                                                                                        a2 = (size_t *)v_68;
                                                                                                                                        *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = result;
                                                                                                                                        result = a4->field_0;
                                                                                                                                        a2 = ((__int64 *)a4)[2];
                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                        if (result <= 2) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                            sub_1400F2D20(a1, a2, 3, 1);
                                                                                                                                            a4 = (struct Struct_1_t *)v_40;
                                                                                                                                            a2 = ((__int64 *)a4)[2];
                                                                                                                                        }
                                                                                                                                        result = a4->field_8;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 194;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xFF49;
                                                                                                                                        result = a2 + 3;
                                                                                                                                        ((__int64 *)a4)[2] = (__int64)(result);
                                                                                                                                        a2 += 8;
                                                                                                                                        if (!((a2 < 0))) {
                                                                                                                                            i3 = (__int64 *)((__int64)i3 - (__int64)a2);
                                                                                                                                            result = i3;
                                                                                                                                            if (i3 == i3) {
                                                                                                                                                sub_14002EDF0(0, 5, a3, i3);
                                                                                                                                                if (result != 0) {
                                                                                                                                                    i = (struct Struct_2_t *)result;
                                                                                                                                                    *result = 233;
                                                                                                                                                    arg_1 = (__int64)i3;
                                                                                                                                                    a3 = (size_t *)v_40;
                                                                                                                                                    result = *a3;
                                                                                                                                                    a2 = a3[2];
                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                    if (result <= 4) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                        sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                        a2 = a3[2];
                                                                                                                                                    }
                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                    a1 = i->field_4;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                    a1 = i->field_0;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                    a2 += 5;
                                                                                                                                                    a3[2] = a2;
                                                                                                                                                    i3 = (__int64 *)a3;
                                                                                                                                                    off_140108030(a1, a2, a3);
                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                    result = i2 + 70;
                                                                                                                                                    *dst = result;
                                                                                                                                                    a1 = (size_t *)v_160;
                                                                                                                                                    a2 = a1;
                                                                                                                                                    a2 += 6;
                                                                                                                                                    if (!((a2 < 0))) {
                                                                                                                                                        a3 = (size_t *)arg_10;
                                                                                                                                                        result = (__int64 *)a3;
                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                        a4 = (struct Struct_1_t *)result;
                                                                                                                                                        if (result == result) {
                                                                                                                                                            if (a3 < a2) {
                                                                                                                                                                a1 += 2;
                                                                                                                                                                a4 = &off_14011D380;
                                                                                                                                                                sub_1400F3600(a1, a2, a3, a4);
                                                                                                                                                            }
                                                                                                                                                            a4 = (struct Struct_1_t *)i3;
                                                                                                                                                            a2 = (size_t *)arg_8;
                                                                                                                                                            *(__int64 *)((__int64)a2 + (__int64)a1 + 2) = result;
                                                                                                                                                            i4 = (__int64 *)arg_10;
                                                                                                                                                            i3 = 88;
                                                                                                                                                            ptr = 0x408841;
                                                                                                                                                            do {
                                                                                                                                                                a1 = a4->field_0;
                                                                                                                                                                result = (__int64 *)a1;
                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                v_20 = 1;
                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                a1 = a4->field_0;
                                                                                                                                                                i4 = ((__int64 *)a4)[2];
                                                                                                                                                                result = a4->field_8;
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i4) = 0x2484B60F;
                                                                                                                                                                i4 += 4;
                                                                                                                                                                ((__int64 *)a4)[2] = (__int64)(i4);
                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                if (a1 <= 3) {
                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                    sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                    a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                    result = a4->field_8;
                                                                                                                                                                    i4 = ((__int64 *)a4)[2];
                                                                                                                                                                }
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i4) = i3;
                                                                                                                                                                i4 += 4;
                                                                                                                                                                ((__int64 *)a4)[2] = (__int64)(i4);
                                                                                                                                                                a1 = a4->field_0;
                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                if (a1 <= 3) {
                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                    sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                    a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                    result = a4->field_8;
                                                                                                                                                                    i4 = ((__int64 *)a4)[2];
                                                                                                                                                                }
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i4) = ptr;
                                                                                                                                                                i4 += 4;
                                                                                                                                                                ((__int64 *)a4)[2] = (__int64)(i4);
                                                                                                                                                                ++i3;
                                                                                                                                                                ptr += 0x1000000;
                                                                                                                                                            } while (i3 != 104);
                                                                                                                                                            sub_14002EDF0(0, 7, a3, a4);
                                                                                                                                                            if (result != 0) {
                                                                                                                                                                i = (struct Struct_2_t *)result;
                                                                                                                                                                *result = 0x10C08349;
                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                ptr = *a1;
                                                                                                                                                                result = (__int64 *)ptr;
                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                if (result <= 3) {
                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                    sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                    ptr = *a1;
                                                                                                                                                                    i4 = a1[2];
                                                                                                                                                                }
                                                                                                                                                                i3 = (__int64 *)arg_8;
                                                                                                                                                                result = i->field_0;
                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)i4) = result;
                                                                                                                                                                i4 += 4;
                                                                                                                                                                a1[2] = i4;
                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                ptr = (struct Struct_3_t *)((__int64)ptr - (__int64)i4);
                                                                                                                                                                if (ptr <= 2) {
                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                    i3 = (__int64 *)v_40;
                                                                                                                                                                    sub_1400F2D20(i3, i4, 3, 1);
                                                                                                                                                                    result = i3;
                                                                                                                                                                    i3 = (__int64 *)arg_8;
                                                                                                                                                                    i4 = (__int64 *)arg_10;
                                                                                                                                                                    *(__int64 *)((__int64)i3 + (__int64)i4 + 2) = 201;
                                                                                                                                                                    *(__int64 *)((__int64)i3 + (__int64)i4) = 0xFF49;
                                                                                                                                                                    ptr2 = i4 + 3;
                                                                                                                                                                    arg_10 = (__int64)ptr2;
                                                                                                                                                                    result = i2 + 104;
                                                                                                                                                                    *dst = result;
                                                                                                                                                                    i4 += 8;
                                                                                                                                                                    if (!((i4 < 0))) {
                                                                                                                                                                        a1 = (size_t *)v_158;
                                                                                                                                                                        a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                        result = (__int64 *)a1;
                                                                                                                                                                        if (a1 == a1) {
                                                                                                                                                                            ptr = (struct Struct_3_t *)a1;
                                                                                                                                                                            sub_14002EDF0(0, 5);
                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                i = (struct Struct_2_t *)result;
                                                                                                                                                                                *result = 233;
                                                                                                                                                                                arg_1 = (__int64)ptr;
                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                result = *a1;
                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                if (result <= 4) {
                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                    sub_1400F2D20(a1, ptr2, 5, 1);
                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                    i3 = (__int64 *)arg_8;
                                                                                                                                                                                    ptr2 = a1[2];
                                                                                                                                                                                }
                                                                                                                                                                                result = i->field_4;
                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)ptr2 + 4) = result;
                                                                                                                                                                                result = i->field_0;
                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                ptr2 += 5;
                                                                                                                                                                                a1[2] = ptr2;
                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                                a2 = (size_t *)dst2;
                                                                                                                                                                                a2 += 9;
                                                                                                                                                                                if (!((a2 < 0))) {
                                                                                                                                                                                    result = (__int64 *)ptr2;
                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                                                                    if (result == result) {
                                                                                                                                                                                        if (ptr2 < a2) {
                                                                                                                                                                                            return (__int64)a1;
                                                                                                                                                                                        }
                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)dst2 + 5) = result;
                                                                                                                                                                                        sub_14002EDF0(0, 5);
                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                            i = (struct Struct_2_t *)result;
                                                                                                                                                                                            *result = 233;
                                                                                                                                                                                            arg_1 = 16;
                                                                                                                                                                                            i4 = (__int64 *)v_40;
                                                                                                                                                                                            ptr = *i4;
                                                                                                                                                                                            result = (__int64 *)ptr;
                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                            if (result <= 4) {
                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                sub_1400F2D20(a1, ptr2, 5, 1);
                                                                                                                                                                                                i4 = (__int64 *)v_40;
                                                                                                                                                                                                ptr = *i4;
                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                            }
                                                                                                                                                                                            i3 = (__int64 *)arg_8;
                                                                                                                                                                                            result = i->field_4;
                                                                                                                                                                                            *(__int64 *)((__int64)i3 + (__int64)ptr2 + 4) = result;
                                                                                                                                                                                            result = i->field_0;
                                                                                                                                                                                            *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                            ptr2 += 5;
                                                                                                                                                                                            arg_10 = (__int64)ptr2;
                                                                                                                                                                                            off_140108030();
                                                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                                                            ptr = (struct Struct_3_t *)((__int64)ptr - (__int64)ptr2);
                                                                                                                                                                                            a3 = (size_t *)ptr2;
                                                                                                                                                                                            if (ptr <= 15) {
                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                sub_1400F2D20(i4, ptr2, 16, 1);
                                                                                                                                                                                                i3 = (__int64 *)arg_8;
                                                                                                                                                                                                a3 = (size_t *)arg_10;
                                                                                                                                                                                            }
                                                                                                                                                                                            result = (__int64 *)v_148;
                                                                                                                                                                                            xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                                                                                                                                            _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3), xmm0);
                                                                                                                                                                                            a3 += 16;
                                                                                                                                                                                            arg_10 = (__int64)a3;
                                                                                                                                                                                            i2 += 107;
                                                                                                                                                                                            *dst = i2;
                                                                                                                                                                                            a1 = (size_t *)v_150;
                                                                                                                                                                                            a2 = a1;
                                                                                                                                                                                            a2 += 11;
                                                                                                                                                                                            if (!((a2 < 0))) {
                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)((__int64)ptr2 - (__int64)a2);
                                                                                                                                                                                                result = (__int64 *)ptr2;
                                                                                                                                                                                                if (ptr2 == ptr2) {
                                                                                                                                                                                                    if (a2 > a3) {
                                                                                                                                                                                                        return (__int64)result;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    *(__int64 *)((__int64)i3 + (__int64)a1 + 7) = ptr2;
                                                                                                                                                                                                    sub_14002EDF0(0, 8, a3);
                                                                                                                                                                                                    i = (struct Struct_2_t *)result;
                                                                                                                                                                                                    *result = 0x24448B4C;
                                                                                                                                                                                                    ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                                                    i->field_4 = 56;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                    if (result <= 4) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                                                                                                        ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                                                    a1 = i->field_4;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                    a1 = i->field_0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                    a2 += 5;
                                                                                                                                                                                                    ptr->field_10 = a2;
                                                                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                    i3 = *dst;
                                                                                                                                                                                                    result = i3 + 1;
                                                                                                                                                                                                    *dst = result;
                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                    i = (struct Struct_2_t *)result;
                                                                                                                                                                                                    *result = 0x244C8B4C;
                                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                                                    i->field_4 = 64;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                    if (result <= 4) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                                                                                                        ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                                                    a1 = i->field_4;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                    a1 = i->field_0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                    a2 += 5;
                                                                                                                                                                                                    ptr->field_10 = a2;
                                                                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                    a3 = (size_t *)v_40;
                                                                                                                                                                                                    ptr2 = a3[2];
                                                                                                                                                                                                    result = i3 + 2;
                                                                                                                                                                                                    *dst = result;
                                                                                                                                                                                                    if (ptr2 == *a3) {
                                                                                                                                                                                                        sub_1400F3510(a3, a2, a3);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2) = 77;
                                                                                                                                                                                                    result = ptr2 + 1;
                                                                                                                                                                                                    a3[2] = result;
                                                                                                                                                                                                    if (result == *a3) {
                                                                                                                                                                                                        sub_1400F3510(a3, a2, a3);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2 + 1) = 49;
                                                                                                                                                                                                    result = ptr2 + 2;
                                                                                                                                                                                                    a3[2] = result;
                                                                                                                                                                                                    if (result == *a3) {
                                                                                                                                                                                                        sub_1400F3510(a3, a2, a3);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 210;
                                                                                                                                                                                                    i4 = ptr2 + 3;
                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 7, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i4 + 3) = 0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i4) = 0x358D48;
                                                                                                                                                                                                    dst2 = i4 + 7;
                                                                                                                                                                                                    a3[2] = dst2;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst2, 7, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst2 = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2 + 3) = 0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2) = 0x3D8D48;
                                                                                                                                                                                                    dst2 += 7;
                                                                                                                                                                                                    a3[2] = dst2;
                                                                                                                                                                                                    result = i3 + 5;
                                                                                                                                                                                                    *dst = result;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                    i2 = dst2;
                                                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        i2 = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i2 + 2) = 201;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i2) = 0x854D;
                                                                                                                                                                                                    dst = i2 + 3;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 5) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 6, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 4) = 0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x840F;
                                                                                                                                                                                                    dst += 6;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 3) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 4, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0xB60F41;
                                                                                                                                                                                                    dst += 4;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 4) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 5, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 4) = 23;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x1CB60F42;
                                                                                                                                                                                                    result = dst + 5;
                                                                                                                                                                                                    a3[2] = result;
                                                                                                                                                                                                    a1 = i3 + 9;
                                                                                                                                                                                                    a2 = (size_t *)v_50;
                                                                                                                                                                                                    *a2 = a1;
                                                                                                                                                                                                    if (result == *a3) {
                                                                                                                                                                                                        sub_1400F3510(a3, a2, a3);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 5) = 49;
                                                                                                                                                                                                    result = dst + 6;
                                                                                                                                                                                                    a3[2] = result;
                                                                                                                                                                                                    if (result == *a3) {
                                                                                                                                                                                                        sub_1400F3510(a3, a2, a3);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 6) = 216;
                                                                                                                                                                                                    dst += 7;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 3, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 2) = 0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x8841;
                                                                                                                                                                                                    dst += 3;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 3, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 2) = 194;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x3041;
                                                                                                                                                                                                    dst += 3;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 4) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 5, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 4) = 22;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x14B60F4E;
                                                                                                                                                                                                    dst += 5;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = i3 + 13;
                                                                                                                                                                                                    a1 = (size_t *)v_50;
                                                                                                                                                                                                    *a1 = result;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 3, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 2) = 192;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0xFF49;
                                                                                                                                                                                                    dst += 3;
                                                                                                                                                                                                    a3[2] = dst;
                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 3, 1);
                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                        dst = a3[2];
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 2) = 201;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0xFF49;
                                                                                                                                                                                                    result = dst + 3;
                                                                                                                                                                                                    a3[2] = result;
                                                                                                                                                                                                    dst += 8;
                                                                                                                                                                                                    if (!((dst < 0))) {
                                                                                                                                                                                                        dst2 = (__int64 *)((__int64)dst2 - (__int64)dst);
                                                                                                                                                                                                        result = dst2;
                                                                                                                                                                                                        if (dst2 == dst2) {
                                                                                                                                                                                                            sub_14002EDF0(0, 5, a3);
                                                                                                                                                                                                            ptr = (struct Struct_3_t *)v_50;
                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                *result = 233;
                                                                                                                                                                                                                arg_1 = (__int64)dst2;
                                                                                                                                                                                                                a3 = (size_t *)v_40;
                                                                                                                                                                                                                result = *a3;
                                                                                                                                                                                                                a2 = a3[2];
                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                if (result <= 4) {
                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                    sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                                                                                                                    a3 = (size_t *)v_40;
                                                                                                                                                                                                                    a2 = a3[2];
                                                                                                                                                                                                                }
                                                                                                                                                                                                                result = (__int64 *)arg_8;
                                                                                                                                                                                                                a1 = i->field_4;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                                a1 = i->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                a2 += 5;
                                                                                                                                                                                                                a3[2] = a2;
                                                                                                                                                                                                                dst2 = (__int64 *)a3;
                                                                                                                                                                                                                off_140108030(a1, a2, a3);
                                                                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                                                                result = i3 + 16;
                                                                                                                                                                                                                *(__int64 *)ptr = (__int64)(result);
                                                                                                                                                                                                                a2 = (size_t *)i2;
                                                                                                                                                                                                                a2 += 9;
                                                                                                                                                                                                                if (!((a2 < 0))) {
                                                                                                                                                                                                                    a3 = (size_t *)arg_10;
                                                                                                                                                                                                                    result = (__int64 *)a3;
                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                                                                                                    if (result == result) {
                                                                                                                                                                                                                        if (a3 < a2) {
                                                                                                                                                                                                                            return (__int64)a1;
                                                                                                                                                                                                                        }
                                                                                                                                                                                                                        a1 = (size_t *)arg_8;
                                                                                                                                                                                                                        *(__int64 *)((__int64)a1 + (__int64)i2 + 5) = result;
                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)dst2;
                                                                                                                                                                                                                        sub_14002EDF0(0, 5, a3);
                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                            i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                            *result = 233;
                                                                                                                                                                                                                            arg_1 = 512;
                                                                                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                            if (result <= 4) {
                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                                                                                                                                a3 = (size_t *)v_40;
                                                                                                                                                                                                                                a2 = a3[2];
                                                                                                                                                                                                                            }
                                                                                                                                                                                                                            result = (__int64 *)arg_8;
                                                                                                                                                                                                                            a1 = i->field_4;
                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                                            a1 = i->field_0;
                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                            a2 += 5;
                                                                                                                                                                                                                            a3[2] = a2;
                                                                                                                                                                                                                            off_140108030(a1, a2, ptr);
                                                                                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                            result = *a1;
                                                                                                                                                                                                                            dst2 = a1[2];
                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                            i2 = dst2;
                                                                                                                                                                                                                            if (result <= 255) {
                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                sub_1400F2D20(a1, dst2, 256, 1);
                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                i2 = a1[2];
                                                                                                                                                                                                                            }
                                                                                                                                                                                                                            result = (__int64 *)v_70;
                                                                                                                                                                                                                            dst = result + 345;
                                                                                                                                                                                                                            a1 = (size_t *)arg_8;
                                                                                                                                                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)i2);
                                                                                                                                                                                                                            a2 = (size_t *)v_140;
                                                                                                                                                                                                                            sub_1400F27F0(a1, a2, 256);
                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                            i2 += 256;
                                                                                                                                                                                                                            a1[2] = i2;
                                                                                                                                                                                                                            result = *a1;
                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                                                                                                                                                            i = (struct Struct_2_t *)i2;
                                                                                                                                                                                                                            if (result <= 255) {
                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                sub_1400F2D20(a1, i2, 256, 1);
                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                i = a1[2];
                                                                                                                                                                                                                            }
                                                                                                                                                                                                                            a1 = (size_t *)arg_8;
                                                                                                                                                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)i);
                                                                                                                                                                                                                            sub_1400F27F0(a1, dst, 256);
                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                            i += 256;
                                                                                                                                                                                                                            a1[2] = i;
                                                                                                                                                                                                                            i3 += 19;
                                                                                                                                                                                                                            ptr = (struct Struct_3_t *)v_50;
                                                                                                                                                                                                                            *(__int64 *)ptr = (__int64)(i3);
                                                                                                                                                                                                                            a2 = (size_t *)ptr2;
                                                                                                                                                                                                                            a2 += 10;
                                                                                                                                                                                                                            if (!((a2 < 0))) {
                                                                                                                                                                                                                                dst2 = (__int64 *)((__int64)dst2 - (__int64)a2);
                                                                                                                                                                                                                                result = dst2;
                                                                                                                                                                                                                                if (dst2 == dst2) {
                                                                                                                                                                                                                                    if (a2 > i) {
                                                                                                                                                                                                                                        return (__int64)result;
                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2 + 6) = dst2;
                                                                                                                                                                                                                                    a2 = (size_t *)i4;
                                                                                                                                                                                                                                    a2 += 14;
                                                                                                                                                                                                                                    if (!((a2 < 0))) {
                                                                                                                                                                                                                                        i2 = (__int64 *)((__int64)i2 - (__int64)a2);
                                                                                                                                                                                                                                        result = i2;
                                                                                                                                                                                                                                        if (i2 == i2) {
                                                                                                                                                                                                                                            a3 = a1[2];
                                                                                                                                                                                                                                            if (a2 > a3) {
                                                                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                            result = (__int64 *)arg_8;
                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)i4 + 10) = i2;
                                                                                                                                                                                                                                            result = *a1;
                                                                                                                                                                                                                                            i3 = a1[2];
                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)i3);
                                                                                                                                                                                                                                            i4 = i3;
                                                                                                                                                                                                                                            if (result <= 6) {
                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                sub_1400F2D20(a1, i3, 7, 1);
                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                i4 = a1[2];
                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                            v_68 = (__int64)i3;
                                                                                                                                                                                                                                            result = (__int64 *)v_70;
                                                                                                                                                                                                                                            result += 601;
                                                                                                                                                                                                                                            v_100 = (__int64)result;
                                                                                                                                                                                                                                            dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                            *(__int64 *)((__int64)dst2 + (__int64)i4 + 3) = 0;
                                                                                                                                                                                                                                            *(__int64 *)((__int64)dst2 + (__int64)i4) = 0x358D48;
                                                                                                                                                                                                                                            i4 += 7;
                                                                                                                                                                                                                                            a1[2] = i4;
                                                                                                                                                                                                                                            i2 = ptr->field_0;
                                                                                                                                                                                                                                            ++i2;
                                                                                                                                                                                                                                            *(__int64 *)ptr = (__int64)(i2);
                                                                                                                                                                                                                                            i3 = 272;
                                                                                                                                                                                                                                            ptr2 = 1;
                                                                                                                                                                                                                                            do {
                                                                                                                                                                                                                                                sub_14002EDF0(0, 8, a3);
                                                                                                                                                                                                                                                a4 = i3 - 272;
                                                                                                                                                                                                                                                v_80 = 8;
                                                                                                                                                                                                                                                v_88 = (__int64)result;
                                                                                                                                                                                                                                                *result = 0x8B48;
                                                                                                                                                                                                                                                v_90 = 2;
                                                                                                                                                                                                                                                a1 = rsp + 128;
                                                                                                                                                                                                                                                sub_1400D4F50(a1, 0, 6, a4);
                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)v_80;
                                                                                                                                                                                                                                                dst = (__int64 *)v_88;
                                                                                                                                                                                                                                                i = (struct Struct_2_t *)v_90;
                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                result = *a1;
                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                                                                if (i > result) {
                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                    dst2 = (__int64 *)a1;
                                                                                                                                                                                                                                                    sub_1400F2D20(a1, i4, i, 1);
                                                                                                                                                                                                                                                    result = dst2;
                                                                                                                                                                                                                                                    dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                    i4 = (__int64 *)arg_10;
                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                dst2 = (__int64 *)((__int64)dst2 + (__int64)i4);
                                                                                                                                                                                                                                                sub_1400F27F0(dst2, dst, i);
                                                                                                                                                                                                                                                i4 = (__int64 *)((__int64)i4 + (__int64)i);
                                                                                                                                                                                                                                                a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                a3[2] = i4;
                                                                                                                                                                                                                                                if (ptr == 0) {
                                                                                                                                                                                                                                                    result = i2 + 1;
                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)v_50;
                                                                                                                                                                                                                                                    *(__int64 *)i = (__int64)(result);
                                                                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                                                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                                                                                                    if (a1 < 3) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 3, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4 + 2) = 134;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = 0x3348;
                                                                                                                                                                                                                                                    i4 += 3;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    a2 = (size_t *)result;
                                                                                                                                                                                                                                                    a2 = (size_t *)((__int64)a2 - (__int64)i4);
                                                                                                                                                                                                                                                    if (a2 <= 3) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                        a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    a2 = i3 - 240;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = a2;
                                                                                                                                                                                                                                                    i4 += 4;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 3, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4 + 2) = 134;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = 0x3348;
                                                                                                                                                                                                                                                    i4 += 3;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                                                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                                                                                                    if (a1 <= 3) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    a2 = i3 - 208;
                                                                                                                                                                                                                                                    a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = a2;
                                                                                                                                                                                                                                                    i4 += 4;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    a2 = i2 + 3;
                                                                                                                                                                                                                                                    *(__int64 *)i = (__int64)(a2);
                                                                                                                                                                                                                                                    a2 = (size_t *)result;
                                                                                                                                                                                                                                                    a2 = (size_t *)((__int64)a2 - (__int64)i4);
                                                                                                                                                                                                                                                    if (a2 <= 2) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 3, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                        a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4 + 2) = 134;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = 0x3348;
                                                                                                                                                                                                                                                    i4 += 3;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                                                                    if (result <= 3) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    result = i3 - 176;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = result;
                                                                                                                                                                                                                                                    i4 += 4;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    result = *a3;
                                                                                                                                                                                                                                                    if (v_78 == 0) {
                                                                                                                                                                                                                                                        i2 += 4;
                                                                                                                                                                                                                                                        a1 = (size_t *)result;
                                                                                                                                                                                                                                                        a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                                                                                                        if (a1 <= 3) {
                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                            sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                            a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                            result = *a3;
                                                                                                                                                                                                                                                            i4 = a3[2];
                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                        dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                        *(__int64 *)((__int64)dst2 + (__int64)i4) = 0x24843348;
                                                                                                                                                                                                                                                        i4 += 4;
                                                                                                                                                                                                                                                        a3[2] = i4;
                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)ptr2;
                                                                                                                                                                                                                                                        if (result <= 3) {
                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                            sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                            a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                            dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                            i4 = a3[2];
                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                        result = i3 + 168;
                                                                                                                                                                                                                                                        *(__int64 *)((__int64)dst2 + (__int64)i4) = result;
                                                                                                                                                                                                                                                        i4 += 4;
                                                                                                                                                                                                                                                        a3[2] = i4;
                                                                                                                                                                                                                                                        v_60 = (__int64)i2;
                                                                                                                                                                                                                                                        result = i2 + 1;
                                                                                                                                                                                                                                                        *(__int64 *)i = (__int64)(result);
                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)a3;
                                                                                                                                                                                                                                                        sub_14002EDF0(0, 8, a3);
                                                                                                                                                                                                                                                        a4 = i3 - 56;
                                                                                                                                                                                                                                                        v_80 = 8;
                                                                                                                                                                                                                                                        v_88 = (__int64)result;
                                                                                                                                                                                                                                                        *result = 0x8948;
                                                                                                                                                                                                                                                        v_90 = 2;
                                                                                                                                                                                                                                                        a1 = rsp + 128;
                                                                                                                                                                                                                                                        sub_1400D4F50(a1, 0, 4, a4);
                                                                                                                                                                                                                                                        i2 = (__int64 *)v_80;
                                                                                                                                                                                                                                                        dst = (__int64 *)v_88;
                                                                                                                                                                                                                                                        i = (struct Struct_2_t *)v_90;
                                                                                                                                                                                                                                                        result = ptr2->field_0;
                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                                                                        if (i > result) {
                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                            sub_1400F2D20(ptr2, i4, i, 1);
                                                                                                                                                                                                                                                            dst2 = ptr2->field_8;
                                                                                                                                                                                                                                                            i4 = ptr2->field_10;
                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                        a1 = (__int64)i4 + (__int64)dst2;
                                                                                                                                                                                                                                                        sub_1400F27F0(a1, dst, i);
                                                                                                                                                                                                                                                        i4 = (__int64 *)((__int64)i4 + (__int64)i);
                                                                                                                                                                                                                                                        result = (__int64 *)v_40;
                                                                                                                                                                                                                                                        arg_10 = (__int64)i4;
                                                                                                                                                                                                                                                        if (i2 == 0) {
                                                                                                                                                                                                                                                            result = (__int64 *)v_60;
                                                                                                                                                                                                                                                            i2 = result + 2;
                                                                                                                                                                                                                                                            dst = (__int64 *)v_50;
                                                                                                                                                                                                                                                            *dst = i2;
                                                                                                                                                                                                                                                            i3 += 8;
                                                                                                                                                                                                                                                            result = ptr + 1;
                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)result;
                                                                                                                                                                                                                                                            sub_14002EDF0(0, 5, a3);
                                                                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                                                                i2 = result;
                                                                                                                                                                                                                                                                *result = 233;
                                                                                                                                                                                                                                                                arg_1 = 128;
                                                                                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                i = ptr2->field_0;
                                                                                                                                                                                                                                                                result = (__int64 *)i;
                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)i4);
                                                                                                                                                                                                                                                                if (result <= 4) {
                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, i4, 5, 1);
                                                                                                                                                                                                                                                                    ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                    i = ptr2->field_0;
                                                                                                                                                                                                                                                                    i4 = ptr2->field_10;
                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                i3 = ptr2->field_8;
                                                                                                                                                                                                                                                                result = (__int64 *)arg_4;
                                                                                                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)i4 + 4) = result;
                                                                                                                                                                                                                                                                result = *i2;
                                                                                                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)i4) = result;
                                                                                                                                                                                                                                                                i4 += 5;
                                                                                                                                                                                                                                                                ptr2->field_10 = i4;
                                                                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                                                                off_140108038(result, 0, i2);
                                                                                                                                                                                                                                                                result = (__int64 *)v_100;
                                                                                                                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                                                                                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_90, xmm1);
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_80, xmm0);
                                                                                                                                                                                                                                                                result = (__int64 *)v_70;
                                                                                                                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)(result + 633));
                                                                                                                                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)(result + 649));
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_b0, xmm1);
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_a0, xmm0);
                                                                                                                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)(result + 665));
                                                                                                                                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)(result + 681));
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_d0, xmm1);
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_c0, xmm0);
                                                                                                                                                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)(result + 697));
                                                                                                                                                                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)(result + 713));
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_e0, xmm0);
                                                                                                                                                                                                                                                                _mm_store_si128((__m128i *)&v_f0, xmm1);
                                                                                                                                                                                                                                                                i = (struct Struct_2_t *)((__int64)i - (__int64)i4);
                                                                                                                                                                                                                                                                a3 = (size_t *)i4;
                                                                                                                                                                                                                                                                if (i < 128) {
                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                    sub_1400F2D20(ptr2, i4, 128, 1);
                                                                                                                                                                                                                                                                    i3 = ptr2->field_8;
                                                                                                                                                                                                                                                                    a3 = ptr2->field_10;
                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_f0);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 112), xmm0);
                                                                                                                                                                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_e0);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 96), xmm0);
                                                                                                                                                                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 80), xmm0);
                                                                                                                                                                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_c0);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 64), xmm0);
                                                                                                                                                                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_80);
                                                                                                                                                                                                                                                                xmm1 = _mm_load_si128((__m128i *)&v_90);
                                                                                                                                                                                                                                                                xmm2 = _mm_load_si128((__m128i *)&v_a0);
                                                                                                                                                                                                                                                                xmm3 = _mm_load_si128((__m128i *)&v_b0);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 48), xmm3);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 32), xmm2);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3 + 16), xmm1);
                                                                                                                                                                                                                                                                _mm_storeu_si128((__m128i *)((__int64)i3 + (__int64)a3), xmm0);
                                                                                                                                                                                                                                                                a3 += 128;
                                                                                                                                                                                                                                                                ptr2->field_10 = a3;
                                                                                                                                                                                                                                                                result = (__int64 *)v_60;
                                                                                                                                                                                                                                                                result += 4;
                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                a1 = (size_t *)v_68;
                                                                                                                                                                                                                                                                a2 = a1;
                                                                                                                                                                                                                                                                a2 += 7;
                                                                                                                                                                                                                                                                if (!((a2 < 0))) {
                                                                                                                                                                                                                                                                    i4 = (__int64 *)((__int64)i4 - (__int64)a2);
                                                                                                                                                                                                                                                                    result = i4;
                                                                                                                                                                                                                                                                    if (i4 == i4) {
                                                                                                                                                                                                                                                                        if (a2 > a3) {
                                                                                                                                                                                                                                                                            return (__int64)result;
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)a1 + 3) = i4;
                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 8, a3);
                                                                                                                                                                                                                                                                        i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                        *result = 0x24648B4C;
                                                                                                                                                                                                                                                                        arg_4 = 56;
                                                                                                                                                                                                                                                                        dst2 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                        result = *dst2;
                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                            sub_1400F2D20(a1, ptr2, 5, 1);
                                                                                                                                                                                                                                                                            dst2 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        i3 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                        result = i->field_4;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)ptr2 + 4) = result;
                                                                                                                                                                                                                                                                        result = i->field_0;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                        ptr2 += 5;
                                                                                                                                                                                                                                                                        arg_10 = (__int64)ptr2;
                                                                                                                                                                                                                                                                        off_140108030();
                                                                                                                                                                                                                                                                        off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                        i2 = *dst;
                                                                                                                                                                                                                                                                        result = i2 + 1;
                                                                                                                                                                                                                                                                        *dst = result;
                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                        i4 = result;
                                                                                                                                                                                                                                                                        *result = 0x246C8B4C;
                                                                                                                                                                                                                                                                        arg_4 = 64;
                                                                                                                                                                                                                                                                        ptr = *dst2;
                                                                                                                                                                                                                                                                        result = (__int64 *)ptr;
                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                            sub_1400F2D20(a1, ptr2, 5, 1);
                                                                                                                                                                                                                                                                            dst2 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                            ptr = *dst2;
                                                                                                                                                                                                                                                                            i3 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (__int64 *)arg_4;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)ptr2 + 4) = result;
                                                                                                                                                                                                                                                                        result = *i4;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                        ptr2 += 5;
                                                                                                                                                                                                                                                                        arg_10 = (__int64)ptr2;
                                                                                                                                                                                                                                                                        off_140108030();
                                                                                                                                                                                                                                                                        off_140108038(result, 0, i4);
                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                            *result = 0x84C7;
                                                                                                                                                                                                                                                                            arg_2 = 36;
                                                                                                                                                                                                                                                                            result = 0x6170786500000088;
                                                                                                                                                                                                                                                                            i->field_3 = result;
                                                                                                                                                                                                                                                                            ptr = (struct Struct_3_t *)((__int64)ptr - (__int64)ptr2);
                                                                                                                                                                                                                                                                            if (ptr <= 10) {
                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                sub_1400F2D20(i3, ptr2, 11, 1);
                                                                                                                                                                                                                                                                                a1 = (size_t *)i3;
                                                                                                                                                                                                                                                                                i3 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                                ptr2 = a1[2];
                                                                                                                                                                                                                                                                                result = i->field_7;
                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)ptr2 + 7) = result;
                                                                                                                                                                                                                                                                                result = i->field_0;
                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                ptr2 += 11;
                                                                                                                                                                                                                                                                                a1[2] = ptr2;
                                                                                                                                                                                                                                                                                i3 = (__int64 *)a1;
                                                                                                                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                result = i2 + 3;
                                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                    *result = 0x84C7;
                                                                                                                                                                                                                                                                                    arg_2 = 36;
                                                                                                                                                                                                                                                                                    i->field_3 = result;
                                                                                                                                                                                                                                                                                    result = *i3;
                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                    if (result <= 10) {
                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, ptr2, 11, 1);
                                                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                        ptr2 = ptr->field_10;
                                                                                                                                                                                                                                                                                        i3 = ptr->field_8;
                                                                                                                                                                                                                                                                                        result = i->field_7;
                                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)ptr2 + 7) = result;
                                                                                                                                                                                                                                                                                        result = i->field_0;
                                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                        ptr2 += 11;
                                                                                                                                                                                                                                                                                        ptr->field_10 = ptr2;
                                                                                                                                                                                                                                                                                        off_140108030(0x3320646E0000008C);
                                                                                                                                                                                                                                                                                        off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                                                                            i4 = result;
                                                                                                                                                                                                                                                                                            *result = 0x84C7;
                                                                                                                                                                                                                                                                                            arg_2 = 36;
                                                                                                                                                                                                                                                                                            arg_3 = (__int64)result;
                                                                                                                                                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                            if (result <= 10) {
                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, ptr2, 11, 1);
                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                i3 = ptr->field_8;
                                                                                                                                                                                                                                                                                                ptr2 = ptr->field_10;
                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                            result = (__int64 *)arg_7;
                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)i3 + (__int64)ptr2 + 7) = result;
                                                                                                                                                                                                                                                                                            result = *i4;
                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                            ptr2 += 11;
                                                                                                                                                                                                                                                                                            ptr->field_10 = ptr2;
                                                                                                                                                                                                                                                                                            off_140108030(0x79622D3200000090);
                                                                                                                                                                                                                                                                                            off_140108038(result, 0, i4);
                                                                                                                                                                                                                                                                                            sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                                                                                                i4 = result;
                                                                                                                                                                                                                                                                                                *result = 0x84C7;
                                                                                                                                                                                                                                                                                                arg_2 = 36;
                                                                                                                                                                                                                                                                                                arg_3 = (__int64)result;
                                                                                                                                                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                if (result <= 10) {
                                                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, ptr2, 11, 1);
                                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                    i3 = ptr->field_8;
                                                                                                                                                                                                                                                                                                    ptr2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                result = (__int64 *)arg_7;
                                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)ptr2 + 7) = result;
                                                                                                                                                                                                                                                                                                result = *i4;
                                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)i3 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                                ptr2 += 11;
                                                                                                                                                                                                                                                                                                ptr->field_10 = ptr2;
                                                                                                                                                                                                                                                                                                off_140108030(0x6B20657400000094);
                                                                                                                                                                                                                                                                                                off_140108038(result, 0, i4);
                                                                                                                                                                                                                                                                                                result = i2 + 6;
                                                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                                                i2 += 13;
                                                                                                                                                                                                                                                                                                i4 = 152;
                                                                                                                                                                                                                                                                                                i3 = rsp + 128;
                                                                                                                                                                                                                                                                                                do {
                                                                                                                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                    a4 = i4 + 64;
                                                                                                                                                                                                                                                                                                    v_80 = 8;
                                                                                                                                                                                                                                                                                                    v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                    *result = 139;
                                                                                                                                                                                                                                                                                                    v_90 = 1;
                                                                                                                                                                                                                                                                                                    sub_1400D4F50(i3, 0, 4, a4);
                                                                                                                                                                                                                                                                                                    dst = (__int64 *)v_80;
                                                                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)v_88;
                                                                                                                                                                                                                                                                                                    dst2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                    i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                    result = *i3;
                                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                    if (dst2 > result) {
                                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, ptr2, dst2, 1);
                                                                                                                                                                                                                                                                                                        i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)arg_8;
                                                                                                                                                                                                                                                                                                    a1 = (__int64)ptr + (__int64)ptr2;
                                                                                                                                                                                                                                                                                                    sub_1400F27F0(a1, i, dst2);
                                                                                                                                                                                                                                                                                                    ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)dst2);
                                                                                                                                                                                                                                                                                                    arg_10 = (__int64)ptr2;
                                                                                                                                                                                                                                                                                                    if (dst == 0) {
                                                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                        i3 = rsp + 128;
                                                                                                                                                                                                                                                                                                        v_80 = 8;
                                                                                                                                                                                                                                                                                                        v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                        *result = 137;
                                                                                                                                                                                                                                                                                                        v_90 = 1;
                                                                                                                                                                                                                                                                                                        sub_1400D4F50(i3, 0, 4, i4);
                                                                                                                                                                                                                                                                                                        dst = (__int64 *)v_80;
                                                                                                                                                                                                                                                                                                        dst2 = (__int64 *)v_88;
                                                                                                                                                                                                                                                                                                        i = (struct Struct_2_t *)v_90;
                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                        result = *a1;
                                                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                        if (i > result) {
                                                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                                                            ptr = (struct Struct_3_t *)a1;
                                                                                                                                                                                                                                                                                                            sub_1400F2D20(a1, ptr2, i, 1);
                                                                                                                                                                                                                                                                                                            result = (__int64 *)ptr;
                                                                                                                                                                                                                                                                                                            ptr = ptr->field_8;
                                                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                        a1 = (__int64)ptr + (__int64)ptr2;
                                                                                                                                                                                                                                                                                                        sub_1400F27F0(a1, dst2, i);
                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)i);
                                                                                                                                                                                                                                                                                                        result = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                        arg_10 = (__int64)ptr2;
                                                                                                                                                                                                                                                                                                        if (dst == 0) {
                                                                                                                                                                                                                                                                                                            result = i2 - 5;
                                                                                                                                                                                                                                                                                                            a1 = (size_t *)v_50;
                                                                                                                                                                                                                                                                                                            *a1 = result;
                                                                                                                                                                                                                                                                                                            i2 += 2;
                                                                                                                                                                                                                                                                                                            i4 += 4;
                                                                                                                                                                                                                                                                                                            sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                                                                                                                i4 = result;
                                                                                                                                                                                                                                                                                                                *result = 0x84C7;
                                                                                                                                                                                                                                                                                                                arg_2 = 36;
                                                                                                                                                                                                                                                                                                                arg_3 = 184;
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                result = *a1;
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                if (result <= 10) {
                                                                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, ptr2, 11, 1);
                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)arg_8;
                                                                                                                                                                                                                                                                                                                    ptr2 = a1[2];
                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                result = (__int64 *)arg_7;
                                                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr2 + 7) = result;
                                                                                                                                                                                                                                                                                                                result = *i4;
                                                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                                                ptr2 += 11;
                                                                                                                                                                                                                                                                                                                a1[2] = ptr2;
                                                                                                                                                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                                                                                                                                                off_140108038(result, 0, i4);
                                                                                                                                                                                                                                                                                                                a2 = (size_t *)v_70;
                                                                                                                                                                                                                                                                                                                result = a2[9];
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)result ^ 0xCBF29CE4);
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)(__int64)result * 0x1000193);
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[9];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[10];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[10];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[10];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                a1 = a2[10];
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                ptr = (__int64)(__int64)a1 * 0x1000193;
                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)((__int64)(__int64)ptr | 1);
                                                                                                                                                                                                                                                                                                                result = (__int64 *)ptr;
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)result ^ 0xCBF29CE4);
                                                                                                                                                                                                                                                                                                                i = (__int64)(__int64)result * 0x1000193;
                                                                                                                                                                                                                                                                                                                i += 100;
                                                                                                                                                                                                                                                                                                                a2 = -12;
                                                                                                                                                                                                                                                                                                                v_60 = (__int64)i2;
                                                                                                                                                                                                                                                                                                                result = (__int64 *)i;
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)result >> 16);
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)i);
                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)(__int64)result * 0x85EBCA6B);
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)result;
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 13);
                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)a1 * 0xC2B2AE35;
                                                                                                                                                                                                                                                                                                                i3 = result;
                                                                                                                                                                                                                                                                                                                i3 = (__int64 *)((__int64)(__int64)i3 >> 16);
                                                                                                                                                                                                                                                                                                                i3 = (__int64 *)((__int64)(__int64)i3 ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                result = (__int64 *)v_70;
                                                                                                                                                                                                                                                                                                                i4 = *(__int64 *)((__int64)result + (__int64)a2 + 84);
                                                                                                                                                                                                                                                                                                                i4 = (__int64 *)((__int64)(__int64)i4 ^ (__int64)i3);
                                                                                                                                                                                                                                                                                                                i2 = (__int64 *)a2;
                                                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                                                while (result != 0) {
                                                                                                                                                                                                                                                                                                                    v_68 = (__int64)i2;
                                                                                                                                                                                                                                                                                                                    dst2 = i2 + 200;
                                                                                                                                                                                                                                                                                                                    v_80 = 11;
                                                                                                                                                                                                                                                                                                                    v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                    *result = 199;
                                                                                                                                                                                                                                                                                                                    v_90 = 1;
                                                                                                                                                                                                                                                                                                                    a1 = rsp + 128;
                                                                                                                                                                                                                                                                                                                    sub_1400D4F50(a1, 0, 4, dst2);
                                                                                                                                                                                                                                                                                                                    i2 = (__int64 *)v_80;
                                                                                                                                                                                                                                                                                                                    dst = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                    result = i2;
                                                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                                                                                                                    v_78 = (__int64)i;
                                                                                                                                                                                                                                                                                                                    if (result <= 3) {
                                                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                                                        a1 = rsp + 128;
                                                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 4, 1);
                                                                                                                                                                                                                                                                                                                        i2 = (__int64 *)v_80;
                                                                                                                                                                                                                                                                                                                        dst = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)v_88;
                                                                                                                                                                                                                                                                                                                    *(__int64 *)((__int64)i + (__int64)dst) = i4;
                                                                                                                                                                                                                                                                                                                    dst += 4;
                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                    result = *a1;
                                                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                    v_100 = (__int64)dst2;
                                                                                                                                                                                                                                                                                                                    if (dst > result) {
                                                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, ptr2, dst, 1);
                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                        ptr2 = a1[2];
                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                    dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                                                                    a1 = (__int64)ptr2 + (__int64)dst2;
                                                                                                                                                                                                                                                                                                                    sub_1400F27F0(a1, i, dst);
                                                                                                                                                                                                                                                                                                                    a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                    ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)dst);
                                                                                                                                                                                                                                                                                                                    a3[2] = ptr2;
                                                                                                                                                                                                                                                                                                                    if (i2 == 0) {
                                                                                                                                                                                                                                                                                                                        result = (__int64 *)v_60;
                                                                                                                                                                                                                                                                                                                        result -= 5;
                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_50;
                                                                                                                                                                                                                                                                                                                        *a1 = result;
                                                                                                                                                                                                                                                                                                                        dst = (__int64)(__int64)ptr * 0x1000193;
                                                                                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)((__int64)(__int64)ptr >> 17);
                                                                                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)((__int64)(__int64)ptr ^ (__int64)dst);
                                                                                                                                                                                                                                                                                                                        result = (__int64)(__int64)ptr * 0x38E38E39;
                                                                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)(__int64)result >> 33);
                                                                                                                                                                                                                                                                                                                        result += (__int64)(__int64)result*8;
                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)ptr;
                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                                                                                                                                                                                                                                                        result = &off_14011D2B0;
                                                                                                                                                                                                                                                                                                                        a2 = *(__int64 *)((__int64)a1 + (__int64)result);
                                                                                                                                                                                                                                                                                                                        i = *(__int64 *)((__int64)a1 + (__int64)result + 8);
                                                                                                                                                                                                                                                                                                                        i4 = *a3;
                                                                                                                                                                                                                                                                                                                        result = i4;
                                                                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                        if (i > result) {
                                                                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                                                                            i2 = (__int64 *)a3;
                                                                                                                                                                                                                                                                                                                            i4 = (__int64 *)a2;
                                                                                                                                                                                                                                                                                                                            sub_1400F2D20(a3, ptr2, i, 1);
                                                                                                                                                                                                                                                                                                                            a2 = (size_t *)i4;
                                                                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                                                                            i4 = *i2;
                                                                                                                                                                                                                                                                                                                            dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                        a1 = (__int64)ptr2 + (__int64)dst2;
                                                                                                                                                                                                                                                                                                                        sub_1400F27F0(a1, a2, i);
                                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)i);
                                                                                                                                                                                                                                                                                                                        result = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                                        arg_10 = (__int64)ptr2;
                                                                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                                                                                                            v_80 = 11;
                                                                                                                                                                                                                                                                                                                            v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                            *result = 129;
                                                                                                                                                                                                                                                                                                                            v_90 = 1;
                                                                                                                                                                                                                                                                                                                            a1 = rsp + 128;
                                                                                                                                                                                                                                                                                                                            a4 = (struct Struct_1_t *)v_100;
                                                                                                                                                                                                                                                                                                                            sub_1400D4F50(a1, 6, 4, a4);
                                                                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)v_80;
                                                                                                                                                                                                                                                                                                                            i2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                            result = (__int64 *)i;
                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                                                                                                                                                                                                                                                            v_118 = (__int64)dst;
                                                                                                                                                                                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                                                a1 = rsp + 128;
                                                                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, i2, 4, 1);
                                                                                                                                                                                                                                                                                                                                i = (struct Struct_2_t *)v_80;
                                                                                                                                                                                                                                                                                                                                i2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                            dst = (__int64 *)v_88;
                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)dst + (__int64)i2) = i3;
                                                                                                                                                                                                                                                                                                                            i2 += 4;
                                                                                                                                                                                                                                                                                                                            i4 = (__int64 *)((__int64)i4 - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                            if (i2 > i4) {
                                                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                                                i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                                                sub_1400F2D20(i3, ptr2, i2, 1);
                                                                                                                                                                                                                                                                                                                                dst2 = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                            dst2 = (__int64 *)((__int64)dst2 + (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                            sub_1400F27F0(dst2, dst, i2);
                                                                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)i2);
                                                                                                                                                                                                                                                                                                                            a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                            ((__int64 *)a4)[2] = (__int64)(ptr2);
                                                                                                                                                                                                                                                                                                                            if (i == 0) {
                                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)ptr * 0x1000193;
                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_118;
                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 17);
                                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)a1;
                                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)((__int64)(__int64)ptr ^ (__int64)result);
                                                                                                                                                                                                                                                                                                                                result = (__int64)(__int64)ptr * 0x38E38E39;
                                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)(__int64)result >> 33);
                                                                                                                                                                                                                                                                                                                                result += (__int64)(__int64)result*8;
                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)ptr;
                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                                                                                                                                                                                                                                                                result = &off_14011D2B0;
                                                                                                                                                                                                                                                                                                                                a2 = *(__int64 *)((__int64)a1 + (__int64)result);
                                                                                                                                                                                                                                                                                                                                i = *(__int64 *)((__int64)a1 + (__int64)result + 8);
                                                                                                                                                                                                                                                                                                                                result = a4->field_0;
                                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                                if (i > result) {
                                                                                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                    i3 = (__int64 *)a2;
                                                                                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, ptr2, i, 1);
                                                                                                                                                                                                                                                                                                                                    a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                    a2 = (size_t *)i3;
                                                                                                                                                                                                                                                                                                                                    ptr2 = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                dst2 = (__int64 *)v_50;
                                                                                                                                                                                                                                                                                                                                dst = (__int64 *)v_60;
                                                                                                                                                                                                                                                                                                                                i4 = a4->field_8;
                                                                                                                                                                                                                                                                                                                                a1 = (__int64)i4 + (__int64)ptr2;
                                                                                                                                                                                                                                                                                                                                i3 = (__int64 *)a4;
                                                                                                                                                                                                                                                                                                                                sub_1400F27F0(a1, a2, i, a4);
                                                                                                                                                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)((__int64)ptr2 + (__int64)i);
                                                                                                                                                                                                                                                                                                                                ((__int64 *)a4)[2] = (__int64)(ptr2);
                                                                                                                                                                                                                                                                                                                                result = dst - 2;
                                                                                                                                                                                                                                                                                                                                *dst2 = result;
                                                                                                                                                                                                                                                                                                                                i2 = dst + 4;
                                                                                                                                                                                                                                                                                                                                i = (struct Struct_2_t *)v_78;
                                                                                                                                                                                                                                                                                                                                ++i;
                                                                                                                                                                                                                                                                                                                                a2 = (size_t *)v_68;
                                                                                                                                                                                                                                                                                                                                a2 += 4;
                                                                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 6, a3, a4);
                                                                                                                                                                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                                                                    i3 = dst - 6;
                                                                                                                                                                                                                                                                                                                                    *result = 189;
                                                                                                                                                                                                                                                                                                                                    arg_1 = 0;
                                                                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                                    if (result <= 4) {
                                                                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, ptr2, 5, 1);
                                                                                                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                                                        i4 = ptr->field_8;
                                                                                                                                                                                                                                                                                                                                        ptr2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                    result = i->field_4;
                                                                                                                                                                                                                                                                                                                                    *(__int64 *)((__int64)i4 + (__int64)ptr2 + 4) = result;
                                                                                                                                                                                                                                                                                                                                    result = i->field_0;
                                                                                                                                                                                                                                                                                                                                    *(__int64 *)((__int64)i4 + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                                                                    ptr2 += 5;
                                                                                                                                                                                                                                                                                                                                    ptr->field_10 = ptr2;
                                                                                                                                                                                                                                                                                                                                    off_140108030();
                                                                                                                                                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                    result = i3 + 5;
                                                                                                                                                                                                                                                                                                                                    *dst2 = result;
                                                                                                                                                                                                                                                                                                                                    ptr2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                    sub_14002EDF0(0, 7);
                                                                                                                                                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                                                                                                                                                        i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                                                                        *result = 0xFD8349;
                                                                                                                                                                                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                                                                                                        if (result <= 3) {
                                                                                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                            sub_1400F2D20(a1, a2, 4, 1);
                                                                                                                                                                                                                                                                                                                                            ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                                                                                                                                                                        a1 = i->field_0;
                                                                                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                                                                                                                                        a2 += 4;
                                                                                                                                                                                                                                                                                                                                        ptr->field_10 = a2;
                                                                                                                                                                                                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                                                                                                                                                                                                        off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                        *dst2 = dst;
                                                                                                                                                                                                                                                                                                                                        result = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                        v_60 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 6);
                                                                                                                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                                                                            *result = 0x840F;
                                                                                                                                                                                                                                                                                                                                            arg_2 = 0;
                                                                                                                                                                                                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                                                                                                            if (result <= 5) {
                                                                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, a2, 6, 1);
                                                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                                                                                                                                                                                            a1 = i->field_4;
                                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                                                                                                                                                            a1 = i->field_0;
                                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                                                                                                                                            a2 += 6;
                                                                                                                                                                                                                                                                                                                                            ptr->field_10 = a2;
                                                                                                                                                                                                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                                                                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                                                                            *result = 0xAC89;
                                                                                                                                                                                                                                                                                                                                            arg_2 = 36;
                                                                                                                                                                                                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                            i->field_3 = 184;
                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                                                                                                            v_78 = (__int64)ptr2;
                                                                                                                                                                                                                                                                                                                                            if (result <= 6) {
                                                                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, a2, 7, 1);
                                                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                                                                                                                                                                                            a1 = i->field_0;
                                                                                                                                                                                                                                                                                                                                            a3 = i->field_3;
                                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
                                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                                                                                                                                            a2 += 7;
                                                                                                                                                                                                                                                                                                                                            ptr->field_10 = a2;
                                                                                                                                                                                                                                                                                                                                            off_140108030(a1, a2, a3);
                                                                                                                                                                                                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                            i3 += 8;
                                                                                                                                                                                                                                                                                                                                            *dst2 = i3;
                                                                                                                                                                                                                                                                                                                                            i4 = 72;
                                                                                                                                                                                                                                                                                                                                            i3 = rsp + 128;
                                                                                                                                                                                                                                                                                                                                            do {
                                                                                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                                a4 = i4 + 64;
                                                                                                                                                                                                                                                                                                                                                v_80 = 8;
                                                                                                                                                                                                                                                                                                                                                v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                *result = 139;
                                                                                                                                                                                                                                                                                                                                                v_90 = 1;
                                                                                                                                                                                                                                                                                                                                                sub_1400D4F50(i3, 0, 4, a4);
                                                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)v_80;
                                                                                                                                                                                                                                                                                                                                                i = (struct Struct_2_t *)v_88;
                                                                                                                                                                                                                                                                                                                                                dst2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                                                a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                result = a4->field_0;
                                                                                                                                                                                                                                                                                                                                                dst = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                if (dst2 > result) {
                                                                                                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, dst, dst2, 1);
                                                                                                                                                                                                                                                                                                                                                    a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                    dst = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                a1 = a4->field_8;
                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 + (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)a4;
                                                                                                                                                                                                                                                                                                                                                sub_1400F27F0(a1, i, dst2, a4);
                                                                                                                                                                                                                                                                                                                                                dst = (__int64 *)((__int64)dst + (__int64)dst2);
                                                                                                                                                                                                                                                                                                                                                ((__int64 *)a4)[2] = (__int64)(dst);
                                                                                                                                                                                                                                                                                                                                                if (ptr == 0) {
                                                                                                                                                                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                                    v_80 = 8;
                                                                                                                                                                                                                                                                                                                                                    v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                    *result = 137;
                                                                                                                                                                                                                                                                                                                                                    v_90 = 1;
                                                                                                                                                                                                                                                                                                                                                    sub_1400D4F50(i3, 0, 4, i4);
                                                                                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)v_80;
                                                                                                                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)v_88;
                                                                                                                                                                                                                                                                                                                                                    dst2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                                                    a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                    result = a4->field_0;
                                                                                                                                                                                                                                                                                                                                                    dst = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                    if (dst2 > result) {
                                                                                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, dst, dst2, 1);
                                                                                                                                                                                                                                                                                                                                                        a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                        dst = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                    a1 = a4->field_8;
                                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)((__int64)a1 + (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                    ptr2 = (struct Struct_4_t *)a4;
                                                                                                                                                                                                                                                                                                                                                    sub_1400F27F0(a1, i, dst2, a4);
                                                                                                                                                                                                                                                                                                                                                    dst = (__int64 *)((__int64)dst + (__int64)dst2);
                                                                                                                                                                                                                                                                                                                                                    ((__int64 *)a4)[2] = (__int64)(dst);
                                                                                                                                                                                                                                                                                                                                                    if (ptr == 0) {
                                                                                                                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)v_50;
                                                                                                                                                                                                                                                                                                                                                        *(__int64 *)ptr = (__int64)(i2);
                                                                                                                                                                                                                                                                                                                                                        i4 += 4;
                                                                                                                                                                                                                                                                                                                                                        i2 += 2;
                                                                                                                                                                                                                                                                                                                                                        i4 = 72;
                                                                                                                                                                                                                                                                                                                                                        i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72, a4);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        sub_1400D5190(i3, ptr, 72);
                                                                                                                                                                                                                                                                                                                                                        i3 = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                                        i3 += 4;
                                                                                                                                                                                                                                                                                                                                                        i2 = rsp + 128;
                                                                                                                                                                                                                                                                                                                                                        do {
                                                                                                                                                                                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                                            a4 = i4 + 64;
                                                                                                                                                                                                                                                                                                                                                            v_80 = 8;
                                                                                                                                                                                                                                                                                                                                                            v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                            *result = 139;
                                                                                                                                                                                                                                                                                                                                                            v_90 = 1;
                                                                                                                                                                                                                                                                                                                                                            sub_1400D4F50(i2, 0, 4, a4);
                                                                                                                                                                                                                                                                                                                                                            ptr = (struct Struct_3_t *)v_80;
                                                                                                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)v_88;
                                                                                                                                                                                                                                                                                                                                                            dst2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                                                            a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                            result = a4->field_0;
                                                                                                                                                                                                                                                                                                                                                            dst = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                            if (dst2 > result) {
                                                                                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, dst, dst2, 1);
                                                                                                                                                                                                                                                                                                                                                                a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                dst = ((__int64 *)a4)[2];
                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                            a1 = a4->field_8;
                                                                                                                                                                                                                                                                                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)a4;
                                                                                                                                                                                                                                                                                                                                                            sub_1400F27F0(a1, i, dst2, a4);
                                                                                                                                                                                                                                                                                                                                                            dst = (__int64 *)((__int64)dst + (__int64)dst2);
                                                                                                                                                                                                                                                                                                                                                            ((__int64 *)a4)[2] = (__int64)(dst);
                                                                                                                                                                                                                                                                                                                                                            if (ptr == 0) {
                                                                                                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                                                v_80 = 8;
                                                                                                                                                                                                                                                                                                                                                                v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                *result = 139;
                                                                                                                                                                                                                                                                                                                                                                v_90 = 1;
                                                                                                                                                                                                                                                                                                                                                                sub_1400D4F50(i2, 1, 4, i4);
                                                                                                                                                                                                                                                                                                                                                                ptr = (struct Struct_3_t *)v_80;
                                                                                                                                                                                                                                                                                                                                                                dst = (__int64 *)v_88;
                                                                                                                                                                                                                                                                                                                                                                i = (struct Struct_2_t *)v_90;
                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                result = *a1;
                                                                                                                                                                                                                                                                                                                                                                dst2 = a1[2];
                                                                                                                                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                                                                                                                                                                if (i > result) {
                                                                                                                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, dst2, i, 1);
                                                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                    dst2 = a1[2];
                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 + (__int64)dst2);
                                                                                                                                                                                                                                                                                                                                                                sub_1400F27F0(a1, dst, i);
                                                                                                                                                                                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                dst2 = (__int64 *)((__int64)dst2 + (__int64)i);
                                                                                                                                                                                                                                                                                                                                                                ptr2->field_10 = dst2;
                                                                                                                                                                                                                                                                                                                                                                if (ptr == 0) {
                                                                                                                                                                                                                                                                                                                                                                    result = i3 - 2;
                                                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)v_50;
                                                                                                                                                                                                                                                                                                                                                                    *a1 = result;
                                                                                                                                                                                                                                                                                                                                                                    if (dst2 == ptr2->field_0) {
                                                                                                                                                                                                                                                                                                                                                                        sub_1400F3510(ptr2);
                                                                                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2) = 1;
                                                                                                                                                                                                                                                                                                                                                                    result = dst2 + 1;
                                                                                                                                                                                                                                                                                                                                                                    ptr2->field_10 = result;
                                                                                                                                                                                                                                                                                                                                                                    if (result == ptr2->field_0) {
                                                                                                                                                                                                                                                                                                                                                                        sub_1400F3510(ptr2);
                                                                                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2 + 1) = 193;
                                                                                                                                                                                                                                                                                                                                                                    dst2 += 2;
                                                                                                                                                                                                                                                                                                                                                                    ptr2->field_10 = dst2;
                                                                                                                                                                                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                                                    v_80 = 8;
                                                                                                                                                                                                                                                                                                                                                                    v_88 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                    *result = 137;
                                                                                                                                                                                                                                                                                                                                                                    v_90 = 1;
                                                                                                                                                                                                                                                                                                                                                                    sub_1400D4F50(i2, 1, 4, i4);
                                                                                                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)v_80;
                                                                                                                                                                                                                                                                                                                                                                    i = (struct Struct_2_t *)v_88;
                                                                                                                                                                                                                                                                                                                                                                    dst2 = (__int64 *)v_90;
                                                                                                                                                                                                                                                                                                                                                                    result = ptr2->field_0;
                                                                                                                                                                                                                                                                                                                                                                    dst = ptr2->field_10;
                                                                                                                                                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                                    if (dst2 > result) {
                                                                                                                                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                        sub_1400F2D20(a1, dst, dst2, 1);
                                                                                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                        dst = ptr2->field_10;
                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                    a1 = ptr2->field_8;
                                                                                                                                                                                                                                                                                                                                                                    a1 = (size_t *)((__int64)a1 + (__int64)dst);
                                                                                                                                                                                                                                                                                                                                                                    sub_1400F27F0(a1, i, dst2);
                                                                                                                                                                                                                                                                                                                                                                    dst = (__int64 *)((__int64)dst + (__int64)dst2);
                                                                                                                                                                                                                                                                                                                                                                    ptr2->field_10 = dst;
                                                                                                                                                                                                                                                                                                                                                                    if (ptr == 0) {
                                                                                                                                                                                                                                                                                                                                                                        ptr = (struct Struct_3_t *)v_50;
                                                                                                                                                                                                                                                                                                                                                                        *(__int64 *)ptr = (__int64)(i3);
                                                                                                                                                                                                                                                                                                                                                                        i4 += 4;
                                                                                                                                                                                                                                                                                                                                                                        i3 += 4;
                                                                                                                                                                                                                                                                                                                                                                        i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                                                                                        sub_1400D5320(i3, ptr);
                                                                                                                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 7);
                                                                                                                                                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                                                                                                            *result = 0x1C58348;
                                                                                                                                                                                                                                                                                                                                                                            result = *i3;
                                                                                                                                                                                                                                                                                                                                                                            a2 = (size_t *)arg_10;
                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                                                                                                                                            i2 = (__int64 *)v_70;
                                                                                                                                                                                                                                                                                                                                                                            i4 = (__int64 *)v_138;
                                                                                                                                                                                                                                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, a2, 4, 1);
                                                                                                                                                                                                                                                                                                                                                                                i3 = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                                                                                                a2 = (size_t *)arg_10;
                                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                                                                                                                            a1 = i->field_0;
                                                                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                                                                                                                                                                            a2 += 4;
                                                                                                                                                                                                                                                                                                                                                                            arg_10 = (__int64)a2;
                                                                                                                                                                                                                                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                                                                                                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)v_40;
                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)arg_10;
                                                                                                                                                                                                                                                                                                                                                                            result += 5;
                                                                                                                                                                                                                                                                                                                                                                            if (!((result < 0))) {
                                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)v_78;
                                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                                                                                                                                                                                                                                                                                                                result = (__int64 *)a1;
                                                                                                                                                                                                                                                                                                                                                                                if (a1 == a1) {
                                                                                                                                                                                                                                                                                                                                                                                    ptr2 = (struct Struct_4_t *)a1;
                                                                                                                                                                                                                                                                                                                                                                                    i3 = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                                                                    sub_14002EDF0(0, 5);
                                                                                                                                                                                                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                                                                                                                                                                                                        i = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                                                                                                                                                                        *result = 233;
                                                                                                                                                                                                                                                                                                                                                                                        arg_1 = (__int64)ptr2;
                                                                                                                                                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                                                                                                                                                        a2 = a3[2];
                                                                                                                                                                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                                            sub_1400F2D20(a1, a2, 5, 1);
                                                                                                                                                                                                                                                                                                                                                                                            a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                                            a2 = a3[2];
                                                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                                                        result = (__int64 *)arg_8;
                                                                                                                                                                                                                                                                                                                                                                                        a1 = i->field_4;
                                                                                                                                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                                                                                                                                                                                                        a1 = i->field_0;
                                                                                                                                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                                                                                                                                                                                        a2 += 5;
                                                                                                                                                                                                                                                                                                                                                                                        a3[2] = a2;
                                                                                                                                                                                                                                                                                                                                                                                        ptr2 = (struct Struct_4_t *)a3;
                                                                                                                                                                                                                                                                                                                                                                                        off_140108030(a1, a2, a3);
                                                                                                                                                                                                                                                                                                                                                                                        off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                                                                        i3 += 2;
                                                                                                                                                                                                                                                                                                                                                                                        *(__int64 *)ptr = (__int64)(i3);
                                                                                                                                                                                                                                                                                                                                                                                        a1 = (size_t *)v_60;
                                                                                                                                                                                                                                                                                                                                                                                        a2 = a1;
                                                                                                                                                                                                                                                                                                                                                                                        a2 += 6;
                                                                                                                                                                                                                                                                                                                                                                                        if (!((a2 < 0))) {
                                                                                                                                                                                                                                                                                                                                                                                            a3 = ptr2->field_10;
                                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)a3;
                                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                                                                                                                                                            a4 = (struct Struct_1_t *)result;
                                                                                                                                                                                                                                                                                                                                                                                            i3 = (__int64 *)v_130;
                                                                                                                                                                                                                                                                                                                                                                                            if (result == result) {
                                                                                                                                                                                                                                                                                                                                                                                                if (a3 < a2) {
                                                                                                                                                                                                                                                                                                                                                                                                    return (__int64)i3;
                                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                                a2 = ptr2->field_8;
                                                                                                                                                                                                                                                                                                                                                                                                *(__int64 *)((__int64)a2 + (__int64)a1 + 2) = result;
                                                                                                                                                                                                                                                                                                                                                                                                i = (struct Struct_2_t *)arg_30a;
                                                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)i;
                                                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ 1);
                                                                                                                                                                                                                                                                                                                                                                                                result = (i3 == 0) ? 1 : 0;
                                                                                                                                                                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                                                                                                                                                                                                                                                                                                                                dst = (__int64 *)v_5f;
                                                                                                                                                                                                                                                                                                                                                                                                if ((a1 == 0)) {
                                                                                                                                                                                                                                                                                                                                                                                                    result = (__int64 *)arg_54;
                                                                                                                                                                                                                                                                                                                                                                                                    dst2 = 32;
                                                                                                                                                                                                                                                                                                                                                                                                    if (result != 0) dst2 = result;
                                                                                                                                                                                                                                                                                                                                                                                                    i = 1;
                                                                                                                                                                                                                                                                                                                                                                                                    ptr = 1;
                                                                                                                                                                                                                                                                                                                                                                                                    return (__int64)ptr;
                                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                                return (__int64)ptr;
                                                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                                                            result = &off_14011D238;
                                                                                                                                                                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                            a1 = &off_14011BC90;
                                                                                                                                                                                                                                                                                                                                                                                            a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                            a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                            sub_1400F3B80(a1, 8, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                            result = &off_14011CB30;
                                                                                                                                                                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                            a1 = &off_14011CB18;
                                                                                                                                                                                                                                                                                                                                                                                            a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                            a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                            sub_1400F3B80(a1, 17, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                            result = &off_14011CB60;
                                                                                                                                                                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                            a1 = &off_14011CB48;
                                                                                                                                                                                                                                                                                                                                                                                            a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                            a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                            sub_1400F3B80(a1, 22, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                            ptr = (struct Struct_3_t *)a2;
                                                                                                                                                                                                                                                                                                                                                                                            i3 = (__int64 *)a1;
                                                                                                                                                                                                                                                                                                                                                                                            i2 = a3[4];
                                                                                                                                                                                                                                                                                                                                                                                            v_38 = (int)a3;
                                                                                                                                                                                                                                                                                                                                                                                            dst = a3[4];
                                                                                                                                                                                                                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                                                                                                                            if (result == 0) JUMPOUT(0x1400d28e7);
                                                                                                                                                                                                                                                                                                                                                                                            i4 = result;
                                                                                                                                                                                                                                                                                                                                                                                            *i4 = result;
                                                                                                                                                                                                                                                                                                                                                                                            result = *i3;
                                                                                                                                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_4_t *)arg_10;
                                                                                                                                                                                                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                                                                                                                                                                                                                            if (result <= 7) JUMPOUT(0x1400d20ed);
                                                                                                                                                                                                                                                                                                                                                                                            i = (struct Struct_2_t *)arg_8;
                                                                                                                                                                                                                                                                                                                                                                                            result = *i4;
                                                                                                                                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)i + (__int64)ptr2) = result;
                                                                                                                                                                                                                                                                                                                                                                                            ptr2 += 8;
                                                                                                                                                                                                                                                                                                                                                                                            arg_10 = (__int64)ptr2;
                                                                                                                                                                                                                                                                                                                                                                                            off_140108030(0xD024848B48);
                                                                                                                                                                                                                                                                                                                                                                                            off_140108038(result, 0, i4);
                                                                                                                                                                                                                                                                                                                                                                                            dst2 = ptr->field_0;
                                                                                                                                                                                                                                                                                                                                                                                            sub_14002EDF0(0, 7);
                                                                                                                                                                                                                                                                                                                                                                                            if (result == 0) JUMPOUT(0x1400d28f6);
                                                                                                                                                                                                                                                                                                                                                                                            i4 = result;
                                                                                                                                                                                                                                                                                                                                                                                            *result = 72;
                                                                                                                                                                                                                                                                                                                                                                                            result = i2;
                                                                                                                                                                                                                                                                                                                                                                                            if (i2 == i2) JUMPOUT(0x1400d0b28);
                                                                                                                                                                                                                                                                                                                                                                                            arg_3 = (__int64)i2;
                                                                                                                                                                                                                                                                                                                                                                                            i2 = 7;
                                                                                                                                                                                                                                                                                                                                                                                            result = 129;
                                                                                                                                                                                                                                                                                                                                                                                            return sub_1400D0B34();
                                                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                                                        result = &off_14011B3E0;
                                                                                                                                                                                                                                                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                        a1 = &off_14011B3C3;
                                                                                                                                                                                                                                                                                                                                                                                        a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                        a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                        sub_1400F3B80(a1, 23, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 7);
                                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3326(1, 5);
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3326(1, 6);
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3326(1, 12);
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3326(1, 9);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011B718;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011B700;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 20, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011C768;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011C758;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 11, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011C790;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011C780;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 14, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011C7B8;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011C7A8;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 14, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011C7E0;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011C7D0;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 9, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011B8D8;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011B8C8;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 10, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011B900;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011B8F0;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 14, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011B928;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011B918;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 9, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011C488;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011C470;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 18, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011C4B0;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011C4A0;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 13, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011B6C0;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011B6A8;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 18, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                    result = &off_14011B6E8;
                                                                                                                                                                                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                    a1 = &off_14011B6D8;
                                                                                                                                                                                                                                                                                                                                                                                    a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                    a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                    sub_1400F3B80(a1, 11, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                result = &off_14011D220;
                                                                                                                                                                                                                                                                                                                                                                                v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                                                                                                                a1 = &off_14011BC68;
                                                                                                                                                                                                                                                                                                                                                                                a4 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                                                                                                                a3 = rsp + 79;
                                                                                                                                                                                                                                                                                                                                                                                sub_1400F3B80(a1, 10, a3, a4);
                                                                                                                                                                                                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                    off_140108030();
                                                                                                                                                                                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                                                                                                                                                                off_140108038(result, 0, dst);
                                                                                                                                                                                                                                                                                                                                                                ptr2 = (struct Struct_4_t *)v_40;
                                                                                                                                                                                                                                                                                                                                                                dst2 = ptr2->field_10;
                                                                                                                                                                                                                                                                                                                                                                return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                            off_140108030();
                                                                                                                                                                                                                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                                            return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                                        } while (i4 != 136);
                                                                                                                                                                                                                                                                                                                                                        return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                    off_140108030();
                                                                                                                                                                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                                    return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                                                return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                            } while (i4 != 136);
                                                                                                                                                                                                                                                                                                                                            return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                        return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                    return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                return (__int64)dst2;
                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                            off_140108030(a1, a2, a3, a4);
                                                                                                                                                                                                                                                                                                                            off_140108038(result, 0, dst);
                                                                                                                                                                                                                                                                                                                            a4 = (struct Struct_1_t *)v_40;
                                                                                                                                                                                                                                                                                                                            return (__int64)a4;
                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 11);
                                                                                                                                                                                                                                                                                                                        return (__int64)a4;
                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                    off_140108030(a1, a2, a3);
                                                                                                                                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                                    a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                        off_140108030();
                                                                                                                                                                                                                                                                                                        off_140108038(result, 0, dst2);
                                                                                                                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                    off_140108030();
                                                                                                                                                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                                                                                                                                } while (i4 != 184);
                                                                                                                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                    ptr = (struct Struct_3_t *)i3;
                                                                                                                                                                                                                                                                                    return (__int64)ptr;
                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                return (__int64)ptr;
                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                            a1 = (size_t *)v_40;
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
                                                                                                                                                                                                                                                        off_140108030();
                                                                                                                                                                                                                                                        off_140108038(result, 0, dst);
                                                                                                                                                                                                                                                        return (__int64)a1;
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    a1 = (size_t *)result;
                                                                                                                                                                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)i4);
                                                                                                                                                                                                                                                    if (a1 <= 3) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = 0x24843348;
                                                                                                                                                                                                                                                    i4 += 4;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    a2 = (size_t *)result;
                                                                                                                                                                                                                                                    a2 = (size_t *)((__int64)a2 - (__int64)i4);
                                                                                                                                                                                                                                                    if (a2 <= 3) {
                                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                                        a1 = (size_t *)v_40;
                                                                                                                                                                                                                                                        sub_1400F2D20(a1, i4, 4, 1);
                                                                                                                                                                                                                                                        a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                        i4 = a3[2];
                                                                                                                                                                                                                                                        result = *a3;
                                                                                                                                                                                                                                                        a1 = (size_t *)arg_8;
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)i4) = i3;
                                                                                                                                                                                                                                                    i4 += 4;
                                                                                                                                                                                                                                                    a3[2] = i4;
                                                                                                                                                                                                                                                    i2 += 5;
                                                                                                                                                                                                                                                    return (__int64)i2;
                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                off_140108030(a1, a2, a3);
                                                                                                                                                                                                                                                off_140108038(result, 0, dst);
                                                                                                                                                                                                                                                a3 = (size_t *)v_40;
                                                                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                                                                            } while (ptr < 4);
                                                                                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                                                            }
                                                                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                                                                        }
                                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                                                }
                                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                                            }
                                                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                                                        }
                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                                }
                                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                                            }
                                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                                        }
                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                    }
                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                }
                                                                                                                                                                                return (__int64)a3;
                                                                                                                                                                            }
                                                                                                                                                                            return (__int64)a3;
                                                                                                                                                                        }
                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                    }
                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                }
                                                                                                                                                                result = (__int64 *)v_40;
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
                                                                                                off_140108030(a1, a2, a3);
                                                                                                off_140108038(result, 0, dst);
                                                                                                a3 = (size_t *)v_40;
                                                                                                i4 = a3[2];
                                                                                                return (__int64)i4;
                                                                                            }
                                                                                            return (__int64)i4;
                                                                                        }
                                                                                        return (__int64)i4;
                                                                                    }
                                                                                    return (__int64)i4;
                                                                                }
                                                                                return (__int64)i4;
                                                                            }
                                                                            off_140108030(a1, a2, a3);
                                                                            off_140108038(result, 0, dst);
                                                                            a3 = (size_t *)v_40;
                                                                            ptr2 = a3[2];
                                                                            return (__int64)ptr2;
                                                                        }
                                                                        return (__int64)ptr2;
                                                                    }
                                                                    i4 = i3;
                                                                    return (__int64)i4;
                                                                }
                                                                return (__int64)i4;
                                                            }
                                                            return (__int64)i4;
                                                        }
                                                        return (__int64)i4;
                                                    }
                                                    return (__int64)i4;
                                                }
                                                return (__int64)i4;
                                            }
                                            return (__int64)i4;
                                        }
                                        off_140108030(a1, a2, a3);
                                        off_140108038(result, 0, ptr2);
                                        a3 = (size_t *)v_40;
                                        dst = a3[2];
                                        return (__int64)dst;
                                    }
                                    return (__int64)dst;
                                }
                                return (__int64)dst;
                            }
                            return (__int64)dst;
                        }
                    }
                }
                return (__int64)dst;
            }
            ptr2->field_3 = i3;
            i = 7;
            result = 129;
            return (__int64)result;
        }
        return (__int64)result;
    }
    do {
        sub_1400F3326(1, 8, a3);
        do {
            v_20 = 1;
            a1 = (size_t *)v_40;
            sub_1400F2D20(a1, a2, 5, 1);
            ptr = (struct Struct_3_t *)v_40;
            a2 = ptr->field_10;
            do {
                result = ptr->field_8;
                a1 = i->field_4;
                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                a1 = i->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 5;
                ptr->field_10 = a2;
                off_140108030(a1, a2);
                off_140108038(result, 0, i);
                a1 = (size_t *)v_50;
                i3 = *a1;
                result = i3 + 1;
                *a1 = result;
                sub_14002EDF0(0, 8);
                i = (struct Struct_2_t *)result;
                *result = 0x24748B4C;
                result = ptr->field_0;
                a2 = ptr->field_10;
                i->field_4 = 64;
                result = (__int64 *)((__int64)result - (__int64)a2);
                if (result <= 4) {
                    v_20 = 1;
                    a1 = (size_t *)v_40;
                    sub_1400F2D20(a1, a2, 5, 1);
                    ptr = (struct Struct_3_t *)v_40;
                    a2 = ptr->field_10;
                }
                result = ptr->field_8;
                a1 = i->field_4;
                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                a1 = i->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 5;
                ptr->field_10 = a2;
                off_140108030(a1, a2);
                off_140108038(result, 0, i);
                result = i3 + 2;
                a1 = (size_t *)v_50;
                *a1 = result;
                sub_14002EDF0(0, 7);
                if (result != 0) {
                    i = (struct Struct_2_t *)result;
                    *result = 0x8148;
                    arg_3 = 192;
                    arg_2 = 236;
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if (result <= 6) {
                        v_20 = 1;
                        a1 = (size_t *)v_40;
                        sub_1400F2D20(a1, a2, 7, 1);
                        ptr = (struct Struct_3_t *)v_40;
                        a2 = ptr->field_10;
                    }
                    result = ptr->field_8;
                    a1 = i->field_0;
                    a3 = i->field_3;
                    *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 7;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2, a3);
                    off_140108038(result, 0, i);
                    i3 += 3;
                    a2 = (size_t *)v_50;
                    *a2 = i3;
                    a3 = (size_t *)v_10c;
                    sub_1400D9BD0(ptr, a2, a3);
                    v_78 = (__int64)dst2;
                    if (i4 < 64) {
                        sub_14002EDF0(0, 3, a3);
                        if (result == 0) {
                            do {
                                sub_1400F3340(1, 3);
                                return v_78;
                            } while (true);
                        }
                        i = (struct Struct_2_t *)result;
                        *result = 0x3148;
                        arg_2 = 192;
                        ptr = (struct Struct_3_t *)v_40;
                        result = ptr->field_0;
                        a2 = ptr->field_10;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 2) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, a2, 3, 1);
                            ptr = (struct Struct_3_t *)v_40;
                            a2 = ptr->field_10;
                        }
                        result = ptr->field_8;
                        a1 = i->field_2;
                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                        a1 = i->field_0;
                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                        a2 += 3;
                        ptr->field_10 = a2;
                        off_140108030(a1, a2);
                        off_140108038(result, 0, i);
                        a1 = (size_t *)v_50;
                        i3 = *a1;
                        result = i3 + 1;
                        *a1 = result;
                        sub_14002EDF0(0, 8);
                        i = (struct Struct_2_t *)result;
                        *result = 0x247C8D48;
                        result = ptr->field_0;
                        a2 = ptr->field_10;
                        i->field_4 = 64;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 4) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, a2, 5, 1);
                            ptr = (struct Struct_3_t *)v_40;
                            a2 = ptr->field_10;
                        }
                        result = ptr->field_8;
                        a1 = i->field_4;
                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                        a1 = i->field_0;
                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                        a2 += 5;
                        ptr->field_10 = a2;
                        off_140108030(a1, a2);
                        off_140108038(result, 0, i);
                        sub_14002EDF0(0, 6);
                        if (result != 0) {
                            i = (struct Struct_2_t *)result;
                            *result = 185;
                            arg_1 = 128;
                            result = ptr->field_0;
                            a2 = ptr->field_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 4) {
                                v_20 = 1;
                                a1 = (size_t *)v_40;
                                sub_1400F2D20(a1, a2, 5, 1);
                                ptr = (struct Struct_3_t *)v_40;
                                a2 = ptr->field_10;
                            }
                            i2 = i4;
                            i2 = (__int64 *)((__int64)(__int64)i2 & 63);
                            result = ptr->field_8;
                            a1 = i->field_4;
                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                            a1 = i->field_0;
                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                            a2 += 5;
                            ptr->field_10 = a2;
                            off_140108030(a1, a2);
                            off_140108038(result, 0, i);
                            a3 = (size_t *)v_40;
                            result = i3 + 3;
                            a1 = (size_t *)v_50;
                            *a1 = result;
                            result = *a3;
                            a2 = a3[2];
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 2) {
                                v_20 = 1;
                                a1 = (size_t *)v_40;
                                sub_1400F2D20(a1, a2, 3, 1);
                                a3 = (size_t *)v_40;
                                a2 = a3[2];
                            }
                            result = (__int64 *)arg_8;
                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 170;
                            *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                            a2 += 3;
                            a3[2] = a2;
                            if (i2 != 0) {
                                sub_14002EDF0(0, 3, a3);
                                if (result == 0) {
                                    return (__int64)a2;
                                }
                                i = (struct Struct_2_t *)result;
                                *result = 0x894C;
                                arg_2 = 230;
                                ptr = (struct Struct_3_t *)v_40;
                                result = ptr->field_0;
                                a2 = ptr->field_10;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 2) {
                                    v_20 = 1;
                                    a1 = (size_t *)v_40;
                                    sub_1400F2D20(a1, a2, 3, 1);
                                    ptr = (struct Struct_3_t *)v_40;
                                    a2 = ptr->field_10;
                                }
                                result = ptr->field_8;
                                a1 = i->field_2;
                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                a1 = i->field_0;
                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                a2 += 3;
                                ptr->field_10 = a2;
                                off_140108030(a1, a2);
                                off_140108038(result, 0, i);
                                result = i3 + 5;
                                a1 = (size_t *)v_50;
                                *a1 = result;
                                sub_14002EDF0(0, 8);
                                i = (struct Struct_2_t *)result;
                                *result = 0x247C8D48;
                                result = ptr->field_0;
                                a2 = ptr->field_10;
                                i->field_4 = 64;
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                if (result <= 4) {
                                    v_20 = 1;
                                    a1 = (size_t *)v_40;
                                    sub_1400F2D20(a1, a2, 5, 1);
                                    ptr = (struct Struct_3_t *)v_40;
                                    a2 = ptr->field_10;
                                }
                                result = ptr->field_8;
                                a1 = i->field_4;
                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                a1 = i->field_0;
                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                a2 += 5;
                                ptr->field_10 = a2;
                                off_140108030(a1, a2);
                                off_140108038(result, 0, i);
                                result = i3 + 6;
                                a1 = (size_t *)v_50;
                                *a1 = result;
                                sub_14002EDF0(0, 6);
                                if (result != 0) {
                                    i = (struct Struct_2_t *)result;
                                    *result = 185;
                                    arg_1 = (__int64)i2;
                                    result = ptr->field_0;
                                    a2 = ptr->field_10;
                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                    if (result <= 4) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, a2, 5, 1);
                                        ptr = (struct Struct_3_t *)v_40;
                                        a2 = ptr->field_10;
                                    }
                                    result = ptr->field_8;
                                    a1 = i->field_4;
                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                    a1 = i->field_0;
                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                    a2 += 5;
                                    ptr->field_10 = a2;
                                    off_140108030(a1, a2);
                                    off_140108038(result, 0, i);
                                    a3 = (size_t *)v_40;
                                    result = *a3;
                                    a2 = a3[2];
                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                    if (result <= 2) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, a2, 3, 1);
                                        a3 = (size_t *)v_40;
                                        a2 = a3[2];
                                    }
                                    result = (__int64 *)arg_8;
                                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 164;
                                    *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                                    a2 += 3;
                                    a3[2] = a2;
                                    i3 += 8;
                                    result = (__int64 *)v_50;
                                    *result = i3;
                                    result = *a3;
                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                    if (result <= 2) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, ptr, 3, 1);
                                        a3 = (size_t *)v_40;
                                        a2 = a3[2];
                                    }
                                    ptr = i2 + 64;
                                    result = (__int64 *)arg_8;
                                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                                    *(__int64 *)((__int64)result + (__int64)a2) = 0x84C6;
                                    a2 += 3;
                                    a3[2] = a2;
                                    result = *a3;
                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                    if (result <= 3) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, a2, 4, 1);
                                        a3 = (size_t *)v_40;
                                        a2 = a3[2];
                                    }
                                    result = (__int64 *)arg_8;
                                    *(__int64 *)((__int64)result + (__int64)a2) = ptr;
                                    a2 += 4;
                                    a3[2] = a2;
                                    if (*a3 == a2) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, a2, 1, 1);
                                        a3 = (size_t *)v_40;
                                        a2 = a3[2];
                                    }
                                    ptr2 = 0;
                                    i = (i2 >= 56) ? 1 : 0;
                                    result = (__int64 *)arg_8;
                                    *(__int64 *)((__int64)result + (__int64)a2) = 128;
                                    ++a2;
                                    a3[2] = a2;
                                    result = i3 + 1;
                                    a1 = (size_t *)v_50;
                                    *a1 = result;
                                    sub_14002EDF0(0, 11, a3);
                                    if (result != 0) {
                                        i4 = (__int64 *)((__int64)(__int64)i4 << 3);
                                        i4 = __builtin_bswap64(i4);
                                        dst2 = i4;
                                        ptr2 = (struct Struct_4_t *)i;
                                        ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 << 6);
                                        ptr2 += 120;
                                        v_80 = 11;
                                        v_88 = (__int64)result;
                                        *result = 199;
                                        v_90 = 1;
                                        a1 = rsp + 128;
                                        sub_1400D4F50(a1, 0, 4, ptr2);
                                        ptr = (struct Struct_3_t *)v_80;
                                        i4 = (__int64 *)v_90;
                                        result = (__int64 *)ptr;
                                        result = (__int64 *)((__int64)result - (__int64)i4);
                                        v_68 = (__int64)i2;
                                        if (result <= 3) {
                                            v_20 = 1;
                                            a1 = rsp + 128;
                                            sub_1400F2D20(a1, i4, 4, 1);
                                            ptr = (struct Struct_3_t *)v_80;
                                            i4 = (__int64 *)v_90;
                                        }
                                        i2 = (__int64 *)v_88;
                                        *(__int64 *)((__int64)i2 + (__int64)i4) = dst2;
                                        i4 += 4;
                                        dst = (__int64 *)v_40;
                                        result = *dst;
                                        i = (struct Struct_2_t *)arg_10;
                                        result = (__int64 *)((__int64)result - (__int64)i);
                                        if (i4 > result) {
                                            v_20 = 1;
                                            a1 = (size_t *)v_40;
                                            sub_1400F2D20(a1, i, i4, 1);
                                            dst = (__int64 *)v_40;
                                            i = (struct Struct_2_t *)arg_10;
                                        }
                                        a1 = (size_t *)arg_8;
                                        a1 = (size_t *)((__int64)a1 + (__int64)i);
                                        sub_1400F27F0(a1, i2, i4);
                                        i = (struct Struct_2_t *)((__int64)i + (__int64)i4);
                                        arg_10 = (__int64)i;
                                        if (ptr != 0) {
                                            off_140108030();
                                            off_140108038(result, 0, i2);
                                        }
                                        sub_14002EDF0(0, 11);
                                        if (result == 0) {
                                            return arg_10;
                                        } else {
                                            dst2 = (__int64 *)((__int64)(__int64)dst2 >> 32);
                                            ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 | 4);
                                            v_80 = 11;
                                            v_88 = (__int64)result;
                                            *result = 199;
                                            v_90 = 1;
                                            a1 = rsp + 128;
                                            sub_1400D4F50(a1, 0, 4, ptr2);
                                            ptr = (struct Struct_3_t *)v_80;
                                            ptr2 = (struct Struct_4_t *)v_90;
                                            result = (__int64 *)ptr;
                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                            i2 = (__int64 *)v_70;
                                            if (result <= 3) {
                                                v_20 = 1;
                                                a1 = rsp + 128;
                                                sub_1400F2D20(a1, ptr2, 4, 1);
                                                ptr = (struct Struct_3_t *)v_80;
                                                ptr2 = (struct Struct_4_t *)v_90;
                                            }
                                            i4 = (__int64 *)v_88;
                                            *(__int64 *)((__int64)i4 + (__int64)ptr2) = dst2;
                                            ptr2 += 4;
                                            a1 = (size_t *)v_40;
                                            result = *a1;
                                            i = a1[2];
                                            result = (__int64 *)((__int64)result - (__int64)i);
                                            if (ptr2 > result) {
                                                v_20 = 1;
                                                a1 = (size_t *)v_40;
                                                sub_1400F2D20(a1, i, ptr2, 1);
                                                a1 = (size_t *)v_40;
                                                i = a1[2];
                                            }
                                            dst2 = (__int64 *)v_78;
                                            a1 = (size_t *)arg_8;
                                            a1 = (size_t *)((__int64)a1 + (__int64)i);
                                            sub_1400F27F0(a1, i4, ptr2);
                                            a2 = (size_t *)v_40;
                                            i = (struct Struct_2_t *)((__int64)i + (__int64)ptr2);
                                            a2[2] = i;
                                            if (ptr != 0) {
                                                off_140108030(a1, a2);
                                                off_140108038(result, 0, i4);
                                                a2 = (size_t *)v_40;
                                            }
                                            i = i2 + 746;
                                            i3 += 3;
                                            ptr = (struct Struct_3_t *)v_50;
                                            *(__int64 *)ptr = (__int64)(i3);
                                            ptr2 = (struct Struct_4_t *)v_110;
                                            i3 = (__int64 *)a2;
                                            sub_1400D9E70(ptr2, a2, ptr, 64);
                                            if (v_68 > 55) {
                                                sub_1400D9E70(ptr2, i3, ptr, 128);
                                            }
                                            a4 = (struct Struct_1_t *)v_128;
                                            sub_1400DA120(i3, ptr, i, a4);
                                            sub_14002EDF0(0, 7);
                                            if (result != 0) {
                                                i = (struct Struct_2_t *)result;
                                                *result = 0x8148;
                                                arg_3 = 192;
                                                arg_2 = 196;
                                                result = *i3;
                                                a2 = (size_t *)arg_10;
                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                ptr = (struct Struct_3_t *)v_60;
                                                if (result <= 6) {
                                                    v_20 = 1;
                                                    a1 = (size_t *)v_40;
                                                    sub_1400F2D20(a1, a2, 7, 1);
                                                    i3 = (__int64 *)v_40;
                                                    a2 = (size_t *)arg_10;
                                                }
                                                result = (__int64 *)arg_8;
                                                a1 = i->field_0;
                                                a3 = i->field_3;
                                                *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                a2 += 7;
                                                arg_10 = (__int64)a2;
                                                off_140108030(a1, a2, a3);
                                                off_140108038(result, 0, i);
                                                result = (__int64 *)v_50;
                                                *result = *result + 1;
                                                return (__int64)result;
                                            }
                                        }
                                        return (__int64)result;
                                    }
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            i3 += 4;
                            result = *a3;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 2) {
                                return (__int64)result;
                            }
                            return (__int64)result;
                        }
                        return (__int64)result;
                    }
                    sub_14002EDF0(0, 6);
                    if (result != 0) {
                        i = (struct Struct_2_t *)result;
                        dst = i4;
                        result = i4;
                        result = (__int64 *)((__int64)(__int64)result >> 6);
                        *(__int64 *)i = (__int64)(0xBD41);
                        i->field_2 = result;
                        i4 = (__int64 *)v_40;
                        result = *i4;
                        ptr2 = (struct Struct_4_t *)arg_10;
                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                        if (result <= 5) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, ptr2, 6, 1);
                            i4 = (__int64 *)v_40;
                            ptr2 = (struct Struct_4_t *)arg_10;
                        }
                        ptr = (struct Struct_3_t *)arg_8;
                        result = i->field_4;
                        *(__int64 *)((__int64)ptr + (__int64)ptr2 + 4) = result;
                        result = i->field_0;
                        *(__int64 *)((__int64)ptr + (__int64)ptr2) = result;
                        ptr2 += 6;
                        arg_10 = (__int64)ptr2;
                        off_140108030();
                        off_140108038(result, 0, i);
                        result = (__int64 *)v_50;
                        i3 = *result;
                        sub_14002EDF0(0, 8);
                        i = (struct Struct_2_t *)result;
                        *result = 0x244C8D48;
                        arg_4 = 32;
                        result = *i4;
                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                        i2 = (__int64 *)ptr2;
                        if (result <= 4) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, ptr2, 5, 1);
                            i4 = (__int64 *)v_40;
                            ptr = (struct Struct_3_t *)arg_8;
                            i2 = (__int64 *)arg_10;
                        }
                        result = i->field_4;
                        *(__int64 *)((__int64)ptr + (__int64)i2 + 4) = result;
                        result = i->field_0;
                        *(__int64 *)((__int64)ptr + (__int64)i2) = result;
                        i2 += 5;
                        arg_10 = (__int64)i2;
                        off_140108030();
                        off_140108038(result, 0, i);
                        result = i3 + 2;
                        a1 = (size_t *)v_50;
                        *a1 = result;
                        sub_14002EDF0(0, 3);
                        if (result == 0) {
                            return (__int64)a1;
                        }
                        i = (struct Struct_2_t *)result;
                        *result = 0x894C;
                        arg_2 = 226;
                        result = *i4;
                        result = (__int64 *)((__int64)result - (__int64)i2);
                        if (result <= 2) {
                            v_20 = 1;
                            a1 = (size_t *)v_40;
                            sub_1400F2D20(a1, i2, 3, 1);
                            a1 = (size_t *)v_40;
                            ptr = (struct Struct_3_t *)arg_8;
                            i2 = a1[2];
                        }
                        result = i->field_2;
                        *(__int64 *)((__int64)ptr + (__int64)i2 + 2) = result;
                        result = i->field_0;
                        *(__int64 *)((__int64)ptr + (__int64)i2) = result;
                        i4 = i2 + 3;
                        a1[2] = i4;
                        off_140108030(i4);
                        off_140108038(result, 0, i);
                        i2 += 8;
                        if (!((i2 < 0))) {
                            ptr = (struct Struct_3_t *)v_110;
                            ptr = (struct Struct_3_t *)((__int64)ptr - (__int64)i2);
                            result = (__int64 *)ptr;
                            if (ptr == ptr) {
                                a3 = (size_t *)v_40;
                                result = *a3;
                                if (result == i4) {
                                    v_20 = 1;
                                    a1 = (size_t *)v_40;
                                    sub_1400F2D20(a1, i4, 1, 1);
                                    a3 = (size_t *)v_40;
                                    result = *a3;
                                    i4 = a3[2];
                                }
                                i2 = (__int64 *)arg_8;
                                *(__int64 *)((__int64)i2 + (__int64)i4) = 232;
                                ++i4;
                                a3[2] = i4;
                                result = (__int64 *)((__int64)result - (__int64)i4);
                                if (result <= 3) {
                                    v_20 = 1;
                                    a1 = (size_t *)v_40;
                                    sub_1400F2D20(a1, i4, 4, 1);
                                    a3 = (size_t *)v_40;
                                    i2 = (__int64 *)arg_8;
                                    i4 = a3[2];
                                }
                                *(__int64 *)((__int64)i2 + (__int64)i4) = ptr;
                                i4 += 4;
                                a3[2] = i4;
                                result = i3 + 4;
                                a1 = (size_t *)v_50;
                                *a1 = result;
                                dst2 = (__int64 *)a3;
                                sub_14002EDF0(0, 7, a3);
                                if (result != 0) {
                                    i = (struct Struct_2_t *)result;
                                    *result = 0x40C48349;
                                    ptr = *dst2;
                                    result = (__int64 *)ptr;
                                    result = (__int64 *)((__int64)result - (__int64)i4);
                                    if (result <= 3) {
                                        v_20 = 1;
                                        a1 = (size_t *)v_40;
                                        sub_1400F2D20(a1, i4, 4, 1);
                                        a1 = (size_t *)v_40;
                                        i4 = a1[2];
                                        ptr = *a1;
                                        i2 = (__int64 *)arg_8;
                                    }
                                    result = i->field_0;
                                    *(__int64 *)((__int64)i2 + (__int64)i4) = result;
                                    i4 += 4;
                                    a1[2] = i4;
                                    off_140108030(dst2);
                                    off_140108038(result, 0, i);
                                    ptr = (struct Struct_3_t *)((__int64)ptr - (__int64)i4);
                                    if (ptr <= 2) {
                                        v_20 = 1;
                                        ptr = (struct Struct_3_t *)v_40;
                                        sub_1400F2D20(ptr, i4, 3, 1);
                                        i4 = ptr->field_10;
                                        result = ptr->field_8;
                                        *(__int64 *)((__int64)result + (__int64)i4 + 2) = 205;
                                        *(__int64 *)((__int64)result + (__int64)i4) = 0xFF49;
                                        a2 = i4 + 3;
                                        ptr->field_10 = a2;
                                        i4 += 9;
                                        if (!((i4 < 0))) {
                                            ptr2 = (struct Struct_4_t *)((__int64)ptr2 - (__int64)i4);
                                            a1 = (size_t *)ptr2;
                                            if (ptr2 == ptr2) {
                                                a1 = ptr->field_0;
                                                a3 = a1;
                                                a3 = (size_t *)((__int64)a3 - (__int64)a2);
                                                i4 = dst;
                                                if (a3 <= 1) {
                                                    v_20 = 1;
                                                    a1 = (size_t *)v_40;
                                                    sub_1400F2D20(a1, a2, 2, 1);
                                                    ptr = (struct Struct_3_t *)v_40;
                                                    a2 = ptr->field_10;
                                                    a1 = ptr->field_0;
                                                    result = ptr->field_8;
                                                }
                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x850F;
                                                a2 += 2;
                                                ptr->field_10 = a2;
                                                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                if (a1 <= 3) {
                                                    v_20 = 1;
                                                    a1 = (size_t *)v_40;
                                                    sub_1400F2D20(a1, a2, 4, 1);
                                                    ptr = (struct Struct_3_t *)v_40;
                                                    result = ptr->field_8;
                                                    a2 = ptr->field_10;
                                                }
                                                *(__int64 *)((__int64)result + (__int64)a2) = ptr2;
                                                a2 += 4;
                                                ptr->field_10 = a2;
                                                i3 += 7;
                                                result = (__int64 *)v_50;
                                                *result = i3;
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    ptr = (struct Struct_3_t *)v_40;
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
            } while (result > 4);
            return (__int64)ptr;
        } while (result <= 4);
    } while (result == 0);
    return (__int64)result;
}