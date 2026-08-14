// inferred from 8 accesses on `result`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    char field_2; // offset 2
    char field_3; // offset 3
    char field_4; // offset 4
    char field_5; // offset 5
    char field_6; // offset 6
    int field_7; // offset 7
    __int64 field_B; // offset 11
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int16 field_0; // offset 0
    char _pad_0[1];
    __int64 field_3; // offset 3
};

// inferred from 4 accesses on `ptr2`
struct Struct_3_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
    char _pad_3[5];
    __int64 field_10; // offset 16
};

__int64 sub_1400F3510();
__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F3340();
__int64 sub_1400F3600();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400D5190();
__int64 sub_1400F3326();
__int64 sub_1400F3B80();
__int64 sub_1401045CC();
__int64 off_140108030();
extern __int64 off_14011D380;
extern __int64 off_140108038;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011CE40;
extern __int64 off_14011CE28;
extern __int64 off_14011CE68;
extern __int64 off_14011CE58;
extern __int64 off_14011CE90;
extern __int64 off_14011CE80;
extern __int64 off_14011C570;
extern __int64 off_14011C562;
extern __int64 off_14011C588;
extern __int64 off_14011BC90;

__int64 __fastcall sub_140101C10(size_t *a1) {
    __int64 rsp;
    int arg_2;
    int arg_2d;
    int arg_3;
    int arg_4;
    int arg_8;
    int arg_9;
    __int64 v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    int v_47;
    __int64 v_48;
    __int64 v_50;
    __int64 v_58;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    struct Struct_3_t *ptr2;
    struct Struct_1_t *result;
    __int64 *dst;
    __int64 *dst2;
    __int64 v6;
    __int64 *dst3;
    __int64 v7;
    __int64 *src;
    __int64 v9;
    struct Struct_2_t *ptr;
    __int64 v12;
    __int64 *src2;
    __m128i xmm0;

    ptr2 = (struct Struct_3_t *)a1;
    v_28 = 0;
    v_30 = 1;
    v_38 = 0;
    v_40 = 0;
    a1 = rsp + 40;
    sub_1400F3510(a1);
    result = (struct Struct_1_t *)v_30;
    *(__int64 *)result = (__int64)(85);
    v_38 = 1;
    if (v_28 == 1) {
        a1 = rsp + 40;
        sub_1400F3510(a1);
    }
    result = (struct Struct_1_t *)v_30;
    result->field_1 = 83;
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
    v_40 = 4;
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
    v_40 = 6;
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
    v_40 = 8;
    sub_14002EDF0(0, 7);
    if (result != 0) {
        dst = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8148);
        result->field_3 = 128;
        result->field_2 = 236;
        result = (struct Struct_1_t *)v_28;
        dst2 = (__int64 *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
        if (result <= 6) {
            do {
                v_20 = 1;
                a1 = rsp + 40;
                sub_1400F2D20(a1, dst2, 7, 1);
                dst2 = (__int64 *)v_38;
            } while (true);
        }
        result = (struct Struct_1_t *)v_30;
        a1 = *dst;
        v6 = arg_3;
        *(__int64 *)((__int64)result + (__int64)dst2 + 3) = v6;
        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
        dst2 += 7;
        v_38 = (__int64)dst2;
        off_140108030(a1, dst2, v6);
        ((__int64 (*)())off_140108038)(result, 0, dst);
        sub_14002EDF0(0, 3);
        if (result == 0) {
            sub_1400F3340(1, 3);
            dst3 += 2;
            v7 = &off_14011D380;
            sub_1400F3600(dst3, dst2, v6, v7);
            src += 2;
            v7 = &off_14011D380;
            sub_1400F3600(src, dst2, result, v7);
            a1 += 6;
            v7 = &off_14011D380;
            sub_1400F3600(a1, dst2, v6, v7);
        }
        dst = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8949);
        result->field_2 = 204;
        result = (struct Struct_1_t *)v_28;
        dst2 = (__int64 *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, dst2, 3, 1);
            dst2 = (__int64 *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
        a1 = *dst;
        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
        dst2 += 3;
        v_38 = (__int64)dst2;
        off_140108030(a1, dst2);
        ((__int64 (*)())off_140108038)(result, 0, dst);
        v_40 = 10;
        sub_14002EDF0(0, 3);
        if (result == 0) {
            return v_40;
        }
        dst = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8949);
        result->field_2 = 213;
        result = (struct Struct_1_t *)v_28;
        dst2 = (__int64 *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, dst2, 3, 1);
            dst2 = (__int64 *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
        a1 = *dst;
        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
        dst2 += 3;
        v_38 = (__int64)dst2;
        off_140108030(a1, dst2);
        ((__int64 (*)())off_140108038)(result, 0, dst);
        sub_14002EDF0(0, 3);
        if (result == 0) {
            return v_38;
        }
        dst = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x894D);
        result->field_2 = 198;
        result = (struct Struct_1_t *)v_28;
        dst2 = (__int64 *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, dst2, 3, 1);
            dst2 = (__int64 *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
        a1 = *dst;
        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
        dst2 += 3;
        v_38 = (__int64)dst2;
        off_140108030(a1, dst2);
        ((__int64 (*)())off_140108038)(result, 0, dst);
        v_40 = 12;
        sub_14002EDF0(0, 3);
        if (result == 0) {
            return v_40;
        }
        dst = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x894D);
        result->field_2 = 207;
        result = (struct Struct_1_t *)v_28;
        dst2 = (__int64 *)v_38;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
        if (result <= 2) {
            v_20 = 1;
            a1 = rsp + 40;
            sub_1400F2D20(a1, dst2, 3, 1);
            dst2 = (__int64 *)v_38;
        }
        result = (struct Struct_1_t *)v_30;
        a1 = (size_t *)arg_2;
        *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
        a1 = *dst;
        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
        dst2 += 3;
        v_38 = (__int64)dst2;
        off_140108030(a1, dst2);
        ((__int64 (*)())off_140108038)(result, 0, dst);
        sub_14002EDF0(0, 8);
        if (result != 0) {
            dst = (__int64 *)result;
            *(__int64 *)result = (__int64)(0xAC8B);
            result->field_2 = 36;
            result = (struct Struct_1_t *)v_28;
            dst2 = (__int64 *)v_38;
            arg_3 = 232;
            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
            if (result <= 6) {
                v_20 = 1;
                a1 = rsp + 40;
                sub_1400F2D20(a1, dst2, 7, 1);
                dst2 = (__int64 *)v_38;
            }
            result = (struct Struct_1_t *)v_30;
            a1 = *dst;
            v6 = arg_3;
            *(__int64 *)((__int64)result + (__int64)dst2 + 3) = v6;
            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
            dst2 += 7;
            v_38 = (__int64)dst2;
            off_140108030(a1, dst2, v6);
            ((__int64 (*)())off_140108038)(result, 0, dst);
            v_40 = 14;
            sub_14002EDF0(0, 11);
            if (result != 0) {
                dst = (__int64 *)result;
                result = 0x61707865402444C7;
                *dst = result;
                result = (struct Struct_1_t *)v_28;
                dst2 = (__int64 *)v_38;
                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                if (result <= 7) {
                    v_20 = 1;
                    a1 = rsp + 40;
                    sub_1400F2D20(a1, dst2, 8, 1);
                    dst2 = (__int64 *)v_38;
                }
                result = (struct Struct_1_t *)v_30;
                a1 = *dst;
                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                dst2 += 8;
                v_38 = (__int64)dst2;
                off_140108030(a1, dst2);
                ((__int64 (*)())off_140108038)(result, 0, dst);
                sub_14002EDF0(0, 11);
                if (result != 0) {
                    dst = (__int64 *)result;
                    result = 0x3320646E442444C7;
                    *dst = result;
                    result = (struct Struct_1_t *)v_28;
                    dst2 = (__int64 *)v_38;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                    if (result <= 7) {
                        v_20 = 1;
                        a1 = rsp + 40;
                        sub_1400F2D20(a1, dst2, 8, 1);
                        dst2 = (__int64 *)v_38;
                    }
                    result = (struct Struct_1_t *)v_30;
                    a1 = *dst;
                    *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                    dst2 += 8;
                    v_38 = (__int64)dst2;
                    off_140108030(a1, dst2);
                    ((__int64 (*)())off_140108038)(result, 0, dst);
                    v_40 = 16;
                    sub_14002EDF0(0, 11);
                    if (result != 0) {
                        dst = (__int64 *)result;
                        result = 0x79622D32482444C7;
                        *dst = result;
                        result = (struct Struct_1_t *)v_28;
                        dst2 = (__int64 *)v_38;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                        if (result <= 7) {
                            v_20 = 1;
                            a1 = rsp + 40;
                            sub_1400F2D20(a1, dst2, 8, 1);
                            dst2 = (__int64 *)v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        a1 = *dst;
                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                        dst2 += 8;
                        v_38 = (__int64)dst2;
                        off_140108030(a1, dst2);
                        ((__int64 (*)())off_140108038)(result, 0, dst);
                        sub_14002EDF0(0, 11);
                        if (result != 0) {
                            dst = (__int64 *)result;
                            result = 0x6B2065744C2444C7;
                            *dst = result;
                            result = (struct Struct_1_t *)v_28;
                            dst2 = (__int64 *)v_38;
                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                            v_60 = (__int64)ptr2;
                            if (result <= 7) {
                                v_20 = 1;
                                a1 = rsp + 40;
                                sub_1400F2D20(a1, dst2, 8, 1);
                                dst2 = (__int64 *)v_38;
                            }
                            result = (struct Struct_1_t *)v_30;
                            a1 = *dst;
                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                            dst2 += 8;
                            v_38 = (__int64)dst2;
                            off_140108030(a1, dst2);
                            ((__int64 (*)())off_140108038)(result, 0, dst);
                            dst = rsp + 72;
                            v9 = rsp + 40;
                            ptr = off_140108038;
                            dst3 = 0;
                            sub_14002EDF0(0, 8);
                            while (result != 0) {
                                v_48 = 8;
                                v_50 = (__int64)result;
                                *(__int64 *)result = (__int64)(0x8B41);
                                v_58 = 2;
                                sub_1400D4F50(dst, 0, 6, dst3);
                                v12 = v_48;
                                src = (__int64 *)v_50;
                                src2 = (__int64 *)v_58;
                                result = (struct Struct_1_t *)v_28;
                                ptr2 = (struct Struct_3_t *)v_38;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                if (src2 > result) {
                                    v_20 = 1;
                                    sub_1400F2D20(v9, ptr2, src2, 1);
                                    ptr2 = (struct Struct_3_t *)v_38;
                                }
                                a1 = (size_t *)v_30;
                                a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                sub_1400F27F0(a1, src, src2);
                                ptr2 = (struct Struct_3_t *)((__int64)ptr2 + (__int64)src2);
                                v_38 = (__int64)ptr2;
                                if (v12 == 0) {
                                    sub_14002EDF0(0, 8);
                                    if (result != 0) {
                                        v7 = dst3 + 80;
                                        v_48 = 8;
                                        v_50 = (__int64)result;
                                        *(__int64 *)result = (__int64)(137);
                                        v_58 = 1;
                                        sub_1400D4F50(dst, 0, 4, v7);
                                        v12 = v_48;
                                        src = (__int64 *)v_50;
                                        src2 = (__int64 *)v_58;
                                        result = (struct Struct_1_t *)v_28;
                                        ptr2 = (struct Struct_3_t *)v_38;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                        if (src2 > result) {
                                            v_20 = 1;
                                            sub_1400F2D20(v9, ptr2, src2, 1);
                                            ptr2 = (struct Struct_3_t *)v_38;
                                        }
                                        a1 = (size_t *)v_30;
                                        a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                        sub_1400F27F0(a1, src, src2);
                                        ptr2 = (struct Struct_3_t *)((__int64)ptr2 + (__int64)src2);
                                        v_38 = (__int64)ptr2;
                                        if (v12 == 0) {
                                            dst3 += 4;
                                            v_40 = 34;
                                            sub_14002EDF0(0, 8);
                                            if (result != 0) {
                                                dst = (__int64 *)result;
                                                *(__int64 *)result = (__int64)(0x8B41);
                                                result->field_2 = 7;
                                                result = (struct Struct_1_t *)v_28;
                                                dst2 = (__int64 *)v_38;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, dst2, 3, 1);
                                                    dst2 = (__int64 *)v_38;
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                a1 = (size_t *)arg_2;
                                                *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
                                                a1 = *dst;
                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                dst2 += 3;
                                                v_38 = (__int64)dst2;
                                                off_140108030(a1, dst2);
                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                sub_14002EDF0(0, 8);
                                                if (result != 0) {
                                                    dst = (__int64 *)result;
                                                    *(__int64 *)result = (__int64)(0x4489);
                                                    result->field_2 = 36;
                                                    result = (struct Struct_1_t *)v_28;
                                                    dst2 = (__int64 *)v_38;
                                                    arg_3 = 116;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                    if (result <= 3) {
                                                        v_20 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400F2D20(a1, dst2, 4, 1);
                                                        dst2 = (__int64 *)v_38;
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    a1 = *dst;
                                                    *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                    dst2 += 4;
                                                    v_38 = (__int64)dst2;
                                                    off_140108030(a1, dst2);
                                                    ((__int64 (*)())off_140108038)(result, 0, dst);
                                                    v_40 = 36;
                                                    sub_14002EDF0(0, 8);
                                                    if (result != 0) {
                                                        dst = (__int64 *)result;
                                                        *(__int64 *)result = (__int64)(0x8B41);
                                                        result->field_2 = 71;
                                                        result = (struct Struct_1_t *)v_28;
                                                        dst2 = (__int64 *)v_38;
                                                        arg_3 = 4;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, dst2, 4, 1);
                                                            dst2 = (__int64 *)v_38;
                                                        }
                                                        result = (struct Struct_1_t *)v_30;
                                                        a1 = *dst;
                                                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                        dst2 += 4;
                                                        v_38 = (__int64)dst2;
                                                        off_140108030(a1, dst2);
                                                        ((__int64 (*)())off_140108038)(result, 0, dst);
                                                        sub_14002EDF0(0, 8);
                                                        if (result != 0) {
                                                            dst = (__int64 *)result;
                                                            *(__int64 *)result = (__int64)(0x4489);
                                                            result->field_2 = 36;
                                                            result = (struct Struct_1_t *)v_28;
                                                            dst2 = (__int64 *)v_38;
                                                            arg_3 = 120;
                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                            if (result <= 3) {
                                                                v_20 = 1;
                                                                a1 = rsp + 40;
                                                                sub_1400F2D20(a1, dst2, 4, 1);
                                                                dst2 = (__int64 *)v_38;
                                                            }
                                                            result = (struct Struct_1_t *)v_30;
                                                            a1 = *dst;
                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                            dst2 += 4;
                                                            v_38 = (__int64)dst2;
                                                            off_140108030(a1, dst2);
                                                            ((__int64 (*)())off_140108038)(result, 0, dst);
                                                            v_40 = 38;
                                                            sub_14002EDF0(0, 8);
                                                            if (result != 0) {
                                                                dst = (__int64 *)result;
                                                                *(__int64 *)result = (__int64)(0x8B41);
                                                                result->field_2 = 71;
                                                                result = (struct Struct_1_t *)v_28;
                                                                dst2 = (__int64 *)v_38;
                                                                arg_3 = 8;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                if (result <= 3) {
                                                                    v_20 = 1;
                                                                    a1 = rsp + 40;
                                                                    sub_1400F2D20(a1, dst2, 4, 1);
                                                                    dst2 = (__int64 *)v_38;
                                                                }
                                                                result = (struct Struct_1_t *)v_30;
                                                                a1 = *dst;
                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                dst2 += 4;
                                                                v_38 = (__int64)dst2;
                                                                off_140108030(a1, dst2);
                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                sub_14002EDF0(0, 8);
                                                                if (result != 0) {
                                                                    dst = (__int64 *)result;
                                                                    *(__int64 *)result = (__int64)(0x4489);
                                                                    result->field_2 = 36;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    ptr2 = (struct Struct_3_t *)v_38;
                                                                    arg_3 = 124;
                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                    if (result <= 3) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, ptr2, 4, 1);
                                                                        ptr2 = (struct Struct_3_t *)v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    a1 = *dst;
                                                                    *(__int64 *)((__int64)result + (__int64)ptr2) = a1;
                                                                    ptr2 += 4;
                                                                    v_38 = (__int64)ptr2;
                                                                    off_140108030(a1);
                                                                    ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                    sub_14002EDF0(0, 7);
                                                                    if (result != 0) {
                                                                        dst3 = (__int64 *)result;
                                                                        *(__int64 *)result = (__int64)(0xFD8349);
                                                                        result = (struct Struct_1_t *)v_28;
                                                                        dst2 = (__int64 *)v_38;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                        if (result <= 3) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, dst2, 4, 1);
                                                                            dst2 = (__int64 *)v_38;
                                                                        }
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        a1 = *dst3;
                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                        v_68 = (__int64)dst2;
                                                                        result = dst2 + 4;
                                                                        v_38 = (__int64)result;
                                                                        off_140108030(a1, dst2);
                                                                        ((__int64 (*)())off_140108038)(result, 0, dst3);
                                                                        v_40 = 41;
                                                                        sub_14002EDF0(0, 6);
                                                                        if (result != 0) {
                                                                            dst3 = (__int64 *)result;
                                                                            *(__int64 *)result = (__int64)(0x840F);
                                                                            result->field_2 = 0;
                                                                            result = (struct Struct_1_t *)v_28;
                                                                            dst2 = (__int64 *)v_38;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                            if (result <= 5) {
                                                                                v_20 = 1;
                                                                                a1 = rsp + 40;
                                                                                sub_1400F2D20(a1, dst2, 6, 1);
                                                                                dst2 = (__int64 *)v_38;
                                                                            }
                                                                            result = (struct Struct_1_t *)v_30;
                                                                            a1 = (size_t *)arg_4;
                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                            a1 = *dst3;
                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                            dst2 += 6;
                                                                            v_38 = (__int64)dst2;
                                                                            off_140108030(a1, dst2);
                                                                            ((__int64 (*)())off_140108038)(result, 0, dst3);
                                                                            sub_14002EDF0(0, 8);
                                                                            if (result != 0) {
                                                                                dst3 = (__int64 *)result;
                                                                                *(__int64 *)result = (__int64)(0x6C89);
                                                                                result->field_2 = 36;
                                                                                result = (struct Struct_1_t *)v_28;
                                                                                dst2 = (__int64 *)v_38;
                                                                                arg_3 = 112;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                v_70 = (__int64)ptr2;
                                                                                if (result <= 3) {
                                                                                    v_20 = 1;
                                                                                    a1 = rsp + 40;
                                                                                    sub_1400F2D20(a1, dst2, 4, 1);
                                                                                    dst2 = (__int64 *)v_38;
                                                                                }
                                                                                result = (struct Struct_1_t *)v_30;
                                                                                a1 = *dst3;
                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                dst2 += 4;
                                                                                v_38 = (__int64)dst2;
                                                                                off_140108030(a1, dst2);
                                                                                ((__int64 (*)())off_140108038)(result, 0, dst3);
                                                                                dst3 = rsp + 72;
                                                                                src = rsp + 40;
                                                                                src2 = 0;
                                                                                sub_14002EDF0(0, 8);
                                                                                while (result != 0) {
                                                                                    v7 = src2 + 64;
                                                                                    v_48 = 8;
                                                                                    v_50 = (__int64)result;
                                                                                    *(__int64 *)result = (__int64)(139);
                                                                                    v_58 = 1;
                                                                                    sub_1400D4F50(dst3, 0, 4, v7);
                                                                                    dst = (__int64 *)v_48;
                                                                                    v9 = v_50;
                                                                                    v12 = v_58;
                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                    ptr2 = (struct Struct_3_t *)v_38;
                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                                    if (v12 > result) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(src, ptr2, v12, 1);
                                                                                        ptr2 = (struct Struct_3_t *)v_38;
                                                                                    }
                                                                                    a1 = (size_t *)v_30;
                                                                                    a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                                                                    sub_1400F27F0(a1, v9, v12);
                                                                                    ptr2 += v12;
                                                                                    v_38 = (__int64)ptr2;
                                                                                    if (dst == 0) {
                                                                                        sub_14002EDF0(0, 8);
                                                                                        if (result != 0) {
                                                                                            v_48 = 8;
                                                                                            v_50 = (__int64)result;
                                                                                            *(__int64 *)result = (__int64)(137);
                                                                                            v_58 = 1;
                                                                                            sub_1400D4F50(dst3, 0, 4, src2);
                                                                                            dst = (__int64 *)v_48;
                                                                                            v9 = v_50;
                                                                                            v12 = v_58;
                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                            ptr2 = (struct Struct_3_t *)v_38;
                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                                            if (v12 > result) {
                                                                                                v_20 = 1;
                                                                                                sub_1400F2D20(src, ptr2, v12, 1);
                                                                                                ptr2 = (struct Struct_3_t *)v_38;
                                                                                            }
                                                                                            a1 = (size_t *)v_30;
                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                                                                            sub_1400F27F0(a1, v9, v12);
                                                                                            ptr2 += v12;
                                                                                            v_38 = (__int64)ptr2;
                                                                                            if (dst == 0) {
                                                                                                src2 += 4;
                                                                                                v_40 = 75;
                                                                                                dst3 = rsp + 40;
                                                                                                src = rsp + 64;
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                sub_1400D5190(dst3, src, 0);
                                                                                                result = (struct Struct_1_t *)v_40;
                                                                                                v_80 = (__int64)result;
                                                                                                result += 64;
                                                                                                v_78 = (__int64)result;
                                                                                                src = rsp + 72;
                                                                                                src2 = 0;
                                                                                                sub_14002EDF0(0, 8);
                                                                                                while (result != 0) {
                                                                                                    v7 = src2 + 64;
                                                                                                    v_48 = 8;
                                                                                                    v_50 = (__int64)result;
                                                                                                    *(__int64 *)result = (__int64)(139);
                                                                                                    v_58 = 1;
                                                                                                    sub_1400D4F50(src, 0, 4, v7);
                                                                                                    dst = (__int64 *)v_48;
                                                                                                    v9 = v_50;
                                                                                                    v12 = v_58;
                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                    ptr2 = (struct Struct_3_t *)v_38;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                                                    if (v12 > result) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(dst3, ptr2, v12, 1);
                                                                                                        ptr2 = (struct Struct_3_t *)v_38;
                                                                                                    }
                                                                                                    a1 = (size_t *)v_30;
                                                                                                    a1 = (size_t *)((__int64)a1 + (__int64)ptr2);
                                                                                                    sub_1400F27F0(a1, v9, v12);
                                                                                                    ptr2 += v12;
                                                                                                    v_38 = (__int64)ptr2;
                                                                                                    if (dst == 0) {
                                                                                                        sub_14002EDF0(0, 8);
                                                                                                        if (result != 0) {
                                                                                                            v_48 = 8;
                                                                                                            v_50 = (__int64)result;
                                                                                                            *(__int64 *)result = (__int64)(139);
                                                                                                            v_58 = 1;
                                                                                                            sub_1400D4F50(src, 1, 4, src2);
                                                                                                            dst = (__int64 *)v_48;
                                                                                                            v12 = v_50;
                                                                                                            ptr2 = (struct Struct_3_t *)v_58;
                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                            v9 = v_38;
                                                                                                            result -= v9;
                                                                                                            if (ptr2 > result) {
                                                                                                                v_20 = 1;
                                                                                                                sub_1400F2D20(dst3, v9, ptr2, 1);
                                                                                                                v9 = v_38;
                                                                                                            }
                                                                                                            a1 = (size_t *)v_30;
                                                                                                            a1 += v9;
                                                                                                            sub_1400F27F0(a1, v12, ptr2);
                                                                                                            v9 += (__int64)ptr2;
                                                                                                            v_38 = v9;
                                                                                                            if (dst == 0) {
                                                                                                                if (v9 == v_28) {
                                                                                                                    sub_1400F3510(dst3);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)(result + v9) = (__int64)(1);
                                                                                                                result = v9 + 1;
                                                                                                                v_38 = (__int64)result;
                                                                                                                if (result == v_28) {
                                                                                                                    sub_1400F3510(dst3);
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                *(__int64 *)(result + v9 + 1) = (__int64)(193);
                                                                                                                v9 += 2;
                                                                                                                v_38 = v9;
                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                if (result != 0) {
                                                                                                                    v_48 = 8;
                                                                                                                    v_50 = (__int64)result;
                                                                                                                    *(__int64 *)result = (__int64)(137);
                                                                                                                    v_58 = 1;
                                                                                                                    sub_1400D4F50(src, 1, 4, src2);
                                                                                                                    dst = (__int64 *)v_48;
                                                                                                                    v9 = v_50;
                                                                                                                    ptr2 = (struct Struct_3_t *)v_58;
                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                    v12 = v_38;
                                                                                                                    result -= v12;
                                                                                                                    if (ptr2 > result) {
                                                                                                                        v_20 = 1;
                                                                                                                        sub_1400F2D20(dst3, v12, ptr2, 1);
                                                                                                                        v12 = v_38;
                                                                                                                    }
                                                                                                                    a1 = (size_t *)v_30;
                                                                                                                    a1 += v12;
                                                                                                                    sub_1400F27F0(a1, v9, ptr2);
                                                                                                                    v12 += (__int64)ptr2;
                                                                                                                    v_38 = v12;
                                                                                                                    if (dst == 0) {
                                                                                                                        src2 += 4;
                                                                                                                        result = (struct Struct_1_t *)v_78;
                                                                                                                        v_40 = (__int64)result;
                                                                                                                        ptr2 = (struct Struct_3_t *)v_38;
                                                                                                                        if (ptr2 == v_28) {
                                                                                                                            a1 = rsp + 40;
                                                                                                                            sub_1400F3510(a1);
                                                                                                                        }
                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr2) = 72;
                                                                                                                        result = ptr2 + 1;
                                                                                                                        v_38 = (__int64)result;
                                                                                                                        dst = (__int64 *)v_80;
                                                                                                                        if (result == v_28) {
                                                                                                                            a1 = rsp + 40;
                                                                                                                            sub_1400F3510(a1);
                                                                                                                        }
                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr2 + 1) = 49;
                                                                                                                        result = ptr2 + 2;
                                                                                                                        v_38 = (__int64)result;
                                                                                                                        if (result == v_28) {
                                                                                                                            a1 = rsp + 40;
                                                                                                                            sub_1400F3510(a1);
                                                                                                                        }
                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 255;
                                                                                                                        ptr2 += 3;
                                                                                                                        v_38 = (__int64)ptr2;
                                                                                                                        sub_14002EDF0(0, 7);
                                                                                                                        if (result != 0) {
                                                                                                                            dst3 = (__int64 *)result;
                                                                                                                            *(__int64 *)result = (__int64)(0xFD8349);
                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                            if (result <= 3) {
                                                                                                                                v_20 = 1;
                                                                                                                                a1 = rsp + 40;
                                                                                                                                sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                            }
                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                            a1 = *dst3;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                            dst2 += 4;
                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                            off_140108030(a1, dst2);
                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst3);
                                                                                                                            result = dst + 66;
                                                                                                                            v_40 = (__int64)result;
                                                                                                                            dst3 = (__int64 *)v_38;
                                                                                                                            sub_14002EDF0(0, 6);
                                                                                                                            if (result != 0) {
                                                                                                                                src = (__int64 *)result;
                                                                                                                                *(__int64 *)result = (__int64)(0x840F);
                                                                                                                                result->field_2 = 0;
                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                if (result <= 5) {
                                                                                                                                    v_20 = 1;
                                                                                                                                    a1 = rsp + 40;
                                                                                                                                    sub_1400F2D20(a1, dst2, 6, 1);
                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                }
                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                a1 = (size_t *)arg_4;
                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                                                                                a1 = *src;
                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                dst2 += 6;
                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                off_140108030(a1, dst2);
                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, src);
                                                                                                                                sub_14002EDF0(0, 7);
                                                                                                                                if (result != 0) {
                                                                                                                                    src = (__int64 *)result;
                                                                                                                                    *(__int64 *)result = (__int64)(0x40FF8348);
                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                    if (result <= 3) {
                                                                                                                                        v_20 = 1;
                                                                                                                                        a1 = rsp + 40;
                                                                                                                                        sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                    }
                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                    a1 = *src;
                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                    dst2 += 4;
                                                                                                                                    v_38 = (__int64)dst2;
                                                                                                                                    off_140108030(a1, dst2);
                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, src);
                                                                                                                                    result = dst + 68;
                                                                                                                                    v_40 = (__int64)result;
                                                                                                                                    src = (__int64 *)v_38;
                                                                                                                                    sub_14002EDF0(0, 6);
                                                                                                                                    if (result != 0) {
                                                                                                                                        src2 = (__int64 *)result;
                                                                                                                                        *(__int64 *)result = (__int64)(0x840F);
                                                                                                                                        result->field_2 = 0;
                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                        if (result <= 5) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F2D20(a1, dst2, 6, 1);
                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        a1 = (size_t *)arg_4;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                                                                                        a1 = *src2;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                        dst2 += 6;
                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                        off_140108030(a1, dst2);
                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                        sub_14002EDF0(0, 9);
                                                                                                                                        if (result != 0) {
                                                                                                                                            src2 = (__int64 *)result;
                                                                                                                                            *(__int64 *)result = (__int64)(0xB60F);
                                                                                                                                            result->field_2 = 4;
                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                            arg_3 = 60;
                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                            if (result <= 3) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                            }
                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                            a1 = *src2;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                            dst2 += 4;
                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                            off_140108030(a1, dst2);
                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                            result = dst + 70;
                                                                                                                                            v_40 = (__int64)result;
                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                            if (result != 0) {
                                                                                                                                                src2 = (__int64 *)result;
                                                                                                                                                *(__int64 *)result = (__int64)(0x1CB60F41);
                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                arg_4 = 36;
                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                if (result <= 4) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                    sub_1400F2D20(a1, dst2, 5, 1);
                                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                                }
                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                a1 = (size_t *)arg_4;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                                                                                                a1 = *src2;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                dst2 += 5;
                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                off_140108030(a1, dst2);
                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                                src2 = (__int64 *)v_38;
                                                                                                                                                if (src2 == v_28) {
                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                    sub_1400F3510(a1);
                                                                                                                                                }
                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)src2) = 49;
                                                                                                                                                result = src2 + 1;
                                                                                                                                                v_38 = (__int64)result;
                                                                                                                                                if (result == v_28) {
                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                    sub_1400F3510(a1);
                                                                                                                                                }
                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)src2 + 1) = 195;
                                                                                                                                                src2 += 2;
                                                                                                                                                v_38 = (__int64)src2;
                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                                                                                                if (result <= 3) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                    sub_1400F2D20(a1, src2, 4, 1);
                                                                                                                                                    src2 = (__int64 *)v_38;
                                                                                                                                                }
                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)src2) = 0x241C8841;
                                                                                                                                                src2 += 4;
                                                                                                                                                v_38 = (__int64)src2;
                                                                                                                                                result = dst + 73;
                                                                                                                                                v_40 = (__int64)result;
                                                                                                                                                sub_14002EDF0(0, 7);
                                                                                                                                                if (result != 0) {
                                                                                                                                                    src2 = (__int64 *)result;
                                                                                                                                                    *(__int64 *)result = (__int64)(0x1C78348);
                                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                    if (result <= 3) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                        sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                    }
                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                    a1 = *src2;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                    dst2 += 4;
                                                                                                                                                    v_38 = (__int64)dst2;
                                                                                                                                                    off_140108030(a1, dst2);
                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                                    sub_14002EDF0(0, 7);
                                                                                                                                                    if (result != 0) {
                                                                                                                                                        src2 = (__int64 *)result;
                                                                                                                                                        *(__int64 *)result = (__int64)(0x1C48349);
                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                        if (result <= 3) {
                                                                                                                                                            v_20 = 1;
                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                            sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                        }
                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                        a1 = *src2;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                        dst2 += 4;
                                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                                        off_140108030(a1, dst2);
                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                                        result = dst + 75;
                                                                                                                                                        v_40 = (__int64)result;
                                                                                                                                                        sub_14002EDF0(0, 7);
                                                                                                                                                        if (result != 0) {
                                                                                                                                                            src2 = (__int64 *)result;
                                                                                                                                                            *(__int64 *)result = (__int64)(0x1ED8349);
                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                v_20 = 1;
                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                            }
                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                            a1 = *src2;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                            dst2 += 4;
                                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                                            off_140108030(a1, dst2);
                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                                            result = (struct Struct_1_t *)v_38;
                                                                                                                                                            result += 5;
                                                                                                                                                            if (!((result < 0))) {
                                                                                                                                                                ptr2 = (struct Struct_3_t *)((__int64)ptr2 - (__int64)result);
                                                                                                                                                                result = (struct Struct_1_t *)ptr2;
                                                                                                                                                                if (ptr2 == ptr2) {
                                                                                                                                                                    sub_14002EDF0(0, 5);
                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                        src2 = (__int64 *)result;
                                                                                                                                                                        *(__int64 *)result = (__int64)(233);
                                                                                                                                                                        result->field_1 = ptr2;
                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                            sub_1400F2D20(a1, dst2, 5, 1);
                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                        }
                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                        a1 = (size_t *)arg_4;
                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                                                                                                                        a1 = *src2;
                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                        dst2 += 5;
                                                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                                                        off_140108030(a1, dst2);
                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                                                        dst += 77;
                                                                                                                                                                        v_40 = (__int64)dst;
                                                                                                                                                                        dst2 = dst3;
                                                                                                                                                                        dst2 += 6;
                                                                                                                                                                        if (!((dst2 < 0))) {
                                                                                                                                                                            v6 = v_38;
                                                                                                                                                                            result = (struct Struct_1_t *)v6;
                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                            a1 = (size_t *)result;
                                                                                                                                                                            if (result == result) {
                                                                                                                                                                                if (v6 < dst2) {
                                                                                                                                                                                    return (__int64)a1;
                                                                                                                                                                                }
                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)dst3 + 2) = result;
                                                                                                                                                                                dst2 = src;
                                                                                                                                                                                dst2 += 6;
                                                                                                                                                                                if (!((dst2 < 0))) {
                                                                                                                                                                                    v6 -= (__int64)dst2;
                                                                                                                                                                                    result = (struct Struct_1_t *)v6;
                                                                                                                                                                                    if (v6 == v6) {
                                                                                                                                                                                        result = (struct Struct_1_t *)v_38;
                                                                                                                                                                                        if (dst2 > result) {
                                                                                                                                                                                            return (__int64)result;
                                                                                                                                                                                        }
                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src + 2) = v6;
                                                                                                                                                                                        sub_14002EDF0(0, 7, v6);
                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                            dst3 = (__int64 *)result;
                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x1C58348);
                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                            ptr2 = (struct Struct_3_t *)v_70;
                                                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                sub_1400F2D20(a1, dst2, 4, 1);
                                                                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                                                            }
                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                            a1 = *dst3;
                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                            dst2 += 4;
                                                                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                                                                            off_140108030(a1, dst2);
                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst3);
                                                                                                                                                                                            result = (struct Struct_1_t *)v_38;
                                                                                                                                                                                            result += 5;
                                                                                                                                                                                            if (!((result < 0))) {
                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)((__int64)ptr2 - (__int64)result);
                                                                                                                                                                                                result = (struct Struct_1_t *)ptr2;
                                                                                                                                                                                                if (ptr2 == ptr2) {
                                                                                                                                                                                                    sub_14002EDF0(0, 5);
                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                        dst3 = (__int64 *)result;
                                                                                                                                                                                                        *(__int64 *)result = (__int64)(233);
                                                                                                                                                                                                        result->field_1 = ptr2;
                                                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                            sub_1400F2D20(a1, dst2, 5, 1);
                                                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                                                        }
                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                        a1 = (size_t *)arg_4;
                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = a1;
                                                                                                                                                                                                        a1 = *dst3;
                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                        dst2 += 5;
                                                                                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                                                                                        off_140108030(a1, dst2);
                                                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst3);
                                                                                                                                                                                                        a1 = (size_t *)v_68;
                                                                                                                                                                                                        dst2 = (__int64 *)a1;
                                                                                                                                                                                                        dst2 += 10;
                                                                                                                                                                                                        if (!((dst2 < 0))) {
                                                                                                                                                                                                            v6 = v_38;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v6;
                                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                            if (result == result) {
                                                                                                                                                                                                                if (v6 < dst2) {
                                                                                                                                                                                                                    return (__int64)result;
                                                                                                                                                                                                                }
                                                                                                                                                                                                                dst2 = (__int64 *)v_30;
                                                                                                                                                                                                                *(__int64 *)((__int64)dst2 + (__int64)a1 + 6) = result;
                                                                                                                                                                                                                sub_14002EDF0(0, 7, v6, result);
                                                                                                                                                                                                                if (result == 0) {
                                                                                                                                                                                                                    sub_1400F3326(1, 7);
                                                                                                                                                                                                                    result = &off_14011B3E0;
                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                    a1 = &off_14011B3C3;
                                                                                                                                                                                                                    v7 = &off_14011D3F8;
                                                                                                                                                                                                                    v6 = rsp + 72;
                                                                                                                                                                                                                    sub_1400F3B80(a1, 23, v6, v7);
                                                                                                                                                                                                                    sub_1400F3326(1, 11);
                                                                                                                                                                                                                    sub_1400F3326(1, 6);
                                                                                                                                                                                                                    sub_1400F3326(1, 5);
                                                                                                                                                                                                                    sub_1400F3326(1, 9);
                                                                                                                                                                                                                    result = &off_14011CE40;
                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                    a1 = &off_14011CE28;
                                                                                                                                                                                                                    v7 = &off_14011D3F8;
                                                                                                                                                                                                                    v6 = rsp + 72;
                                                                                                                                                                                                                    sub_1400F3B80(a1, 17, v6, v7);
                                                                                                                                                                                                                    result = &off_14011CE68;
                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                    a1 = &off_14011CE58;
                                                                                                                                                                                                                    v7 = &off_14011D3F8;
                                                                                                                                                                                                                    v6 = rsp + 72;
                                                                                                                                                                                                                    sub_1400F3B80(a1, 13, v6, v7);
                                                                                                                                                                                                                    result = &off_14011CE90;
                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                    a1 = &off_14011CE80;
                                                                                                                                                                                                                    v7 = &off_14011D3F8;
                                                                                                                                                                                                                    v6 = rsp + 72;
                                                                                                                                                                                                                    sub_1400F3B80(a1, 14, v6, v7);
                                                                                                                                                                                                                    result = &off_14011C570;
                                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                                    a1 = &off_14011C562;
                                                                                                                                                                                                                    v7 = &off_14011D3F8;
                                                                                                                                                                                                                    v6 = rsp + 72;
                                                                                                                                                                                                                    sub_1400F3B80(a1, 14, v6, v7);
                                                                                                                                                                                                                } else {
                                                                                                                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x8148);
                                                                                                                                                                                                                    result->field_3 = 128;
                                                                                                                                                                                                                    result->field_2 = 196;
                                                                                                                                                                                                                    ptr2 = (struct Struct_3_t *)v_28;
                                                                                                                                                                                                                    dst = (__int64 *)v_38;
                                                                                                                                                                                                                    result = (struct Struct_1_t *)ptr2;
                                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F2D20(a1, dst, 7, 1);
                                                                                                                                                                                                                        ptr2 = (struct Struct_3_t *)v_28;
                                                                                                                                                                                                                        dst = (__int64 *)v_38;
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    dst3 = (__int64 *)v_30;
                                                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                                                    a1 = ptr->field_3;
                                                                                                                                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)dst + 3) = a1;
                                                                                                                                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)dst) = result;
                                                                                                                                                                                                                    src = dst + 7;
                                                                                                                                                                                                                    v_38 = (__int64)src;
                                                                                                                                                                                                                    off_140108030(a1);
                                                                                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                                                                                                    if (src == ptr2) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)dst + 7) = 65;
                                                                                                                                                                                                                    result = dst + 8;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    ptr2 = (struct Struct_3_t *)v_60;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 8) = 95;
                                                                                                                                                                                                                    result = dst + 9;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 9) = 65;
                                                                                                                                                                                                                    result = dst + 10;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 10) = 94;
                                                                                                                                                                                                                    result = dst + 11;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 11) = 65;
                                                                                                                                                                                                                    result = dst + 12;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 12) = 93;
                                                                                                                                                                                                                    result = dst + 13;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 13) = 65;
                                                                                                                                                                                                                    result = dst + 14;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 14) = 92;
                                                                                                                                                                                                                    result = dst + 15;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 15) = 95;
                                                                                                                                                                                                                    result = dst + 16;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 16) = 94;
                                                                                                                                                                                                                    result = dst + 17;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 17) = 91;
                                                                                                                                                                                                                    result = dst + 18;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 18) = 93;
                                                                                                                                                                                                                    result = dst + 19;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 19) = 195;
                                                                                                                                                                                                                    dst += 20;
                                                                                                                                                                                                                    v_38 = (__int64)dst;
                                                                                                                                                                                                                    ptr2->field_10 = dst;
                                                                                                                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                                                                                                                                                    _mm_storeu_si128((__m128i *)ptr2, xmm0);
                                                                                                                                                                                                                    return _mm_cvtsi128_si64(xmm0);
                                                                                                                                                                                                                }
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = &off_14011C588;
                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                            a1 = &off_14011BC90;
                                                                                                                                                                                                            v7 = &off_14011D3F8;
                                                                                                                                                                                                            v6 = rsp + 72;
                                                                                                                                                                                                            sub_1400F3B80(a1, 8, v6, v7);
                                                                                                                                                                                                            src2 = dst2;
                                                                                                                                                                                                            dst3 = (__int64 *)a1;
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
                                                                                                                                                                                                            if (result == 0) JUMPOUT(0x140106762);
                                                                                                                                                                                                            ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x8148);
                                                                                                                                                                                                            result->field_3 = 0x490;
                                                                                                                                                                                                            result->field_2 = 236;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                            if (result <= 6) JUMPOUT(0x140105b88);
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            a1 = ptr2->field_0;
                                                                                                                                                                                                            v6 = ptr2->field_3;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 3) = v6;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                            dst2 += 7;
                                                                                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                                                                                            off_140108030(a1, dst2, v6);
                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                            sub_14002EDF0(0, 3);
                                                                                                                                                                                                            if (result == 0) JUMPOUT(0x140105b6a);
                                                                                                                                                                                                            ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x8949);
                                                                                                                                                                                                            result->field_2 = 207;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                            if (result <= 2) JUMPOUT(0x140105bb1);
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            a1 = ptr2->field_2;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
                                                                                                                                                                                                            a1 = ptr2->field_0;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                            dst2 += 3;
                                                                                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                                                                                            off_140108030(a1, dst2);
                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                            sub_14002EDF0(0, 3);
                                                                                                                                                                                                            if (result == 0) JUMPOUT(0x140105b6a);
                                                                                                                                                                                                            ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x8949);
                                                                                                                                                                                                            result->field_2 = 214;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                            if (result <= 2) JUMPOUT(0x140105bda);
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            a1 = ptr2->field_2;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
                                                                                                                                                                                                            a1 = ptr2->field_0;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                            dst2 += 3;
                                                                                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                                                                                            off_140108030(a1, dst2);
                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                            sub_14002EDF0(0, 3);
                                                                                                                                                                                                            if (result == 0) JUMPOUT(0x140105b6a);
                                                                                                                                                                                                            ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x894D);
                                                                                                                                                                                                            result->field_2 = 197;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                            dst = (__int64 *)v_38;
                                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                            if (result <= 2) JUMPOUT(0x140105c03);
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            a1 = ptr2->field_2;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst + 2) = a1;
                                                                                                                                                                                                            a1 = ptr2->field_0;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst) = a1;
                                                                                                                                                                                                            dst += 3;
                                                                                                                                                                                                            v_38 = (__int64)dst;
                                                                                                                                                                                                            off_140108030(a1);
                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                            v9 = arg_2d;
                                                                                                                                                                                                            if (v9 != 0) {
                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140105b6a);
                                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x894C);
                                                                                                                                                                                                                result->field_2 = 205;
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                dst = (__int64 *)v_38;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x140106364);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                a1 = ptr2->field_2;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst + 2) = a1;
                                                                                                                                                                                                                a1 = ptr2->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst) = a1;
                                                                                                                                                                                                                dst += 3;
                                                                                                                                                                                                                v_38 = (__int64)dst;
                                                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            v12 = *src2;
                                                                                                                                                                                                            if (v12 != 0) {
                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140105b6a);
                                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x894C);
                                                                                                                                                                                                                result->field_2 = 249;
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x140106390);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                a1 = ptr2->field_2;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2 + 2) = a1;
                                                                                                                                                                                                                a1 = ptr2->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                                dst2 += 3;
                                                                                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                                                                                off_140108030(a1, dst2);
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140105b6a);
                                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x894C);
                                                                                                                                                                                                                result->field_2 = 234;
                                                                                                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                result = (struct Struct_1_t *)dst;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x14010651e);
                                                                                                                                                                                                                ptr = (struct Struct_2_t *)v_30;
                                                                                                                                                                                                                result = ptr2->field_2;
                                                                                                                                                                                                                src = dst2;
                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)dst2 + 2) = result;
                                                                                                                                                                                                                result = ptr2->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)dst2) = result;
                                                                                                                                                                                                                src += 3;
                                                                                                                                                                                                                v_38 = (__int64)src;
                                                                                                                                                                                                                off_140108030(a1, dst2);
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                                result = (struct Struct_1_t *)dst;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)src);
                                                                                                                                                                                                                v_48 = (__int64)src;
                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x14010654c);
                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)src + 2) = 5;
                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)src) = 0x8D4C;
                                                                                                                                                                                                                src += 3;
                                                                                                                                                                                                                v_38 = (__int64)src;
                                                                                                                                                                                                                dst = (__int64 *)((__int64)dst - (__int64)src);
                                                                                                                                                                                                                if (dst <= 3) JUMPOUT(0x140106584);
                                                                                                                                                                                                                *(__int64 *)((__int64)ptr + (__int64)src) = 0;
                                                                                                                                                                                                                src += 4;
                                                                                                                                                                                                                v_38 = (__int64)src;
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                a1 = (size_t *)result;
                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)src);
                                                                                                                                                                                                                dst2 = src;
                                                                                                                                                                                                                v_78 = (__int64)src;
                                                                                                                                                                                                                if (a1 <= 2) JUMPOUT(0x1401065b5);
                                                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)dst2 + 2) = 13;
                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)dst2) = 0x8D4C;
                                                                                                                                                                                                                dst2 += 3;
                                                                                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                if (result <= 3) JUMPOUT(0x1401065e6);
                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)dst2) = 0;
                                                                                                                                                                                                                dst2 += 4;
                                                                                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                                                                                sub_14002EDF0(0, 7);
                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140106762);
                                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x30EC8348);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                if (result <= 3) JUMPOUT(0x140106614);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                a1 = ptr2->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                                dst2 += 4;
                                                                                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                                                                                off_140108030(a1, dst2);
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140106863);
                                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x202444C7);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                ptr = (struct Struct_2_t *)v_38;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                                if (result <= 7) JUMPOUT(0x14010663d);
                                                                                                                                                                                                                dst = (__int64 *)v_30;
                                                                                                                                                                                                                result = ptr2->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)dst + (__int64)ptr) = result;
                                                                                                                                                                                                                ptr += 8;
                                                                                                                                                                                                                v_38 = (__int64)ptr;
                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                                a1 = (size_t *)v_28;
                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)ptr);
                                                                                                                                                                                                                v_80 = (__int64)ptr;
                                                                                                                                                                                                                result = (struct Struct_1_t *)ptr;
                                                                                                                                                                                                                if (a1 <= 4) JUMPOUT(0x140106669);
                                                                                                                                                                                                                *(__int64 *)((__int64)dst + (__int64)result + 4) = 0;
                                                                                                                                                                                                                *(__int64 *)((__int64)dst + (__int64)result) = 232;
                                                                                                                                                                                                                result += 5;
                                                                                                                                                                                                                v_38 = (__int64)result;
                                                                                                                                                                                                                sub_14002EDF0(0, 7);
                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140106762);
                                                                                                                                                                                                                ptr2 = (struct Struct_3_t *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x30C48348);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                dst = (__int64 *)v_38;
                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                                                                                                                                                if (result <= 3) JUMPOUT(0x140106701);
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                a1 = ptr2->field_0;
                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst) = a1;
                                                                                                                                                                                                                dst += 4;
                                                                                                                                                                                                                v_38 = (__int64)dst;
                                                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            if (dst == v_28) {
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst) = 77;
                                                                                                                                                                                                            result = dst + 1;
                                                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst + 1) = 49;
                                                                                                                                                                                                            result = dst + 2;
                                                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst + 2) = 237;
                                                                                                                                                                                                            result = dst + 3;
                                                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst + 3) = 77;
                                                                                                                                                                                                            result = dst + 4;
                                                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            v_50 = (__int64)src2;
                                                                                                                                                                                                            v_47 = v12;
                                                                                                                                                                                                            v_58 = (__int64)dst3;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst + 4) = 49;
                                                                                                                                                                                                            result = dst + 5;
                                                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst + 5) = 228;
                                                                                                                                                                                                            dst += 6;
                                                                                                                                                                                                            v_38 = (__int64)dst;
                                                                                                                                                                                                            ptr2 = 32;
                                                                                                                                                                                                            src2 = rsp + 184;
                                                                                                                                                                                                            return sub_1401045CC();
                                                                                                                                                                                                        }
                                                                                                                                                                                                        return (__int64)src2;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    return (__int64)src2;
                                                                                                                                                                                                }
                                                                                                                                                                                                return (__int64)src2;
                                                                                                                                                                                            }
                                                                                                                                                                                            return (__int64)src2;
                                                                                                                                                                                        }
                                                                                                                                                                                        return (__int64)src2;
                                                                                                                                                                                    }
                                                                                                                                                                                    return (__int64)src2;
                                                                                                                                                                                }
                                                                                                                                                                                return (__int64)src2;
                                                                                                                                                                            }
                                                                                                                                                                            return (__int64)src2;
                                                                                                                                                                        }
                                                                                                                                                                        return (__int64)src2;
                                                                                                                                                                    }
                                                                                                                                                                    return (__int64)src2;
                                                                                                                                                                }
                                                                                                                                                                return (__int64)src2;
                                                                                                                                                            }
                                                                                                                                                            return (__int64)src2;
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                                return (__int64)src2;
                                                                                                                                            }
                                                                                                                                            sub_1400F3326(1, 8);
                                                                                                                                            return (__int64)src2;
                                                                                                                                        }
                                                                                                                                        return (__int64)src2;
                                                                                                                                    }
                                                                                                                                    return (__int64)src2;
                                                                                                                                }
                                                                                                                                return (__int64)src2;
                                                                                                                            }
                                                                                                                            return (__int64)src2;
                                                                                                                        }
                                                                                                                        return (__int64)src2;
                                                                                                                    }
                                                                                                                    off_140108030();
                                                                                                                    ((__int64 (*)())ptr)(result, 0, v9);
                                                                                                                    return (__int64)src2;
                                                                                                                }
                                                                                                                return (__int64)src2;
                                                                                                            }
                                                                                                            off_140108030();
                                                                                                            ((__int64 (*)())ptr)(result, 0, v12);
                                                                                                            v9 = v_38;
                                                                                                            return v9;
                                                                                                        }
                                                                                                        return v9;
                                                                                                    }
                                                                                                    off_140108030();
                                                                                                    ((__int64 (*)())ptr)(result, 0, v9);
                                                                                                    return v9;
                                                                                                }
                                                                                                return v9;
                                                                                            }
                                                                                            off_140108030();
                                                                                            ((__int64 (*)())ptr)(result, 0, v9);
                                                                                            return v9;
                                                                                        }
                                                                                        return v9;
                                                                                    }
                                                                                    off_140108030();
                                                                                    ((__int64 (*)())ptr)(result, 0, v9);
                                                                                    return v9;
                                                                                }
                                                                            }
                                                                            return v9;
                                                                        }
                                                                        return v9;
                                                                    }
                                                                    return v9;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            return v9;
                                        }
                                        off_140108030();
                                        ((__int64 (*)())ptr)(result, 0, src);
                                        return v9;
                                    }
                                    return v9;
                                }
                                off_140108030();
                                ((__int64 (*)())ptr)(result, 0, src);
                                return v9;
                            }
                            return v9;
                        }
                    }
                }
            }
            return v9;
        }
        return v9;
    }
    return (__int64)result;
}