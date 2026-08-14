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

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3510();
__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3340();
__int64 sub_1400F3600();
__int64 sub_1400F3326();
__int64 sub_1400F3B80();
__int64 sub_14010222E();
__int64 off_140108030();
extern __int64 off_140108038;
extern __int64 off_14011CBA0;
extern __int64 off_14011CCD0;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011CE10;
extern __int64 off_14011CE00;
extern __int64 off_14011CB88;
extern __int64 off_14011CB78;
extern __int64 off_14011CCB8;
extern __int64 off_14011CCA0;

__int64 __fastcall sub_1400FDC10(size_t *a1) {
    __int64 rsp;
    int arg_2;
    int arg_3;
    int arg_4;
    int arg_8;
    int arg_9;
    __int64 v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    __int64 v_58;
    __int64 v_60;
    __int64 *src;
    struct Struct_1_t *result;
    __int64 *dst;
    __int64 v3;
    __int64 v6;
    __int64 *src2;
    __int64 v12;
    __int64 v9;
    __int64 *dst2;
    struct Struct_2_t *ptr;
    __int64 *dst3;
    struct Struct_3_t *ptr2;
    __m128i xmm0;

    src = (__int64 *)a1;
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
        sub_1400F3510(a1, v3, v6, ptr2);
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
        dst = (__int64 *)result;
        *(__int64 *)result = (__int64)(0x8148);
        result->field_3 = 296;
        result->field_2 = 236;
        result = (struct Struct_1_t *)v_28;
        v3 = v_38;
        result -= v3;
        if (result <= 6) {
            do {
                v_20 = 1;
                a1 = rsp + 40;
                sub_1400F2D20(a1, v3, 7, 1);
                v3 = v_38;
            } while (true);
        }
        result = (struct Struct_1_t *)v_30;
        a1 = *dst;
        v6 = arg_3;
        *(__int64 *)(result + v3 + 3) = (__int64)(v6);
        *(__int64 *)(result + v3) = (__int64)(a1);
        v3 += 7;
        v_38 = v3;
        off_140108030(a1, v3, v6);
        ((__int64 (*)())off_140108038)(result, 0, dst);
        sub_14002EDF0(0, 8);
        if (result != 0) {
            dst = (__int64 *)result;
            *(__int64 *)result = (__int64)(0x248C8948);
            result = (struct Struct_1_t *)v_28;
            v3 = v_38;
            arg_4 = 288;
            result -= v3;
            v_60 = (__int64)src;
            if (result <= 7) {
                v_20 = 1;
                a1 = rsp + 40;
                sub_1400F2D20(a1, v3, 8, 1);
                v3 = v_38;
            }
            result = (struct Struct_1_t *)v_30;
            a1 = *dst;
            *(__int64 *)(result + v3) = (__int64)(a1);
            v3 += 8;
            v_38 = v3;
            off_140108030(a1, v3);
            ((__int64 (*)())off_140108038)(result, 0, dst);
            dst = rsp + 64;
            src2 = rsp + 40;
            src = off_140108038;
            v12 = 0;
            sub_14002EDF0(0, 8);
            while (result != 0) {
                v_40 = 8;
                v_48 = (__int64)result;
                *(__int64 *)result = (__int64)(139);
                v_50 = 1;
                sub_1400D4F50(dst, 0, 2, v12);
                v9 = v_40;
                dst2 = (__int64 *)v_48;
                ptr = (struct Struct_2_t *)v_50;
                result = (struct Struct_1_t *)v_28;
                dst3 = (__int64 *)v_38;
                result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                if (ptr > result) {
                    v_20 = 1;
                    sub_1400F2D20(src2, dst3, ptr, 1);
                    dst3 = (__int64 *)v_38;
                }
                a1 = (size_t *)v_30;
                a1 = (size_t *)((__int64)a1 + (__int64)dst3);
                sub_1400F27F0(a1, dst2, ptr);
                dst3 = (__int64 *)((__int64)dst3 + (__int64)ptr);
                v_38 = (__int64)dst3;
                if (v9 == 0) {
                    sub_14002EDF0(0, 3);
                    if (result != 0) {
                        dst2 = (__int64 *)result;
                        *(__int64 *)result = (__int64)(0xC80F);
                        result = (struct Struct_1_t *)v_28;
                        v3 = v_38;
                        result -= v3;
                        if (result <= 1) {
                            v_20 = 1;
                            sub_1400F2D20(src2, v3, 2, 1);
                            v3 = v_38;
                        }
                        result = (struct Struct_1_t *)v_30;
                        a1 = *dst2;
                        *(__int64 *)(result + v3) = (__int64)(a1);
                        v3 += 2;
                        v_38 = v3;
                        off_140108030(a1, v3);
                        ((__int64 (*)())src)(result, 0, dst2);
                        sub_14002EDF0(0, 8);
                        if (result != 0) {
                            v_40 = 8;
                            v_48 = (__int64)result;
                            *(__int64 *)result = (__int64)(137);
                            v_50 = 1;
                            sub_1400D4F50(dst, 0, 4, v12);
                            v9 = v_40;
                            dst2 = (__int64 *)v_48;
                            ptr = (struct Struct_2_t *)v_50;
                            result = (struct Struct_1_t *)v_28;
                            dst3 = (__int64 *)v_38;
                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                            if (ptr > result) {
                                v_20 = 1;
                                sub_1400F2D20(src2, dst3, ptr, 1);
                                dst3 = (__int64 *)v_38;
                            }
                            a1 = (size_t *)v_30;
                            a1 = (size_t *)((__int64)a1 + (__int64)dst3);
                            sub_1400F27F0(a1, dst2, ptr);
                            dst3 = (__int64 *)((__int64)dst3 + (__int64)ptr);
                            v_38 = (__int64)dst3;
                            if (v9 == 0) {
                                v12 += 4;
                                sub_14002EDF0(0, 3);
                                if (result == 0) {
                                    sub_1400F3340(1, 3);
                                }
                                dst = (__int64 *)result;
                                *(__int64 *)result = (__int64)(0x8949);
                                result->field_2 = 225;
                                result = (struct Struct_1_t *)v_28;
                                v3 = v_38;
                                result -= v3;
                                if (result <= 2) {
                                    v_20 = 1;
                                    a1 = rsp + 40;
                                    sub_1400F2D20(a1, v3, 3, 1);
                                    v3 = v_38;
                                }
                                result = (struct Struct_1_t *)v_30;
                                a1 = (size_t *)arg_2;
                                *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                a1 = *dst;
                                *(__int64 *)(result + v3) = (__int64)(a1);
                                v3 += 3;
                                v_38 = v3;
                                off_140108030(a1, v3);
                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                sub_14002EDF0(0, 7);
                                if (result != 0) {
                                    dst = (__int64 *)result;
                                    *(__int64 *)result = (__int64)(0x40C18349);
                                    result = (struct Struct_1_t *)v_28;
                                    v3 = v_38;
                                    result -= v3;
                                    if (result <= 3) {
                                        v_20 = 1;
                                        a1 = rsp + 40;
                                        sub_1400F2D20(a1, v3, 4, 1);
                                        v3 = v_38;
                                    }
                                    result = (struct Struct_1_t *)v_30;
                                    a1 = *dst;
                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                    v3 += 4;
                                    v_38 = v3;
                                    off_140108030(a1, v3);
                                    ((__int64 (*)())off_140108038)(result, 0, dst);
                                    sub_14002EDF0(0, 6);
                                    if (result != 0) {
                                        src2 = (__int64 *)result;
                                        *(__int64 *)result = (__int64)(185);
                                        result->field_1 = 16;
                                        result = (struct Struct_1_t *)v_28;
                                        dst = (__int64 *)v_38;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                        if (result <= 4) {
                                            v_20 = 1;
                                            a1 = rsp + 40;
                                            sub_1400F2D20(a1, dst, 5, 1);
                                            dst = (__int64 *)v_38;
                                        }
                                        result = (struct Struct_1_t *)v_30;
                                        a1 = (size_t *)arg_4;
                                        *(__int64 *)((__int64)result + (__int64)dst + 4) = a1;
                                        a1 = *src2;
                                        *(__int64 *)((__int64)result + (__int64)dst) = a1;
                                        dst += 5;
                                        v_38 = (__int64)dst;
                                        off_140108030(a1);
                                        ((__int64 (*)())off_140108038)(result, 0, src2);
                                        sub_14002EDF0(0, 8);
                                        if (result != 0) {
                                            src2 = (__int64 *)result;
                                            *(__int64 *)result = (__int64)(0x8B41);
                                            result->field_2 = 65;
                                            result = (struct Struct_1_t *)v_28;
                                            v3 = v_38;
                                            arg_3 = 196;
                                            result -= v3;
                                            if (result <= 3) {
                                                v_20 = 1;
                                                a1 = rsp + 40;
                                                sub_1400F2D20(a1, v3, 4, 1);
                                                v3 = v_38;
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            a1 = *src2;
                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                            v3 += 4;
                                            v_38 = v3;
                                            off_140108030(a1, v3);
                                            ((__int64 (*)())off_140108038)(result, 0, src2);
                                            sub_14002EDF0(0, 3);
                                            if (result == 0) {
                                                return v_38;
                                            }
                                            dst2 = (__int64 *)result;
                                            *(__int64 *)result = (__int64)(0x8948);
                                            result->field_2 = 195;
                                            ptr = (struct Struct_2_t *)v_28;
                                            src2 = (__int64 *)v_38;
                                            result = (struct Struct_1_t *)ptr;
                                            result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                a1 = rsp + 40;
                                                sub_1400F2D20(a1, src2, 3, 1);
                                                ptr = (struct Struct_2_t *)v_28;
                                                src2 = (__int64 *)v_38;
                                            }
                                            dst3 = (__int64 *)v_30;
                                            result = (struct Struct_1_t *)arg_2;
                                            *(__int64 *)((__int64)dst3 + (__int64)src2 + 2) = result;
                                            result = *dst2;
                                            *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                            v9 = src2 + 3;
                                            v_38 = v9;
                                            off_140108030();
                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                            if (v9 == ptr) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                                dst3 = (__int64 *)v_30;
                                            }
                                            *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 193;
                                            result = src2 + 4;
                                            v_38 = (__int64)result;
                                            if (result == v_28) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            *(__int64 *)((__int64)result + (__int64)src2 + 4) = 200;
                                            result = src2 + 5;
                                            v_38 = (__int64)result;
                                            if (result == v_28) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            *(__int64 *)((__int64)result + (__int64)src2 + 5) = 7;
                                            src2 += 6;
                                            v_38 = (__int64)src2;
                                            sub_14002EDF0(0, 3);
                                            if (result == 0) {
                                                return v_38;
                                            }
                                            dst2 = (__int64 *)result;
                                            *(__int64 *)result = (__int64)(0x8948);
                                            result->field_2 = 223;
                                            ptr = (struct Struct_2_t *)v_28;
                                            src2 = (__int64 *)v_38;
                                            result = (struct Struct_1_t *)ptr;
                                            result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                a1 = rsp + 40;
                                                sub_1400F2D20(a1, src2, 3, 1);
                                                ptr = (struct Struct_2_t *)v_28;
                                                src2 = (__int64 *)v_38;
                                            }
                                            dst3 = (__int64 *)v_30;
                                            result = (struct Struct_1_t *)arg_2;
                                            *(__int64 *)((__int64)dst3 + (__int64)src2 + 2) = result;
                                            result = *dst2;
                                            *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                            v9 = src2 + 3;
                                            v_38 = v9;
                                            off_140108030();
                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                            if (v9 == ptr) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                                dst3 = (__int64 *)v_30;
                                            }
                                            *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 193;
                                            result = src2 + 4;
                                            v_38 = (__int64)result;
                                            if (result == v_28) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            *(__int64 *)((__int64)result + (__int64)src2 + 4) = 207;
                                            result = src2 + 5;
                                            v_38 = (__int64)result;
                                            if (result == v_28) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            *(__int64 *)((__int64)result + (__int64)src2 + 5) = 18;
                                            result = src2 + 6;
                                            v_38 = (__int64)result;
                                            if (result == v_28) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            *(__int64 *)((__int64)result + (__int64)src2 + 6) = 49;
                                            result = src2 + 7;
                                            v_38 = (__int64)result;
                                            if (result == v_28) {
                                                a1 = rsp + 40;
                                                sub_1400F3510(a1);
                                            }
                                            result = (struct Struct_1_t *)v_30;
                                            *(__int64 *)((__int64)result + (__int64)src2 + 7) = 248;
                                            src2 += 8;
                                            v_38 = (__int64)src2;
                                            sub_14002EDF0(0, 4);
                                            if (result != 0) {
                                                dst2 = (__int64 *)result;
                                                *(__int64 *)result = (__int64)(0xEBC1);
                                                result->field_2 = 3;
                                                ptr = (struct Struct_2_t *)v_28;
                                                src2 = (__int64 *)v_38;
                                                result = (struct Struct_1_t *)ptr;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                if (result <= 2) {
                                                    v_20 = 1;
                                                    a1 = rsp + 40;
                                                    sub_1400F2D20(a1, src2, 3, 1);
                                                    ptr = (struct Struct_2_t *)v_28;
                                                    src2 = (__int64 *)v_38;
                                                }
                                                dst3 = (__int64 *)v_30;
                                                result = (struct Struct_1_t *)arg_2;
                                                *(__int64 *)((__int64)dst3 + (__int64)src2 + 2) = result;
                                                result = *dst2;
                                                *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                                v9 = src2 + 3;
                                                v_38 = v9;
                                                off_140108030();
                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                if (v9 == ptr) {
                                                    a1 = rsp + 40;
                                                    sub_1400F3510(a1);
                                                    dst3 = (__int64 *)v_30;
                                                }
                                                *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 49;
                                                result = src2 + 4;
                                                v_38 = (__int64)result;
                                                if (result == v_28) {
                                                    a1 = rsp + 40;
                                                    sub_1400F3510(a1);
                                                }
                                                result = (struct Struct_1_t *)v_30;
                                                *(__int64 *)((__int64)result + (__int64)src2 + 4) = 216;
                                                src2 += 5;
                                                v_38 = (__int64)src2;
                                                sub_14002EDF0(0, 8);
                                                if (result != 0) {
                                                    src2 = (__int64 *)result;
                                                    *(__int64 *)result = (__int64)(0x8B41);
                                                    result->field_2 = 89;
                                                    result = (struct Struct_1_t *)v_28;
                                                    v3 = v_38;
                                                    arg_3 = 248;
                                                    result -= v3;
                                                    if (result <= 3) {
                                                        v_20 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400F2D20(a1, v3, 4, 1);
                                                        v3 = v_38;
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    a1 = *src2;
                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                    v3 += 4;
                                                    v_38 = v3;
                                                    off_140108030(a1, v3);
                                                    ((__int64 (*)())off_140108038)(result, 0, src2);
                                                    sub_14002EDF0(0, 3);
                                                    if (result == 0) {
                                                        return v_38;
                                                    }
                                                    dst2 = (__int64 *)result;
                                                    *(__int64 *)result = (__int64)(0x8948);
                                                    result->field_2 = 223;
                                                    ptr = (struct Struct_2_t *)v_28;
                                                    src2 = (__int64 *)v_38;
                                                    result = (struct Struct_1_t *)ptr;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                    if (result <= 2) {
                                                        v_20 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400F2D20(a1, src2, 3, 1);
                                                        ptr = (struct Struct_2_t *)v_28;
                                                        src2 = (__int64 *)v_38;
                                                    }
                                                    dst3 = (__int64 *)v_30;
                                                    result = (struct Struct_1_t *)arg_2;
                                                    *(__int64 *)((__int64)dst3 + (__int64)src2 + 2) = result;
                                                    result = *dst2;
                                                    *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                                    v9 = src2 + 3;
                                                    v_38 = v9;
                                                    off_140108030();
                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                    if (v9 == ptr) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                        dst3 = (__int64 *)v_30;
                                                    }
                                                    *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 193;
                                                    result = src2 + 4;
                                                    v_38 = (__int64)result;
                                                    if (result == v_28) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    *(__int64 *)((__int64)result + (__int64)src2 + 4) = 207;
                                                    result = src2 + 5;
                                                    v_38 = (__int64)result;
                                                    if (result == v_28) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    *(__int64 *)((__int64)result + (__int64)src2 + 5) = 17;
                                                    src2 += 6;
                                                    v_38 = (__int64)src2;
                                                    sub_14002EDF0(0, 3);
                                                    if (result == 0) {
                                                        return v_38;
                                                    }
                                                    dst2 = (__int64 *)result;
                                                    *(__int64 *)result = (__int64)(0x8948);
                                                    result->field_2 = 222;
                                                    ptr = (struct Struct_2_t *)v_28;
                                                    src2 = (__int64 *)v_38;
                                                    result = (struct Struct_1_t *)ptr;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                    if (result <= 2) {
                                                        v_20 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400F2D20(a1, src2, 3, 1);
                                                        ptr = (struct Struct_2_t *)v_28;
                                                        src2 = (__int64 *)v_38;
                                                    }
                                                    dst3 = (__int64 *)v_30;
                                                    result = (struct Struct_1_t *)arg_2;
                                                    *(__int64 *)((__int64)dst3 + (__int64)src2 + 2) = result;
                                                    result = *dst2;
                                                    *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                                    v9 = src2 + 3;
                                                    v_38 = v9;
                                                    off_140108030();
                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                    if (v9 == ptr) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                        dst3 = (__int64 *)v_30;
                                                    }
                                                    *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 193;
                                                    result = src2 + 4;
                                                    v_38 = (__int64)result;
                                                    if (result == v_28) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    *(__int64 *)((__int64)result + (__int64)src2 + 4) = 206;
                                                    result = src2 + 5;
                                                    v_38 = (__int64)result;
                                                    if (result == v_28) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    *(__int64 *)((__int64)result + (__int64)src2 + 5) = 19;
                                                    result = src2 + 6;
                                                    v_38 = (__int64)result;
                                                    if (result == v_28) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    *(__int64 *)((__int64)result + (__int64)src2 + 6) = 49;
                                                    result = src2 + 7;
                                                    v_38 = (__int64)result;
                                                    if (result == v_28) {
                                                        a1 = rsp + 40;
                                                        sub_1400F3510(a1);
                                                    }
                                                    result = (struct Struct_1_t *)v_30;
                                                    *(__int64 *)((__int64)result + (__int64)src2 + 7) = 247;
                                                    src2 += 8;
                                                    v_38 = (__int64)src2;
                                                    sub_14002EDF0(0, 4);
                                                    if (result != 0) {
                                                        dst2 = (__int64 *)result;
                                                        *(__int64 *)result = (__int64)(0xEBC1);
                                                        result->field_2 = 10;
                                                        ptr = (struct Struct_2_t *)v_28;
                                                        src2 = (__int64 *)v_38;
                                                        result = (struct Struct_1_t *)ptr;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                        if (result <= 2) {
                                                            v_20 = 1;
                                                            a1 = rsp + 40;
                                                            sub_1400F2D20(a1, src2, 3, 1);
                                                            ptr = (struct Struct_2_t *)v_28;
                                                            src2 = (__int64 *)v_38;
                                                        }
                                                        dst3 = (__int64 *)v_30;
                                                        result = (struct Struct_1_t *)arg_2;
                                                        *(__int64 *)((__int64)dst3 + (__int64)src2 + 2) = result;
                                                        result = *dst2;
                                                        *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                                        v9 = src2 + 3;
                                                        v_38 = v9;
                                                        off_140108030();
                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                        if (v9 == ptr) {
                                                            a1 = rsp + 40;
                                                            sub_1400F3510(a1);
                                                            dst3 = (__int64 *)v_30;
                                                        }
                                                        *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 49;
                                                        result = src2 + 4;
                                                        v_38 = (__int64)result;
                                                        if (result == v_28) {
                                                            a1 = rsp + 40;
                                                            sub_1400F3510(a1);
                                                        }
                                                        result = (struct Struct_1_t *)v_30;
                                                        *(__int64 *)((__int64)result + (__int64)src2 + 4) = 251;
                                                        src2 += 5;
                                                        v_38 = (__int64)src2;
                                                        sub_14002EDF0(0, 8);
                                                        if (result != 0) {
                                                            dst2 = (__int64 *)result;
                                                            *(__int64 *)result = (__int64)(833);
                                                            result->field_2 = 129;
                                                            result->field_3 = 0xFFFFFFC0;
                                                            ptr = (struct Struct_2_t *)v_28;
                                                            src2 = (__int64 *)v_38;
                                                            result = (struct Struct_1_t *)ptr;
                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                            if (result <= 6) {
                                                                v_20 = 1;
                                                                a1 = rsp + 40;
                                                                sub_1400F2D20(a1, src2, 7, 1);
                                                                ptr = (struct Struct_2_t *)v_28;
                                                                src2 = (__int64 *)v_38;
                                                            }
                                                            dst3 = (__int64 *)v_30;
                                                            result = *dst2;
                                                            a1 = (size_t *)arg_3;
                                                            *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = a1;
                                                            *(__int64 *)((__int64)dst3 + (__int64)src2) = result;
                                                            v9 = src2 + 7;
                                                            v_38 = v9;
                                                            off_140108030(a1);
                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                            if (v9 == ptr) {
                                                                a1 = rsp + 40;
                                                                sub_1400F3510(a1);
                                                                dst3 = (__int64 *)v_30;
                                                            }
                                                            *(__int64 *)((__int64)dst3 + (__int64)src2 + 7) = 1;
                                                            result = src2 + 8;
                                                            v_38 = (__int64)result;
                                                            if (result == v_28) {
                                                                a1 = rsp + 40;
                                                                sub_1400F3510(a1);
                                                            }
                                                            result = (struct Struct_1_t *)v_30;
                                                            *(__int64 *)((__int64)result + (__int64)src2 + 8) = 216;
                                                            src2 += 9;
                                                            v_38 = (__int64)src2;
                                                            sub_14002EDF0(0, 8);
                                                            if (result != 0) {
                                                                src2 = (__int64 *)result;
                                                                *(__int64 *)result = (__int64)(833);
                                                                result->field_2 = 129;
                                                                result->field_3 = 0xFFFFFFE4;
                                                                result = (struct Struct_1_t *)v_28;
                                                                v3 = v_38;
                                                                result -= v3;
                                                                if (result <= 6) {
                                                                    v_20 = 1;
                                                                    a1 = rsp + 40;
                                                                    sub_1400F2D20(a1, v3, 7, 1);
                                                                    v3 = v_38;
                                                                }
                                                                result = (struct Struct_1_t *)v_30;
                                                                a1 = *src2;
                                                                v6 = arg_3;
                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                v3 += 7;
                                                                v_38 = v3;
                                                                off_140108030(a1, v3, v6);
                                                                ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                sub_14002EDF0(0, 8);
                                                                if (result != 0) {
                                                                    src2 = (__int64 *)result;
                                                                    *(__int64 *)result = (__int64)(0x8941);
                                                                    result->field_2 = 1;
                                                                    result = (struct Struct_1_t *)v_28;
                                                                    v3 = v_38;
                                                                    result -= v3;
                                                                    if (result <= 2) {
                                                                        v_20 = 1;
                                                                        a1 = rsp + 40;
                                                                        sub_1400F2D20(a1, v3, 3, 1);
                                                                        v3 = v_38;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_30;
                                                                    a1 = (size_t *)arg_2;
                                                                    *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                    a1 = *src2;
                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                    v3 += 3;
                                                                    v_38 = v3;
                                                                    off_140108030(a1, v3);
                                                                    ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                    sub_14002EDF0(0, 7);
                                                                    if (result != 0) {
                                                                        dst2 = (__int64 *)result;
                                                                        *(__int64 *)result = (__int64)(0x4C18349);
                                                                        result = (struct Struct_1_t *)v_28;
                                                                        src2 = (__int64 *)v_38;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                        if (result <= 3) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, src2, 4, 1);
                                                                            src2 = (__int64 *)v_38;
                                                                        }
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        a1 = *dst2;
                                                                        *(__int64 *)((__int64)result + (__int64)src2) = a1;
                                                                        src2 += 4;
                                                                        v_38 = (__int64)src2;
                                                                        off_140108030(a1);
                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                        result = (struct Struct_1_t *)v_28;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                        if (result <= 1) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, src2, 2, 1);
                                                                            src2 = (__int64 *)v_38;
                                                                        }
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        *(__int64 *)((__int64)result + (__int64)src2) = 0xC1FF;
                                                                        src2 += 2;
                                                                        v_38 = (__int64)src2;
                                                                        result = (struct Struct_1_t *)v_28;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                        if (result <= 2) {
                                                                            v_20 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400F2D20(a1, src2, 3, 1);
                                                                            src2 = (__int64 *)v_38;
                                                                        }
                                                                        result = (struct Struct_1_t *)v_30;
                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 2) = 64;
                                                                        *(__int64 *)((__int64)result + (__int64)src2) = 0xF983;
                                                                        v3 = src2 + 3;
                                                                        v_38 = v3;
                                                                        src2 += 9;
                                                                        if (!((src2 < 0))) {
                                                                            dst = (__int64 *)((__int64)dst - (__int64)src2);
                                                                            a1 = (size_t *)dst;
                                                                            if (dst == dst) {
                                                                                a1 = (size_t *)v_28;
                                                                                a1 -= v3;
                                                                                if (a1 <= 1) {
                                                                                    v_20 = 1;
                                                                                    a1 = rsp + 40;
                                                                                    sub_1400F2D20(a1, v3, 2, 1);
                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                    v3 = v_38;
                                                                                }
                                                                                *(__int64 *)(result + v3) = (__int64)(0x820F);
                                                                                v3 += 2;
                                                                                v_38 = v3;
                                                                                result = (struct Struct_1_t *)v_28;
                                                                                result -= v3;
                                                                                if (result <= 3) {
                                                                                    v_20 = 1;
                                                                                    a1 = rsp + 40;
                                                                                    sub_1400F2D20(a1, v3, 4, 1);
                                                                                    v3 = v_38;
                                                                                }
                                                                                result = (struct Struct_1_t *)v_30;
                                                                                *(__int64 *)(result + v3) = (__int64)(dst);
                                                                                v3 += 4;
                                                                                v_38 = v3;
                                                                                sub_14002EDF0(0, 8);
                                                                                if (result != 0) {
                                                                                    dst = (__int64 *)result;
                                                                                    *(__int64 *)result = (__int64)(0x248C8B48);
                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                    v3 = v_38;
                                                                                    arg_4 = 288;
                                                                                    result -= v3;
                                                                                    if (result <= 7) {
                                                                                        v_20 = 1;
                                                                                        a1 = rsp + 40;
                                                                                        sub_1400F2D20(a1, v3, 8, 1);
                                                                                        v3 = v_38;
                                                                                    }
                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                    a1 = *dst;
                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                    v3 += 8;
                                                                                    v_38 = v3;
                                                                                    off_140108030(a1, v3);
                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                    dst = rsp + 64;
                                                                                    src2 = rsp + 40;
                                                                                    dst2 = 0;
                                                                                    sub_14002EDF0(0, 8);
                                                                                    while (result != 0) {
                                                                                        v_40 = 8;
                                                                                        v_48 = (__int64)result;
                                                                                        *(__int64 *)result = (__int64)(139);
                                                                                        v_50 = 1;
                                                                                        sub_1400D4F50(dst, 0, 1, dst2);
                                                                                        v12 = v_40;
                                                                                        ptr = (struct Struct_2_t *)v_48;
                                                                                        dst3 = (__int64 *)v_50;
                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                        v9 = v_38;
                                                                                        result -= v9;
                                                                                        if (dst3 > result) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(src2, v9, dst3, 1);
                                                                                            v9 = v_38;
                                                                                        }
                                                                                        a1 = (size_t *)v_30;
                                                                                        a1 += v9;
                                                                                        sub_1400F27F0(a1, ptr, dst3);
                                                                                        v9 += (__int64)dst3;
                                                                                        v_38 = v9;
                                                                                        if (v12 == 0) {
                                                                                            sub_14002EDF0(0, 8);
                                                                                            if (result != 0) {
                                                                                                ptr2 = dst2 + 256;
                                                                                                v_40 = 8;
                                                                                                v_48 = (__int64)result;
                                                                                                *(__int64 *)result = (__int64)(137);
                                                                                                v_50 = 1;
                                                                                                sub_1400D4F50(dst, 0, 4, ptr2);
                                                                                                v12 = v_40;
                                                                                                ptr = (struct Struct_2_t *)v_48;
                                                                                                dst3 = (__int64 *)v_50;
                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                v9 = v_38;
                                                                                                result -= v9;
                                                                                                if (dst3 > result) {
                                                                                                    v_20 = 1;
                                                                                                    sub_1400F2D20(src2, v9, dst3, 1);
                                                                                                    v9 = v_38;
                                                                                                }
                                                                                                a1 = (size_t *)v_30;
                                                                                                a1 += v9;
                                                                                                sub_1400F27F0(a1, ptr, dst3);
                                                                                                v9 += (__int64)dst3;
                                                                                                v_38 = v9;
                                                                                                if (v12 == 0) {
                                                                                                    dst2 += 4;
                                                                                                    sub_14002EDF0(0, 3);
                                                                                                    if (result == 0) {
                                                                                                        return (__int64)dst2;
                                                                                                    }
                                                                                                    dst2 = (__int64 *)result;
                                                                                                    *(__int64 *)result = (__int64)(0x8949);
                                                                                                    result->field_2 = 225;
                                                                                                    ptr = (struct Struct_2_t *)v_28;
                                                                                                    dst = (__int64 *)v_38;
                                                                                                    result = (struct Struct_1_t *)ptr;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                                    if (result <= 2) {
                                                                                                        v_20 = 1;
                                                                                                        a1 = rsp + 40;
                                                                                                        sub_1400F2D20(a1, dst, 3, 1);
                                                                                                        ptr = (struct Struct_2_t *)v_28;
                                                                                                        dst = (__int64 *)v_38;
                                                                                                    }
                                                                                                    dst3 = (__int64 *)v_30;
                                                                                                    result = (struct Struct_1_t *)arg_2;
                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)dst + 2) = result;
                                                                                                    result = *dst2;
                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)dst) = result;
                                                                                                    src2 = dst + 3;
                                                                                                    v_38 = (__int64)src2;
                                                                                                    off_140108030();
                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                    result = (struct Struct_1_t *)ptr;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                                                    if (result <= 6) {
                                                                                                        v_20 = 1;
                                                                                                        a1 = rsp + 40;
                                                                                                        sub_1400F2D20(a1, src2, 7, 1);
                                                                                                        src2 = (__int64 *)v_38;
                                                                                                        ptr = (struct Struct_2_t *)v_28;
                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                    }
                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)src2 + 3) = 0;
                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)src2) = 0x158D4C;
                                                                                                    result = src2 + 7;
                                                                                                    v_38 = (__int64)result;
                                                                                                    if (result == ptr) {
                                                                                                        a1 = rsp + 40;
                                                                                                        sub_1400F3510(a1);
                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                    }
                                                                                                    *(__int64 *)((__int64)dst3 + (__int64)src2 + 7) = 72;
                                                                                                    result = src2 + 8;
                                                                                                    v_38 = (__int64)result;
                                                                                                    if (result == v_28) {
                                                                                                        a1 = rsp + 40;
                                                                                                        sub_1400F3510(a1);
                                                                                                    }
                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                    *(__int64 *)((__int64)result + (__int64)src2 + 8) = 49;
                                                                                                    result = src2 + 9;
                                                                                                    v_38 = (__int64)result;
                                                                                                    if (result == v_28) {
                                                                                                        a1 = rsp + 40;
                                                                                                        sub_1400F3510(a1);
                                                                                                    }
                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                    *(__int64 *)((__int64)result + (__int64)src2 + 9) = 201;
                                                                                                    src2 += 10;
                                                                                                    v_38 = (__int64)src2;
                                                                                                    sub_14002EDF0(0, 8);
                                                                                                    if (result != 0) {
                                                                                                        dst2 = (__int64 *)result;
                                                                                                        *(__int64 *)result = (__int64)(0x848B);
                                                                                                        result->field_2 = 36;
                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                        v3 = v_38;
                                                                                                        arg_3 = 272;
                                                                                                        result -= v3;
                                                                                                        if (result <= 6) {
                                                                                                            v_20 = 1;
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F2D20(a1, v3, 7, 1);
                                                                                                            v3 = v_38;
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        a1 = *dst2;
                                                                                                        v6 = arg_3;
                                                                                                        *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                        *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                        v3 += 7;
                                                                                                        v_38 = v3;
                                                                                                        off_140108030(a1, v3, v6);
                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                        sub_14002EDF0(0, 3);
                                                                                                        if (result == 0) {
                                                                                                            return v_38;
                                                                                                        }
                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                        v_58 = (__int64)dst;
                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                        result->field_2 = 199;
                                                                                                        dst = (__int64 *)v_28;
                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                        if (result <= 2) {
                                                                                                            v_20 = 1;
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                        }
                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                        result = ptr->field_2;
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                        result = ptr->field_0;
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                        v9 = dst2 + 3;
                                                                                                        v_38 = v9;
                                                                                                        off_140108030();
                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                        if (v9 == dst) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                        }
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 193;
                                                                                                        result = dst2 + 4;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 200;
                                                                                                        result = dst2 + 5;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 6;
                                                                                                        dst2 += 6;
                                                                                                        v_38 = (__int64)dst2;
                                                                                                        sub_14002EDF0(0, 3);
                                                                                                        if (result == 0) {
                                                                                                            return v_38;
                                                                                                        }
                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                        result->field_2 = 251;
                                                                                                        dst = (__int64 *)v_28;
                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                        if (result <= 2) {
                                                                                                            v_20 = 1;
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                        }
                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                        result = ptr->field_2;
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                        result = ptr->field_0;
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                        v9 = dst2 + 3;
                                                                                                        v_38 = v9;
                                                                                                        off_140108030();
                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                        if (v9 == dst) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                        }
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 193;
                                                                                                        result = dst2 + 4;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 203;
                                                                                                        result = dst2 + 5;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 11;
                                                                                                        result = dst2 + 6;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 6) = 49;
                                                                                                        result = dst2 + 7;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 7) = 216;
                                                                                                        dst2 += 8;
                                                                                                        v_38 = (__int64)dst2;
                                                                                                        sub_14002EDF0(0, 3);
                                                                                                        if (result == 0) {
                                                                                                            return v_38;
                                                                                                        }
                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                        result->field_2 = 251;
                                                                                                        dst = (__int64 *)v_28;
                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                        if (result <= 2) {
                                                                                                            v_20 = 1;
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                            dst = (__int64 *)v_28;
                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                        }
                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                        result = ptr->field_2;
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                        result = ptr->field_0;
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                        v9 = dst2 + 3;
                                                                                                        v_38 = v9;
                                                                                                        off_140108030();
                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                        if (v9 == dst) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                        }
                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 193;
                                                                                                        result = dst2 + 4;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 203;
                                                                                                        result = dst2 + 5;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 25;
                                                                                                        result = dst2 + 6;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 6) = 49;
                                                                                                        result = dst2 + 7;
                                                                                                        v_38 = (__int64)result;
                                                                                                        if (result == v_28) {
                                                                                                            a1 = rsp + 40;
                                                                                                            sub_1400F3510(a1);
                                                                                                        }
                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 7) = 216;
                                                                                                        dst2 += 8;
                                                                                                        v_38 = (__int64)dst2;
                                                                                                        sub_14002EDF0(0, 8);
                                                                                                        if (result != 0) {
                                                                                                            dst2 = (__int64 *)result;
                                                                                                            *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                            result->field_2 = 36;
                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                            v3 = v_38;
                                                                                                            arg_3 = 276;
                                                                                                            result -= v3;
                                                                                                            if (result <= 6) {
                                                                                                                v_20 = 1;
                                                                                                                a1 = rsp + 40;
                                                                                                                sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                v3 = v_38;
                                                                                                            }
                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                            a1 = *dst2;
                                                                                                            v6 = arg_3;
                                                                                                            *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                            v3 += 7;
                                                                                                            v_38 = v3;
                                                                                                            off_140108030(a1, v3, v6);
                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                            sub_14002EDF0(0, 3);
                                                                                                            if (result != 0) {
                                                                                                                dst2 = (__int64 *)result;
                                                                                                                *(__int64 *)result = (__int64)(0xFB21);
                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                v3 = v_38;
                                                                                                                result -= v3;
                                                                                                                if (result <= 1) {
                                                                                                                    v_20 = 1;
                                                                                                                    a1 = rsp + 40;
                                                                                                                    sub_1400F2D20(a1, v3, 2, 1);
                                                                                                                    v3 = v_38;
                                                                                                                }
                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                a1 = *dst2;
                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                v3 += 2;
                                                                                                                v_38 = v3;
                                                                                                                off_140108030(a1, v3);
                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                if (result != 0) {
                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                    *(__int64 *)result = (__int64)(0xD7F7);
                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                    v3 = v_38;
                                                                                                                    result -= v3;
                                                                                                                    if (result <= 1) {
                                                                                                                        v_20 = 1;
                                                                                                                        a1 = rsp + 40;
                                                                                                                        sub_1400F2D20(a1, v3, 2, 1);
                                                                                                                        v3 = v_38;
                                                                                                                    }
                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                    a1 = *dst2;
                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                    v3 += 2;
                                                                                                                    v_38 = v3;
                                                                                                                    off_140108030(a1, v3);
                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                    if (result != 0) {
                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                        *(__int64 *)result = (__int64)(0xBC23);
                                                                                                                        result->field_2 = 36;
                                                                                                                        result->field_3 = 280;
                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                        if (result <= 6) {
                                                                                                                            v_20 = 1;
                                                                                                                            a1 = rsp + 40;
                                                                                                                            sub_1400F2D20(a1, dst2, 7, 1);
                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                        }
                                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                                        result = ptr->field_0;
                                                                                                                        a1 = ptr->field_3;
                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = a1;
                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                        v9 = dst2 + 7;
                                                                                                                        v_38 = v9;
                                                                                                                        off_140108030(a1);
                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                        if (v9 == dst) {
                                                                                                                            a1 = rsp + 40;
                                                                                                                            sub_1400F3510(a1);
                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                        }
                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 7) = 49;
                                                                                                                        result = dst2 + 8;
                                                                                                                        v_38 = (__int64)result;
                                                                                                                        if (result == v_28) {
                                                                                                                            a1 = rsp + 40;
                                                                                                                            sub_1400F3510(a1);
                                                                                                                        }
                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 8) = 251;
                                                                                                                        dst2 += 9;
                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                        if (result != 0) {
                                                                                                                            ptr = (struct Struct_2_t *)result;
                                                                                                                            *(__int64 *)result = (__int64)(0x8403);
                                                                                                                            result->field_2 = 36;
                                                                                                                            result->field_3 = 284;
                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                            result = (struct Struct_1_t *)dst;
                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                            if (result <= 6) {
                                                                                                                                v_20 = 1;
                                                                                                                                a1 = rsp + 40;
                                                                                                                                sub_1400F2D20(a1, dst2, 7, 1);
                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                            }
                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                            result = ptr->field_0;
                                                                                                                            a1 = ptr->field_3;
                                                                                                                            *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = a1;
                                                                                                                            *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                            v9 = dst2 + 7;
                                                                                                                            v_38 = v9;
                                                                                                                            off_140108030(a1);
                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                            if (v9 == dst) {
                                                                                                                                a1 = rsp + 40;
                                                                                                                                sub_1400F3510(a1);
                                                                                                                                dst3 = (__int64 *)v_30;
                                                                                                                            }
                                                                                                                            *(__int64 *)((__int64)dst3 + (__int64)dst2 + 7) = 1;
                                                                                                                            result = dst2 + 8;
                                                                                                                            v_38 = (__int64)result;
                                                                                                                            if (result == v_28) {
                                                                                                                                a1 = rsp + 40;
                                                                                                                                sub_1400F3510(a1);
                                                                                                                            }
                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 8) = 216;
                                                                                                                            dst2 += 9;
                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                            if (result != 0) {
                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                *(__int64 *)result = (__int64)(833);
                                                                                                                                result->field_2 = 130;
                                                                                                                                result->field_3 = 0;
                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                v3 = v_38;
                                                                                                                                result -= v3;
                                                                                                                                if (result <= 6) {
                                                                                                                                    v_20 = 1;
                                                                                                                                    a1 = rsp + 40;
                                                                                                                                    sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                    v3 = v_38;
                                                                                                                                }
                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                a1 = *dst2;
                                                                                                                                v6 = arg_3;
                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                v3 += 7;
                                                                                                                                v_38 = v3;
                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                if (result != 0) {
                                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                                    *(__int64 *)result = (__int64)(833);
                                                                                                                                    result->field_2 = 129;
                                                                                                                                    result->field_3 = 0;
                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                    v3 = v_38;
                                                                                                                                    result -= v3;
                                                                                                                                    if (result <= 6) {
                                                                                                                                        v_20 = 1;
                                                                                                                                        a1 = rsp + 40;
                                                                                                                                        sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                        v3 = v_38;
                                                                                                                                    }
                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                    a1 = *dst2;
                                                                                                                                    v6 = arg_3;
                                                                                                                                    *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                    v3 += 7;
                                                                                                                                    v_38 = v3;
                                                                                                                                    off_140108030(a1, v3, v6);
                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                    if (result == 0) {
                                                                                                                                        return v_38;
                                                                                                                                    }
                                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                                    *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                    result->field_2 = 198;
                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                    v3 = v_38;
                                                                                                                                    result -= v3;
                                                                                                                                    if (result <= 2) {
                                                                                                                                        v_20 = 1;
                                                                                                                                        a1 = rsp + 40;
                                                                                                                                        sub_1400F2D20(a1, v3, 3, 1);
                                                                                                                                        v3 = v_38;
                                                                                                                                    }
                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                    a1 = (size_t *)arg_2;
                                                                                                                                    *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                                                                                    a1 = *dst2;
                                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                    v3 += 3;
                                                                                                                                    v_38 = v3;
                                                                                                                                    off_140108030(a1, v3);
                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                    if (result != 0) {
                                                                                                                                        dst2 = (__int64 *)result;
                                                                                                                                        *(__int64 *)result = (__int64)(0x848B);
                                                                                                                                        result->field_2 = 36;
                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                        v3 = v_38;
                                                                                                                                        arg_3 = 256;
                                                                                                                                        result -= v3;
                                                                                                                                        if (result <= 6) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                            v3 = v_38;
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        a1 = *dst2;
                                                                                                                                        v6 = arg_3;
                                                                                                                                        *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                        *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                        v3 += 7;
                                                                                                                                        v_38 = v3;
                                                                                                                                        off_140108030(a1, v3, v6);
                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                        sub_14002EDF0(0, 3);
                                                                                                                                        if (result == 0) {
                                                                                                                                            return v_38;
                                                                                                                                        }
                                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                        result->field_2 = 199;
                                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                        if (result <= 2) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                        }
                                                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                                                        result = ptr->field_2;
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                                                        result = ptr->field_0;
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                                        v9 = dst2 + 3;
                                                                                                                                        v_38 = v9;
                                                                                                                                        off_140108030();
                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                        if (v9 == dst) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                                        }
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 193;
                                                                                                                                        result = dst2 + 4;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 200;
                                                                                                                                        result = dst2 + 5;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 2;
                                                                                                                                        dst2 += 6;
                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                        sub_14002EDF0(0, 3);
                                                                                                                                        if (result == 0) {
                                                                                                                                            return v_38;
                                                                                                                                        }
                                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                        result->field_2 = 251;
                                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                        if (result <= 2) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                        }
                                                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                                                        result = ptr->field_2;
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                                                        result = ptr->field_0;
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                                        v9 = dst2 + 3;
                                                                                                                                        v_38 = v9;
                                                                                                                                        off_140108030();
                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                        if (v9 == dst) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                                        }
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 193;
                                                                                                                                        result = dst2 + 4;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 203;
                                                                                                                                        result = dst2 + 5;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 13;
                                                                                                                                        result = dst2 + 6;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 6) = 49;
                                                                                                                                        result = dst2 + 7;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 7) = 216;
                                                                                                                                        dst2 += 8;
                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                        sub_14002EDF0(0, 3);
                                                                                                                                        if (result == 0) {
                                                                                                                                            return v_38;
                                                                                                                                        }
                                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                        result->field_2 = 251;
                                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                        if (result <= 2) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                        }
                                                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                                                        result = ptr->field_2;
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                                                        result = ptr->field_0;
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                                        v9 = dst2 + 3;
                                                                                                                                        v_38 = v9;
                                                                                                                                        off_140108030();
                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                        if (v9 == dst) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                                        }
                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 193;
                                                                                                                                        result = dst2 + 4;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 203;
                                                                                                                                        result = dst2 + 5;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 22;
                                                                                                                                        result = dst2 + 6;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 6) = 49;
                                                                                                                                        result = dst2 + 7;
                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                        if (result == v_28) {
                                                                                                                                            a1 = rsp + 40;
                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                        }
                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 7) = 216;
                                                                                                                                        dst2 += 8;
                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                        if (result != 0) {
                                                                                                                                            dst2 = (__int64 *)result;
                                                                                                                                            *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                            result->field_2 = 36;
                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                            v3 = v_38;
                                                                                                                                            arg_3 = 260;
                                                                                                                                            result -= v3;
                                                                                                                                            if (result <= 6) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                v3 = v_38;
                                                                                                                                            }
                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                            a1 = *dst2;
                                                                                                                                            v6 = arg_3;
                                                                                                                                            *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                            v3 += 7;
                                                                                                                                            v_38 = v3;
                                                                                                                                            off_140108030(a1, v3, v6);
                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                            if (result != 0) {
                                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                                *(__int64 *)result = (__int64)(0x249C8B44);
                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                v3 = v_38;
                                                                                                                                                arg_4 = 264;
                                                                                                                                                result -= v3;
                                                                                                                                                if (result <= 7) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                    sub_1400F2D20(a1, v3, 8, 1);
                                                                                                                                                    v3 = v_38;
                                                                                                                                                }
                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                a1 = *dst2;
                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                v3 += 8;
                                                                                                                                                v_38 = v3;
                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                if (result == 0) {
                                                                                                                                                    return v_38;
                                                                                                                                                }
                                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                                *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                                result->field_2 = 250;
                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                v3 = v_38;
                                                                                                                                                result -= v3;
                                                                                                                                                if (result <= 2) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                    sub_1400F2D20(a1, v3, 3, 1);
                                                                                                                                                    v3 = v_38;
                                                                                                                                                }
                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                a1 = (size_t *)arg_2;
                                                                                                                                                *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                                                                                                a1 = *dst2;
                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                v3 += 3;
                                                                                                                                                v_38 = v3;
                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                if (result != 0) {
                                                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                                                    *(__int64 *)result = (__int64)(0xDA21);
                                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                                    v3 = v_38;
                                                                                                                                                    result -= v3;
                                                                                                                                                    if (result <= 1) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                        sub_1400F2D20(a1, v3, 2, 1);
                                                                                                                                                        v3 = v_38;
                                                                                                                                                    }
                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                    a1 = *dst2;
                                                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                    v3 += 2;
                                                                                                                                                    v_38 = v3;
                                                                                                                                                    off_140108030(a1, v3);
                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                                    if (result != 0) {
                                                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                                                        *(__int64 *)result = (__int64)(0x2144);
                                                                                                                                                        result->field_2 = 223;
                                                                                                                                                        dst = (__int64 *)v_28;
                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                        result = (struct Struct_1_t *)dst;
                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                        if (result <= 2) {
                                                                                                                                                            v_20 = 1;
                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                            sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                        }
                                                                                                                                                        dst3 = (__int64 *)v_30;
                                                                                                                                                        result = ptr->field_2;
                                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                                                        v9 = dst2 + 3;
                                                                                                                                                        v_38 = v9;
                                                                                                                                                        off_140108030();
                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                                        if (v9 == dst) {
                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                                                        }
                                                                                                                                                        *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 49;
                                                                                                                                                        result = dst2 + 4;
                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                        if (result == v_28) {
                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                        }
                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 250;
                                                                                                                                                        dst2 += 5;
                                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                                        sub_14002EDF0(0, 3);
                                                                                                                                                        if (result != 0) {
                                                                                                                                                            ptr = (struct Struct_2_t *)result;
                                                                                                                                                            *(__int64 *)result = (__int64)(0x2144);
                                                                                                                                                            result->field_2 = 219;
                                                                                                                                                            dst = (__int64 *)v_28;
                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                            result = (struct Struct_1_t *)dst;
                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                            if (result <= 2) {
                                                                                                                                                                v_20 = 1;
                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                                                dst2 = (__int64 *)v_38;
                                                                                                                                                            }
                                                                                                                                                            dst3 = (__int64 *)v_30;
                                                                                                                                                            result = ptr->field_2;
                                                                                                                                                            *(__int64 *)((__int64)dst3 + (__int64)dst2 + 2) = result;
                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                            *(__int64 *)((__int64)dst3 + (__int64)dst2) = result;
                                                                                                                                                            v9 = dst2 + 3;
                                                                                                                                                            v_38 = v9;
                                                                                                                                                            off_140108030();
                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                                            if (v9 == dst) {
                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                dst3 = (__int64 *)v_30;
                                                                                                                                                            }
                                                                                                                                                            *(__int64 *)((__int64)dst3 + (__int64)dst2 + 3) = 49;
                                                                                                                                                            result = dst2 + 4;
                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                            }
                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 4) = 218;
                                                                                                                                                            result = dst2 + 5;
                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                            }
                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 5) = 1;
                                                                                                                                                            result = dst2 + 6;
                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                            }
                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst2 + 6) = 208;
                                                                                                                                                            dst2 += 7;
                                                                                                                                                            v_38 = (__int64)dst2;
                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                            if (result != 0) {
                                                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                                                *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                result->field_2 = 36;
                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                v3 = v_38;
                                                                                                                                                                arg_3 = 280;
                                                                                                                                                                result -= v3;
                                                                                                                                                                if (result <= 6) {
                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                    sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                }
                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                a1 = *dst2;
                                                                                                                                                                v6 = arg_3;
                                                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                v3 += 7;
                                                                                                                                                                v_38 = v3;
                                                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                if (result != 0) {
                                                                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                                                                    *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                    result->field_2 = 36;
                                                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                    arg_3 = 284;
                                                                                                                                                                    result -= v3;
                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                        sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                        v3 = v_38;
                                                                                                                                                                    }
                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                    a1 = *dst2;
                                                                                                                                                                    v6 = arg_3;
                                                                                                                                                                    *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                    v3 += 7;
                                                                                                                                                                    v_38 = v3;
                                                                                                                                                                    off_140108030(a1, v3, v6);
                                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                        dst2 = (__int64 *)result;
                                                                                                                                                                        *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                        result->field_2 = 36;
                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                        v3 = v_38;
                                                                                                                                                                        arg_3 = 276;
                                                                                                                                                                        result -= v3;
                                                                                                                                                                        if (result <= 6) {
                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                            sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                        }
                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                        a1 = *dst2;
                                                                                                                                                                        v6 = arg_3;
                                                                                                                                                                        *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                        *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                        v3 += 7;
                                                                                                                                                                        v_38 = v3;
                                                                                                                                                                        off_140108030(a1, v3, v6);
                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                            dst2 = (__int64 *)result;
                                                                                                                                                                            *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                            result->field_2 = 36;
                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                            arg_3 = 280;
                                                                                                                                                                            result -= v3;
                                                                                                                                                                            if (result <= 6) {
                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                            }
                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                            a1 = *dst2;
                                                                                                                                                                            v6 = arg_3;
                                                                                                                                                                            *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                            v3 += 7;
                                                                                                                                                                            v_38 = v3;
                                                                                                                                                                            off_140108030(a1, v3, v6);
                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                                                                *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                                result->field_2 = 36;
                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                arg_3 = 272;
                                                                                                                                                                                result -= v3;
                                                                                                                                                                                if (result <= 6) {
                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                    sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                                }
                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                a1 = *dst2;
                                                                                                                                                                                v6 = arg_3;
                                                                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                v3 += 7;
                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                                    result->field_2 = 36;
                                                                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                                    arg_3 = 276;
                                                                                                                                                                                    result -= v3;
                                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                        sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                        v3 = v_38;
                                                                                                                                                                                    }
                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                    a1 = *dst2;
                                                                                                                                                                                    v6 = arg_3;
                                                                                                                                                                                    *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                    v3 += 7;
                                                                                                                                                                                    v_38 = v3;
                                                                                                                                                                                    off_140108030(a1, v3, v6);
                                                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                                                                                        *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                                        result->field_2 = 36;
                                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                                                        ptr->field_3 = 268;
                                                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                        if (result <= 6) {
                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                            sub_1400F2D20(a1, dst2, 7, 1);
                                                                                                                                                                                            dst2 = (__int64 *)v_38;
                                                                                                                                                                                        }
                                                                                                                                                                                        dst = (__int64 *)v_30;
                                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                                        a1 = ptr->field_3;
                                                                                                                                                                                        *(__int64 *)((__int64)dst + (__int64)dst2 + 3) = a1;
                                                                                                                                                                                        *(__int64 *)((__int64)dst + (__int64)dst2) = result;
                                                                                                                                                                                        dst3 = dst2 + 7;
                                                                                                                                                                                        v_38 = (__int64)dst3;
                                                                                                                                                                                        off_140108030(a1);
                                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                                                                        if (dst3 == v_28) {
                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                            dst = (__int64 *)v_30;
                                                                                                                                                                                        }
                                                                                                                                                                                        *(__int64 *)((__int64)dst + (__int64)dst2 + 7) = 1;
                                                                                                                                                                                        result = dst2 + 8;
                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                        }
                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)dst2 + 8) = 243;
                                                                                                                                                                                        dst2 += 9;
                                                                                                                                                                                        v_38 = (__int64)dst2;
                                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                            dst2 = (__int64 *)result;
                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                                            result->field_2 = 36;
                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                            arg_3 = 272;
                                                                                                                                                                                            result -= v3;
                                                                                                                                                                                            if (result <= 6) {
                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                            }
                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                            a1 = *dst2;
                                                                                                                                                                                            v6 = arg_3;
                                                                                                                                                                                            *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                            v3 += 7;
                                                                                                                                                                                            v_38 = v3;
                                                                                                                                                                                            off_140108030(a1, v3, v6);
                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                                                result->field_2 = 36;
                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                arg_3 = 264;
                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                if (result <= 6) {
                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                                    sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                                                }
                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                a1 = *dst2;
                                                                                                                                                                                                v6 = arg_3;
                                                                                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                v3 += 7;
                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                                    dst2 = (__int64 *)result;
                                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                                                    result->field_2 = 36;
                                                                                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                                                    arg_3 = 268;
                                                                                                                                                                                                    result -= v3;
                                                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                        sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                        v3 = v_38;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                    a1 = *dst2;
                                                                                                                                                                                                    v6 = arg_3;
                                                                                                                                                                                                    *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                    *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                    v3 += 7;
                                                                                                                                                                                                    v_38 = v3;
                                                                                                                                                                                                    off_140108030(a1, v3, v6);
                                                                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                        dst2 = (__int64 *)result;
                                                                                                                                                                                                        *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                                                        result->field_2 = 36;
                                                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                        v3 = v_38;
                                                                                                                                                                                                        arg_3 = 260;
                                                                                                                                                                                                        result -= v3;
                                                                                                                                                                                                        if (result <= 6) {
                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                            sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                        }
                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                        a1 = *dst2;
                                                                                                                                                                                                        v6 = arg_3;
                                                                                                                                                                                                        *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                        *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                        v3 += 7;
                                                                                                                                                                                                        v_38 = v3;
                                                                                                                                                                                                        off_140108030(a1, v3, v6);
                                                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                            dst2 = (__int64 *)result;
                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                                                            result->field_2 = 36;
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                            arg_3 = 264;
                                                                                                                                                                                                            result -= v3;
                                                                                                                                                                                                            if (result <= 6) {
                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                            }
                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                            a1 = *dst2;
                                                                                                                                                                                                            v6 = arg_3;
                                                                                                                                                                                                            *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                            v3 += 7;
                                                                                                                                                                                                            v_38 = v3;
                                                                                                                                                                                                            off_140108030(a1, v3, v6);
                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                dst2 = (__int64 *)result;
                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x9C8B);
                                                                                                                                                                                                                result->field_2 = 36;
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                arg_3 = 256;
                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                if (result <= 6) {
                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                                                    sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                                    v3 = v_38;
                                                                                                                                                                                                                }
                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                a1 = *dst2;
                                                                                                                                                                                                                v6 = arg_3;
                                                                                                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                v3 += 7;
                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x9C89);
                                                                                                                                                                                                                    result->field_2 = 36;
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                    ptr->field_3 = 260;
                                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                    if (result <= 6) {
                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F2D20(a1, dst2, 7, 1);
                                                                                                                                                                                                                        dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    dst = (__int64 *)v_30;
                                                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                                                    a1 = ptr->field_3;
                                                                                                                                                                                                                    *(__int64 *)((__int64)dst + (__int64)dst2 + 3) = a1;
                                                                                                                                                                                                                    *(__int64 *)((__int64)dst + (__int64)dst2) = result;
                                                                                                                                                                                                                    dst3 = dst2 + 7;
                                                                                                                                                                                                                    v_38 = (__int64)dst3;
                                                                                                                                                                                                                    off_140108030(a1);
                                                                                                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                                                                                                    if (dst3 == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                        dst = (__int64 *)v_30;
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    *(__int64 *)((__int64)dst + (__int64)dst2 + 7) = 1;
                                                                                                                                                                                                                    result = dst2 + 8;
                                                                                                                                                                                                                    v_38 = (__int64)result;
                                                                                                                                                                                                                    if (result == v_28) {
                                                                                                                                                                                                                        a1 = rsp + 40;
                                                                                                                                                                                                                        sub_1400F3510(a1);
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)dst2 + 8) = 240;
                                                                                                                                                                                                                    dst2 += 9;
                                                                                                                                                                                                                    v_38 = (__int64)dst2;
                                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                                        dst2 = (__int64 *)result;
                                                                                                                                                                                                                        *(__int64 *)result = (__int64)(0x8489);
                                                                                                                                                                                                                        result->field_2 = 36;
                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                        v3 = v_38;
                                                                                                                                                                                                                        arg_3 = 256;
                                                                                                                                                                                                                        result -= v3;
                                                                                                                                                                                                                        if (result <= 6) {
                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                            sub_1400F2D20(a1, v3, 7, 1);
                                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                                        }
                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                        a1 = *dst2;
                                                                                                                                                                                                                        v6 = arg_3;
                                                                                                                                                                                                                        *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                                        *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                        v3 += 7;
                                                                                                                                                                                                                        v_38 = v3;
                                                                                                                                                                                                                        off_140108030(a1, v3, v6);
                                                                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                                        sub_14002EDF0(0, 7);
                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                            dst2 = (__int64 *)result;
                                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x4C18349);
                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                                            result -= v3;
                                                                                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                sub_1400F2D20(a1, v3, 4, 1);
                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                            }
                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                            a1 = *dst2;
                                                                                                                                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                            v3 += 4;
                                                                                                                                                                                                                            v_38 = v3;
                                                                                                                                                                                                                            off_140108030(a1, v3);
                                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                                            sub_14002EDF0(0, 7);
                                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                                ptr = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x4C28349);
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
                                                                                                                                                                                                                                a1 = ptr->field_0;
                                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = a1;
                                                                                                                                                                                                                                dst2 += 4;
                                                                                                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, ptr);
                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                                if (result <= 1) {
                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                                                                    sub_1400F2D20(a1, dst2, 2, 1);
                                                                                                                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = 0xC1FF;
                                                                                                                                                                                                                                dst2 += 2;
                                                                                                                                                                                                                                v_38 = (__int64)dst2;
                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                                                                                                                                                                                                                                if (result <= 2) {
                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                                                                    sub_1400F2D20(a1, dst2, 3, 1);
                                                                                                                                                                                                                                    dst2 = (__int64 *)v_38;
                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2 + 2) = 64;
                                                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)dst2) = 0xF983;
                                                                                                                                                                                                                                v3 = dst2 + 3;
                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                dst2 += 9;
                                                                                                                                                                                                                                if (!((dst2 < 0))) {
                                                                                                                                                                                                                                    src2 = (__int64 *)((__int64)src2 - (__int64)dst2);
                                                                                                                                                                                                                                    a1 = (size_t *)src2;
                                                                                                                                                                                                                                    if (src2 == src2) {
                                                                                                                                                                                                                                        a1 = (size_t *)v_28;
                                                                                                                                                                                                                                        a1 -= v3;
                                                                                                                                                                                                                                        if (a1 <= 1) {
                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                            sub_1400F2D20(a1, v3, 2, 1);
                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                        *(__int64 *)(result + v3) = (__int64)(0x820F);
                                                                                                                                                                                                                                        v3 += 2;
                                                                                                                                                                                                                                        v_38 = v3;
                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                        result -= v3;
                                                                                                                                                                                                                                        if (result <= 3) {
                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                            sub_1400F2D20(a1, v3, 4, 1);
                                                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                        *(__int64 *)(result + v3) = (__int64)(src2);
                                                                                                                                                                                                                                        v3 += 4;
                                                                                                                                                                                                                                        v_38 = v3;
                                                                                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                            src2 = (__int64 *)result;
                                                                                                                                                                                                                                            *(__int64 *)result = (__int64)(0x248C8B48);
                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                            v3 = v_38;
                                                                                                                                                                                                                                            arg_4 = 288;
                                                                                                                                                                                                                                            result -= v3;
                                                                                                                                                                                                                                            if (result <= 7) {
                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                                sub_1400F2D20(a1, v3, 8, 1);
                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                            a1 = *src2;
                                                                                                                                                                                                                                            *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                            v3 += 8;
                                                                                                                                                                                                                                            v_38 = v3;
                                                                                                                                                                                                                                            off_140108030(a1, v3);
                                                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, src2);
                                                                                                                                                                                                                                            src2 = rsp + 64;
                                                                                                                                                                                                                                            ptr = 0;
                                                                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                            while (result != 0) {
                                                                                                                                                                                                                                                ptr2 = ptr + 256;
                                                                                                                                                                                                                                                v_40 = 8;
                                                                                                                                                                                                                                                v_48 = (__int64)result;
                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(139);
                                                                                                                                                                                                                                                v_50 = 1;
                                                                                                                                                                                                                                                sub_1400D4F50(src2, 0, 4, ptr2);
                                                                                                                                                                                                                                                dst = (__int64 *)v_40;
                                                                                                                                                                                                                                                dst3 = (__int64 *)v_48;
                                                                                                                                                                                                                                                v9 = v_50;
                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                v12 = v_38;
                                                                                                                                                                                                                                                result -= v12;
                                                                                                                                                                                                                                                if (v9 > result) {
                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                                                                                    sub_1400F2D20(a1, v12, v9, 1);
                                                                                                                                                                                                                                                    v12 = v_38;
                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                                                                                a1 += v12;
                                                                                                                                                                                                                                                sub_1400F27F0(a1, dst3, v9);
                                                                                                                                                                                                                                                v12 += v9;
                                                                                                                                                                                                                                                v_38 = v12;
                                                                                                                                                                                                                                                if (dst == 0) {
                                                                                                                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                                                                        v_40 = 8;
                                                                                                                                                                                                                                                        v_48 = (__int64)result;
                                                                                                                                                                                                                                                        *(__int64 *)result = (__int64)(139);
                                                                                                                                                                                                                                                        v_50 = 1;
                                                                                                                                                                                                                                                        sub_1400D4F50(src2, 3, 1, ptr);
                                                                                                                                                                                                                                                        dst = (__int64 *)v_40;
                                                                                                                                                                                                                                                        v9 = v_48;
                                                                                                                                                                                                                                                        v12 = v_50;
                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                        dst3 = (__int64 *)v_38;
                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst3);
                                                                                                                                                                                                                                                        if (v12 > result) {
                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                            sub_1400F2D20(a1, dst3, v12, 1);
                                                                                                                                                                                                                                                            dst3 = (__int64 *)v_38;
                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                        dst2 = (__int64 *)v_30;
                                                                                                                                                                                                                                                        a1 = (__int64)dst2 + (__int64)dst3;
                                                                                                                                                                                                                                                        sub_1400F27F0(a1, v9, v12);
                                                                                                                                                                                                                                                        dst3 += v12;
                                                                                                                                                                                                                                                        v_38 = (__int64)dst3;
                                                                                                                                                                                                                                                        if (dst == 0) {
                                                                                                                                                                                                                                                            if (dst3 == v_28) {
                                                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                                                                                dst2 = (__int64 *)v_30;
                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                            *(__int64 *)((__int64)dst2 + (__int64)dst3) = 1;
                                                                                                                                                                                                                                                            result = dst3 + 1;
                                                                                                                                                                                                                                                            v_38 = (__int64)result;
                                                                                                                                                                                                                                                            if (result == v_28) {
                                                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)dst3 + 1) = 195;
                                                                                                                                                                                                                                                            dst3 += 2;
                                                                                                                                                                                                                                                            v_38 = (__int64)dst3;
                                                                                                                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                                                                                v_40 = 8;
                                                                                                                                                                                                                                                                v_48 = (__int64)result;
                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(137);
                                                                                                                                                                                                                                                                v_50 = 1;
                                                                                                                                                                                                                                                                sub_1400D4F50(src2, 3, 1, ptr);
                                                                                                                                                                                                                                                                dst = (__int64 *)v_40;
                                                                                                                                                                                                                                                                dst3 = (__int64 *)v_48;
                                                                                                                                                                                                                                                                v9 = v_50;
                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                v12 = v_38;
                                                                                                                                                                                                                                                                result -= v12;
                                                                                                                                                                                                                                                                if (v9 > result) {
                                                                                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                                                                                    a1 = rsp + 40;
                                                                                                                                                                                                                                                                    sub_1400F2D20(a1, v12, v9, 1);
                                                                                                                                                                                                                                                                    v12 = v_38;
                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                                                                                                a1 += v12;
                                                                                                                                                                                                                                                                sub_1400F27F0(a1, dst3, v9);
                                                                                                                                                                                                                                                                v12 += v9;
                                                                                                                                                                                                                                                                v_38 = v12;
                                                                                                                                                                                                                                                                if (dst == 0) {
                                                                                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                                                                                    sub_14002EDF0(0, 7);
                                                                                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                                                                                        dst2 = (__int64 *)result;
                                                                                                                                                                                                                                                                        *(__int64 *)result = (__int64)(0x8148);
                                                                                                                                                                                                                                                                        result->field_3 = 296;
                                                                                                                                                                                                                                                                        result->field_2 = 196;
                                                                                                                                                                                                                                                                        src = (__int64 *)v_28;
                                                                                                                                                                                                                                                                        src2 = (__int64 *)v_38;
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)src;
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                                                                                                                                                                                                                        if (result <= 6) {
                                                                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F2D20(a1, src2, 7, 1);
                                                                                                                                                                                                                                                                            src = (__int64 *)v_28;
                                                                                                                                                                                                                                                                            src2 = (__int64 *)v_38;
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        dst = (__int64 *)v_30;
                                                                                                                                                                                                                                                                        result = *dst2;
                                                                                                                                                                                                                                                                        a1 = (size_t *)arg_3;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)dst + (__int64)src2 + 3) = a1;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)dst + (__int64)src2) = result;
                                                                                                                                                                                                                                                                        ptr = src2 + 7;
                                                                                                                                                                                                                                                                        v_38 = (__int64)ptr;
                                                                                                                                                                                                                                                                        off_140108030(a1);
                                                                                                                                                                                                                                                                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                                                                                        if (ptr == src) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                            dst = (__int64 *)v_30;
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)dst + (__int64)src2 + 7) = 65;
                                                                                                                                                                                                                                                                        result = src2 + 8;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 8) = 95;
                                                                                                                                                                                                                                                                        result = src2 + 9;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 9) = 65;
                                                                                                                                                                                                                                                                        result = src2 + 10;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 10) = 94;
                                                                                                                                                                                                                                                                        result = src2 + 11;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 11) = 65;
                                                                                                                                                                                                                                                                        result = src2 + 12;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 12) = 93;
                                                                                                                                                                                                                                                                        result = src2 + 13;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 13) = 65;
                                                                                                                                                                                                                                                                        result = src2 + 14;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 14) = 92;
                                                                                                                                                                                                                                                                        result = src2 + 15;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 15) = 95;
                                                                                                                                                                                                                                                                        result = src2 + 16;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 16) = 94;
                                                                                                                                                                                                                                                                        result = src2 + 17;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 17) = 93;
                                                                                                                                                                                                                                                                        result = src2 + 18;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 18) = 91;
                                                                                                                                                                                                                                                                        result = src2 + 19;
                                                                                                                                                                                                                                                                        v_38 = (__int64)result;
                                                                                                                                                                                                                                                                        if (result == v_28) {
                                                                                                                                                                                                                                                                            a1 = rsp + 40;
                                                                                                                                                                                                                                                                            sub_1400F3510(a1);
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)src2 + 19) = 195;
                                                                                                                                                                                                                                                                        src2 += 20;
                                                                                                                                                                                                                                                                        v_38 = (__int64)src2;
                                                                                                                                                                                                                                                                        sub_14002EDF0(0, 5);
                                                                                                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                                                                                                            dst2 = (__int64 *)result;
                                                                                                                                                                                                                                                                            *(__int64 *)result = (__int64)(233);
                                                                                                                                                                                                                                                                            result->field_1 = 256;
                                                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                            src2 = (__int64 *)v_38;
                                                                                                                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)src2);
                                                                                                                                                                                                                                                                            if (result <= 4) {
                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                                                                sub_1400F2D20(a1, src2, 5, 1);
                                                                                                                                                                                                                                                                                src2 = (__int64 *)v_38;
                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                            a1 = (size_t *)arg_4;
                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)src2 + 4) = a1;
                                                                                                                                                                                                                                                                            a1 = *dst2;
                                                                                                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)src2) = a1;
                                                                                                                                                                                                                                                                            src2 += 5;
                                                                                                                                                                                                                                                                            v_38 = (__int64)src2;
                                                                                                                                                                                                                                                                            off_140108030(a1);
                                                                                                                                                                                                                                                                            src = 0;
                                                                                                                                                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, dst2);
                                                                                                                                                                                                                                                                            ptr = &off_14011CBA0;
                                                                                                                                                                                                                                                                            dst2 = rsp + 40;
                                                                                                                                                                                                                                                                            v3 = (__int64)src2;
                                                                                                                                                                                                                                                                            do {
                                                                                                                                                                                                                                                                                dst = *(__int64 *)((__int64)src + (__int64)ptr);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                                                                                                sub_1400F2D20(dst2, v3, 4, 1);
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(dst);
                                                                                                                                                                                                                                                                                v3 += 4;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                src += 4;
                                                                                                                                                                                                                                                                            } while (src != 256);
                                                                                                                                                                                                                                                                            result = (struct Struct_1_t *)v_38;
                                                                                                                                                                                                                                                                            ptr2 = (struct Struct_3_t *)v_60;
                                                                                                                                                                                                                                                                            ptr2->field_10 = result;
                                                                                                                                                                                                                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                                                                                                                                                                                                            _mm_storeu_si128((__m128i *)ptr2, xmm0);
                                                                                                                                                                                                                                                                            a1 = (size_t *)v_58;
                                                                                                                                                                                                                                                                            v3 = (__int64)a1;
                                                                                                                                                                                                                                                                            v3 += 10;
                                                                                                                                                                                                                                                                            if (!((v3 < 0))) {
                                                                                                                                                                                                                                                                                src2 -= v3;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)src2;
                                                                                                                                                                                                                                                                                if (src2 == src2) {
                                                                                                                                                                                                                                                                                    v6 = ptr2->field_10;
                                                                                                                                                                                                                                                                                    if (v3 > v6) {
                                                                                                                                                                                                                                                                                        a1 += 6;
                                                                                                                                                                                                                                                                                        ptr2 = &off_14011CCD0;
                                                                                                                                                                                                                                                                                        sub_1400F3600(a1, v3, v6, ptr2);
                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 8);
                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 3);
                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 7);
                                                                                                                                                                                                                                                                                        result = &off_14011B3E0;
                                                                                                                                                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                        a1 = &off_14011B3C3;
                                                                                                                                                                                                                                                                                        ptr2 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                        v6 = rsp + 64;
                                                                                                                                                                                                                                                                                        sub_1400F3B80(a1, 23, v6, ptr2);
                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 4);
                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 6);
                                                                                                                                                                                                                                                                                        result = &off_14011CE10;
                                                                                                                                                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                        a1 = &off_14011CE00;
                                                                                                                                                                                                                                                                                        ptr2 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                        v6 = rsp + 64;
                                                                                                                                                                                                                                                                                        sub_1400F3B80(a1, 13, v6, ptr2);
                                                                                                                                                                                                                                                                                        result = &off_14011CB88;
                                                                                                                                                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                        a1 = &off_14011CB78;
                                                                                                                                                                                                                                                                                        ptr2 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                        v6 = rsp + 64;
                                                                                                                                                                                                                                                                                        sub_1400F3B80(a1, 12, v6, ptr2);
                                                                                                                                                                                                                                                                                        sub_1400F3326(1, 5);
                                                                                                                                                                                                                                                                                    } else {
                                                                                                                                                                                                                                                                                        result = ptr2->field_8;
                                                                                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a1 + 6) = src2;
                                                                                                                                                                                                                                                                                        return (__int64)result;
                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                result = &off_14011CCB8;
                                                                                                                                                                                                                                                                                v_20 = (__int64)result;
                                                                                                                                                                                                                                                                                a1 = &off_14011CCA0;
                                                                                                                                                                                                                                                                                ptr2 = &off_14011D3F8;
                                                                                                                                                                                                                                                                                v6 = rsp + 64;
                                                                                                                                                                                                                                                                                sub_1400F3B80(a1, 21, v6, ptr2);
                                                                                                                                                                                                                                                                                src = (__int64 *)a1;
                                                                                                                                                                                                                                                                                v_28 = 0;
                                                                                                                                                                                                                                                                                v_30 = 1;
                                                                                                                                                                                                                                                                                v_38 = 0;
                                                                                                                                                                                                                                                                                v_40 = 0;
                                                                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                                                                sub_1400F3510(a1);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(85);
                                                                                                                                                                                                                                                                                v_38 = 1;
                                                                                                                                                                                                                                                                                if (v_28 == 1) JUMPOUT(0x14010352f);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_1 = 83;
                                                                                                                                                                                                                                                                                v_38 = 2;
                                                                                                                                                                                                                                                                                if (v_28 == 2) JUMPOUT(0x14010353e);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_2 = 86;
                                                                                                                                                                                                                                                                                v_38 = 3;
                                                                                                                                                                                                                                                                                if (v_28 == 3) JUMPOUT(0x14010354d);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_3 = 87;
                                                                                                                                                                                                                                                                                v_38 = 4;
                                                                                                                                                                                                                                                                                v_40 = 4;
                                                                                                                                                                                                                                                                                if (v_28 == 4) JUMPOUT(0x14010355c);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_4 = 65;
                                                                                                                                                                                                                                                                                v_38 = 5;
                                                                                                                                                                                                                                                                                if (v_28 == 5) JUMPOUT(0x14010356b);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_5 = 84;
                                                                                                                                                                                                                                                                                v_38 = 6;
                                                                                                                                                                                                                                                                                if (v_28 == 6) JUMPOUT(0x14010357a);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_6 = 65;
                                                                                                                                                                                                                                                                                v_38 = 7;
                                                                                                                                                                                                                                                                                if (v_28 == 7) JUMPOUT(0x140103589);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_7 = 85;
                                                                                                                                                                                                                                                                                v_38 = 8;
                                                                                                                                                                                                                                                                                v_40 = 6;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                if (result == 8) JUMPOUT(0x140103598);
                                                                                                                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                                                                                                                arg_8 = 65;
                                                                                                                                                                                                                                                                                v_38 = 9;
                                                                                                                                                                                                                                                                                if (result == 9) JUMPOUT(0x1401035ac);
                                                                                                                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                                                                                                                arg_9 = 86;
                                                                                                                                                                                                                                                                                v_38 = 10;
                                                                                                                                                                                                                                                                                if (result == 10) JUMPOUT(0x1401035c0);
                                                                                                                                                                                                                                                                                a1 = (size_t *)v_30;
                                                                                                                                                                                                                                                                                a1[1] = 65;
                                                                                                                                                                                                                                                                                v_38 = 11;
                                                                                                                                                                                                                                                                                if (result == 11) JUMPOUT(0x1401035d4);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                result->field_B = 87;
                                                                                                                                                                                                                                                                                v_38 = 12;
                                                                                                                                                                                                                                                                                v_40 = 8;
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 7);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140103ca4);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x8148);
                                                                                                                                                                                                                                                                                result->field_3 = 128;
                                                                                                                                                                                                                                                                                result->field_2 = 236;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 6) JUMPOUT(0x14010373e);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                v6 = arg_3;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 7;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1401036f6);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x8949);
                                                                                                                                                                                                                                                                                result->field_2 = 204;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x140103767);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = (size_t *)arg_2;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 3;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                v_40 = 10;
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1401036f6);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x8949);
                                                                                                                                                                                                                                                                                result->field_2 = 213;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x140103790);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = (size_t *)arg_2;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 3;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1401036f6);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x894D);
                                                                                                                                                                                                                                                                                result->field_2 = 198;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x1401037b9);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = (size_t *)arg_2;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 3;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                v_40 = 12;
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1401036f6);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0x894D);
                                                                                                                                                                                                                                                                                result->field_2 = 207;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 2) JUMPOUT(0x1401037e2);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = (size_t *)arg_2;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3 + 2) = (__int64)(a1);
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 3;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140103c95);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                *(__int64 *)result = (__int64)(0xAC8B);
                                                                                                                                                                                                                                                                                result->field_2 = 36;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                arg_3 = 232;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 6) JUMPOUT(0x14010380b);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                v6 = arg_3;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3 + 3) = (__int64)(v6);
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 7;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3, v6);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                v_40 = 14;
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140103cdc);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                result = 0x61707865402444C7;
                                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 7) JUMPOUT(0x140103834);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 8;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140103cdc);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                result = 0x3320646E442444C7;
                                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 7) JUMPOUT(0x14010385d);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 8;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                v_40 = 16;
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140103cdc);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                result = 0x79622D32482444C7;
                                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                if (result <= 7) JUMPOUT(0x140103886);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 8;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                sub_14002EDF0(0, 11);
                                                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x140103cdc);
                                                                                                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                                                                                                result = 0x6B2065744C2444C7;
                                                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_28;
                                                                                                                                                                                                                                                                                v3 = v_38;
                                                                                                                                                                                                                                                                                result -= v3;
                                                                                                                                                                                                                                                                                v_60 = (__int64)src;
                                                                                                                                                                                                                                                                                if (result <= 7) JUMPOUT(0x1401038af);
                                                                                                                                                                                                                                                                                result = (struct Struct_1_t *)v_30;
                                                                                                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                                                                                                *(__int64 *)(result + v3) = (__int64)(a1);
                                                                                                                                                                                                                                                                                v3 += 8;
                                                                                                                                                                                                                                                                                v_38 = v3;
                                                                                                                                                                                                                                                                                off_140108030(a1, v3);
                                                                                                                                                                                                                                                                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                                                                                                                                                                                                                                                                dst = rsp + 72;
                                                                                                                                                                                                                                                                                v9 = rsp + 40;
                                                                                                                                                                                                                                                                                src2 = off_140108038;
                                                                                                                                                                                                                                                                                dst2 = 0;
                                                                                                                                                                                                                                                                                return sub_14010222E();
                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                            return (__int64)dst2;
                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                        return (__int64)dst2;
                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                    return (__int64)dst2;
                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                                                                ((__int64 (*)())src)(result, 0, dst3);
                                                                                                                                                                                                                                                                return (__int64)dst2;
                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                            return (__int64)dst2;
                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                        off_140108030();
                                                                                                                                                                                                                                                        ((__int64 (*)())src)(result, 0, v9);
                                                                                                                                                                                                                                                        return (__int64)dst2;
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    return (__int64)dst2;
                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                                                ((__int64 (*)())src)(result, 0, dst3);
                                                                                                                                                                                                                                                return (__int64)dst2;
                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                        return (__int64)dst2;
                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                    return (__int64)dst2;
                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                return (__int64)dst2;
                                                                                                                                                                                                                            }
                                                                                                                                                                                                                        }
                                                                                                                                                                                                                        return (__int64)dst2;
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
                                                                                                                                                            return (__int64)dst2;
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                                return (__int64)dst2;
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                    return (__int64)dst2;
                                                                                                                }
                                                                                                            }
                                                                                                            return (__int64)dst2;
                                                                                                        }
                                                                                                    }
                                                                                                    return (__int64)dst2;
                                                                                                }
                                                                                                off_140108030();
                                                                                                ((__int64 (*)())src)(result, 0, ptr);
                                                                                                return (__int64)dst2;
                                                                                            }
                                                                                            return (__int64)dst2;
                                                                                        }
                                                                                        off_140108030();
                                                                                        ((__int64 (*)())src)(result, 0, ptr);
                                                                                        return (__int64)dst2;
                                                                                    }
                                                                                }
                                                                                return (__int64)dst2;
                                                                            }
                                                                            return (__int64)dst2;
                                                                        }
                                                                        return (__int64)dst2;
                                                                    }
                                                                    return (__int64)dst2;
                                                                }
                                                            }
                                                        }
                                                        return (__int64)dst2;
                                                    }
                                                    return (__int64)dst2;
                                                }
                                                return (__int64)dst2;
                                            }
                                            return (__int64)dst2;
                                        }
                                        return (__int64)dst2;
                                    }
                                    return (__int64)dst2;
                                }
                                return (__int64)dst2;
                            }
                            off_140108030();
                            ((__int64 (*)())src)(result, 0, dst2);
                            return (__int64)dst2;
                        }
                        return (__int64)dst2;
                    }
                    return (__int64)dst2;
                }
                off_140108030();
                ((__int64 (*)())src)(result, 0, dst2);
                return (__int64)dst2;
            }
        }
        return (__int64)dst2;
    }
    return (__int64)result;
}