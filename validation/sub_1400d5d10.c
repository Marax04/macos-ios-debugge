// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int16 field_0; // offset 0
    char _pad_0[1];
    char field_3; // offset 3
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400D4F50();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_1400F3510();
__int64 sub_1400F3326();
__int64 sub_1400D69D1();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400D5D10(int *a1, int *a2, int a3, int *a4) {
    __int64 rsp;
    int arg_2;
    int arg_3;
    int v_20;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    int v_4c;
    int v_50;
    int v_54;
    __int64 v_60;
    int v_c0;
    int v_c8;
    int v_d0;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 *dst2;
    struct Struct_2_t *ptr2;
    __int64 v6;
    __int64 v7;
    __int64 v5;
    __int64 *result;
    __int64 v9;

    ptr = (struct Struct_1_t *)a4;
    dst = (__int64 *)a3;
    dst2 = (__int64 *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        a4 = dst + (__int64)(__int64)ptr*4;
        v_30 = 8;
        v_38 = (__int64)result;
        *result = 139;
        v_40 = 1;
        a1 = rsp + 48;
        v_54 = (int)a4;
        sub_1400D4F50(a1, 0, 4, a4);
        v6 = v_30;
        v7 = v_38;
        v5 = v_40;
        result = ptr2->field_0;
        ptr = ptr2->field_10;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (v5 > result) {
            v_20 = 1;
            sub_1400F2D20(ptr2, ptr, v5, 1);
            ptr = ptr2->field_10;
        }
        a1 = ptr2->field_8;
        a1 = (int *)((__int64)a1 + (__int64)ptr);
        sub_1400F27F0(a1, v7, v5);
        ptr += v5;
        ptr2->field_10 = ptr;
        if (v6 != 0) {
            off_140108030();
            off_140108038(result, 0, v7);
        }
        v9 = *dst2;
        result = v9 + 1;
        *dst2 = result;
        sub_14002EDF0(0, 8);
        if (result != 0) {
            a1 = (int *)v_c0;
            a4 = dst + (__int64)(__int64)a1*4;
            v_30 = 8;
            v_38 = (__int64)result;
            *result = 139;
            v_40 = 1;
            a1 = rsp + 48;
            v_50 = (int)a4;
            sub_1400D4F50(a1, 1, 4, a4);
            v6 = v_30;
            v7 = v_38;
            v5 = v_40;
            result = ptr2->field_0;
            ptr = ptr2->field_10;
            result = (__int64 *)((__int64)result - (__int64)ptr);
            if (v5 > result) {
                v_20 = 1;
                sub_1400F2D20(ptr2, ptr, v5, 1);
                ptr = ptr2->field_10;
            }
            a1 = ptr2->field_8;
            a1 = (int *)((__int64)a1 + (__int64)ptr);
            sub_1400F27F0(a1, v7, v5);
            ptr += v5;
            ptr2->field_10 = ptr;
            if (v6 != 0) {
                off_140108030();
                off_140108038(result, 0, v7);
            }
            result = v9 + 2;
            *dst2 = result;
            sub_14002EDF0(0, 8);
            if (result != 0) {
                a1 = (int *)v_c8;
                a4 = dst + (__int64)(__int64)a1*4;
                v_30 = 8;
                v_38 = (__int64)result;
                *result = 139;
                v_40 = 1;
                a1 = rsp + 48;
                v_4c = (int)a4;
                sub_1400D4F50(a1, 2, 4, a4);
                v7 = v_30;
                v5 = v_38;
                v6 = v_40;
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                result = (__int64 *)((__int64)result - (__int64)ptr);
                if (v6 > result) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr, v6, 1);
                    ptr = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                a1 = (int *)((__int64)a1 + (__int64)ptr);
                sub_1400F27F0(a1, v5, v6);
                ptr += v6;
                ptr2->field_10 = ptr;
                if (v7 != 0) {
                    off_140108030();
                    off_140108038(result, 0, v5);
                }
                result = v9 + 3;
                *dst2 = result;
                sub_14002EDF0(0, 8);
                if (result != 0) {
                    a1 = (int *)v_d0;
                    dst += (__int64)(__int64)a1*4;
                    v_30 = 8;
                    v_38 = (__int64)result;
                    *result = 139;
                    v_40 = 1;
                    a1 = rsp + 48;
                    sub_1400D4F50(a1, 3, 4, dst);
                    v7 = v_30;
                    v6 = v_38;
                    ptr = (struct Struct_1_t *)v_40;
                    result = ptr2->field_0;
                    v5 = ptr2->field_10;
                    result -= v5;
                    if (ptr > result) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, v5, ptr, 1);
                        v5 = ptr2->field_10;
                    }
                    a1 = ptr2->field_8;
                    a1 += v5;
                    sub_1400F27F0(a1, v6, ptr);
                    v5 += (__int64)ptr;
                    ptr2->field_10 = v5;
                    if (v7 != 0) {
                        off_140108030();
                        off_140108038(result, 0, v6);
                        v5 = ptr2->field_10;
                    }
                    result = v9 + 4;
                    *dst2 = result;
                    if (v5 == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5) = 1;
                    result = v5 + 1;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 1) = 200;
                    result = v5 + 2;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 2) = 49;
                    result = v5 + 3;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 3) = 195;
                    result = v5 + 4;
                    ptr2->field_10 = result;
                    a1 = v9 + 6;
                    *dst2 = a1;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 4) = 193;
                    result = v5 + 5;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 5) = 195;
                    result = v5 + 6;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 6) = 16;
                    result = v5 + 7;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 7) = 1;
                    result = v5 + 8;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 8) = 218;
                    result = v5 + 9;
                    ptr2->field_10 = result;
                    a1 = v9 + 8;
                    *dst2 = a1;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 9) = 49;
                    result = v5 + 10;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 10) = 209;
                    result = v5 + 11;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 11) = 193;
                    result = v5 + 12;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 12) = 193;
                    result = v5 + 13;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 13) = 12;
                    result = v5 + 14;
                    ptr2->field_10 = result;
                    a1 = v9 + 10;
                    *dst2 = a1;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 14) = 1;
                    result = v5 + 15;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 15) = 200;
                    result = v5 + 16;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 16) = 49;
                    result = v5 + 17;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 17) = 195;
                    result = v5 + 18;
                    ptr2->field_10 = result;
                    a1 = v9 + 12;
                    *dst2 = a1;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 18) = 193;
                    result = v5 + 19;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 19) = 195;
                    result = v5 + 20;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 20) = 8;
                    result = v5 + 21;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 21) = 1;
                    result = v5 + 22;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 22) = 218;
                    result = v5 + 23;
                    ptr2->field_10 = result;
                    a1 = v9 + 14;
                    *dst2 = a1;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 23) = 49;
                    result = v5 + 24;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 24) = 209;
                    result = v5 + 25;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 25) = 193;
                    result = v5 + 26;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 26) = 193;
                    result = v5 + 27;
                    ptr2->field_10 = result;
                    if (result == ptr2->field_0) {
                        sub_1400F3510(ptr2);
                    }
                    result = ptr2->field_8;
                    *(result + v5 + 27) = 7;
                    v5 += 28;
                    ptr2->field_10 = v5;
                    result = v9 + 16;
                    *dst2 = result;
                    sub_14002EDF0(0, 8);
                    if (result != 0) {
                        v_30 = 8;
                        v_38 = (__int64)result;
                        *result = 137;
                        v_40 = 1;
                        a1 = rsp + 48;
                        a4 = (int *)v_54;
                        sub_1400D4F50(a1, 0, 4, a4);
                        v7 = v_30;
                        ptr = (struct Struct_1_t *)v_38;
                        v5 = v_40;
                        result = ptr2->field_0;
                        v6 = ptr2->field_10;
                        result -= v6;
                        if (v5 > result) {
                            v_20 = 1;
                            sub_1400F2D20(ptr2, v6, v5, 1);
                            v6 = ptr2->field_10;
                        }
                        a1 = ptr2->field_8;
                        a1 += v6;
                        sub_1400F27F0(a1, ptr, v5);
                        v6 += v5;
                        ptr2->field_10 = v6;
                        if (v7 != 0) {
                            off_140108030();
                            off_140108038(result, 0, ptr);
                        }
                        sub_14002EDF0(0, 8);
                        if (result != 0) {
                            v_30 = 8;
                            v_38 = (__int64)result;
                            *result = 137;
                            v_40 = 1;
                            a1 = rsp + 48;
                            a4 = (int *)v_50;
                            sub_1400D4F50(a1, 1, 4, a4);
                            v7 = v_30;
                            ptr = (struct Struct_1_t *)v_38;
                            v5 = v_40;
                            result = ptr2->field_0;
                            v6 = ptr2->field_10;
                            result -= v6;
                            if (v5 > result) {
                                v_20 = 1;
                                sub_1400F2D20(ptr2, v6, v5, 1);
                                v6 = ptr2->field_10;
                            }
                            a1 = ptr2->field_8;
                            a1 += v6;
                            sub_1400F27F0(a1, ptr, v5);
                            v6 += v5;
                            ptr2->field_10 = v6;
                            if (v7 != 0) {
                                off_140108030();
                                off_140108038(result, 0, ptr);
                            }
                            result = v9 + 18;
                            *dst2 = result;
                            sub_14002EDF0(0, 8);
                            if (result != 0) {
                                v_30 = 8;
                                v_38 = (__int64)result;
                                *result = 137;
                                v_40 = 1;
                                a1 = rsp + 48;
                                a4 = (int *)v_4c;
                                sub_1400D4F50(a1, 2, 4, a4);
                                v6 = v_30;
                                ptr = (struct Struct_1_t *)v_38;
                                v7 = v_40;
                                result = ptr2->field_0;
                                v5 = ptr2->field_10;
                                result -= v5;
                                if (v7 > result) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, v5, v7, 1);
                                    v5 = ptr2->field_10;
                                }
                                a1 = ptr2->field_8;
                                a1 += v5;
                                sub_1400F27F0(a1, ptr, v7);
                                v5 += v7;
                                ptr2->field_10 = v5;
                                if (v6 != 0) {
                                    off_140108030();
                                    off_140108038(result, 0, ptr);
                                }
                                sub_14002EDF0(0, 8);
                                if (result != 0) {
                                    v_30 = 8;
                                    v_38 = (__int64)result;
                                    *result = 137;
                                    v_40 = 1;
                                    a1 = rsp + 48;
                                    sub_1400D4F50(a1, 3, 4, dst);
                                    v5 = v_30;
                                    ptr = (struct Struct_1_t *)v_38;
                                    v7 = v_40;
                                    result = ptr2->field_0;
                                    dst = ptr2->field_10;
                                    result = (__int64 *)((__int64)result - (__int64)dst);
                                    if (v7 > result) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr2, dst, v7, 1);
                                        dst = ptr2->field_10;
                                    }
                                    a1 = ptr2->field_8;
                                    a1 = (int *)((__int64)a1 + (__int64)dst);
                                    sub_1400F27F0(a1, ptr, v7);
                                    dst += v7;
                                    ptr2->field_10 = dst;
                                    if (v5 != 0) {
                                        off_140108030();
                                        off_140108038(result, 0, ptr);
                                    }
                                    v9 += 20;
                                    *dst2 = v9;
                                    return (__int64)result;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    sub_1400F3326(1, 8);
    dst2 = (__int64 *)a4;
    v_48 = a3;
    dst = (__int64 *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result == 0) JUMPOUT(0x1400d99b3);
    ptr = (struct Struct_1_t *)result;
    *result = 0x24648B4C;
    result = ptr2->field_0;
    a2 = ptr2->field_10;
    ptr->field_4 = 56;
    result = (__int64 *)((__int64)result - (__int64)a2);
    v_60 = (__int64)dst2;
    if (result <= 4) JUMPOUT(0x1400d8e92);
    result = ptr2->field_8;
    a1 = ptr->field_4;
    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
    a1 = ptr->field_0;
    *(__int64 *)((__int64)result + (__int64)a2) = a1;
    a2 += 5;
    ptr2->field_10 = a2;
    off_140108030(a1, a2);
    off_140108038(result, 0, ptr);
    dst2 = *dst;
    result = dst2 + 1;
    *dst = result;
    sub_14002EDF0(0, 8);
    if (result == 0) JUMPOUT(0x1400d99b3);
    ptr = (struct Struct_1_t *)result;
    *result = 0x24748B4C;
    result = ptr2->field_0;
    a2 = ptr2->field_10;
    ptr->field_4 = 64;
    result = (__int64 *)((__int64)result - (__int64)a2);
    if (result <= 4) JUMPOUT(0x1400d8eb8);
    result = ptr2->field_8;
    a1 = ptr->field_4;
    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
    a1 = ptr->field_0;
    *(__int64 *)((__int64)result + (__int64)a2) = a1;
    a2 += 5;
    ptr2->field_10 = a2;
    off_140108030(a1, a2);
    off_140108038(result, 0, ptr);
    result = dst2 + 2;
    *dst = result;
    sub_14002EDF0(0, 7);
    if (result == 0) JUMPOUT(0x1400d9b63);
    ptr = (struct Struct_1_t *)result;
    *result = 0x8148;
    arg_3 = 320;
    arg_2 = 236;
    result = ptr2->field_0;
    a2 = ptr2->field_10;
    result = (__int64 *)((__int64)result - (__int64)a2);
    if (result <= 6) JUMPOUT(0x1400d8ede);
    result = ptr2->field_8;
    a1 = ptr->field_0;
    a3 = ptr->field_3;
    *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
    *(__int64 *)((__int64)result + (__int64)a2) = a1;
    a2 += 7;
    ptr2->field_10 = a2;
    off_140108030(a1, a2, a3);
    off_140108038(result, 0, ptr);
    result = dst2 + 3;
    *dst = result;
    v7 = 536;
    v6 = rsp + 40;
    v_40 = (__int64)dst;
    return sub_1400D69D1();
}