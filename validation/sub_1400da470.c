// inferred from 2 accesses on `i`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_1400F3B80();
__int64 sub_1400F3326();
__int64 sub_1400D4F50();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011C3D0;
extern __int64 off_14011C3B0;
extern __int64 off_14011D3F8;
extern __int64 off_14011B988;
extern __int64 off_14011B970;
extern __int64 off_14011B390;
extern __int64 off_14011B34D;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011C398;
extern __int64 off_14011C378;

__int64 __fastcall sub_1400DA470(size_t *a1, size_t *a2, size_t *a3, int *a4) {
    __int64 rsp;
    __int64 arg_1;
    __int64 arg_2;
    int arg_4;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    int v_a0;
    __int64 *dst;
    struct Struct_1_t *i;
    __int64 *dst2;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    __int64 *result;
    __int64 i2;
    struct Struct_4_t *ptr3;
    __int64 v6;

    dst = (__int64 *)a4;
    i = (struct Struct_1_t *)a3;
    dst2 = (__int64 *)a2;
    ptr = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        ptr2 = (struct Struct_3_t *)result;
        *(__int64 *)ptr2 = (__int64)(result);
        result = ptr->field_0;
        i2 = ptr->field_10;
        result -= i2;
        if (result <= 7) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 8, 1);
            i2 = ptr->field_10;
        }
        ptr3 = ptr->field_8;
        result = ptr2->field_0;
        *(__int64 *)(ptr3 + i2) = (__int64)(result);
        i2 += 8;
        ptr->field_10 = i2;
        off_140108030(0xD0249C8B4C);
        off_140108038(result, 0, ptr2);
        v6 = *dst2;
        sub_14002EDF0(0, 10);
        if (result != 0) {
            ptr2 = (struct Struct_3_t *)result;
            *result = 0xBA49;
            arg_2 = (__int64)i;
            i = ptr->field_0;
            result = (__int64 *)i;
            result -= i2;
            v_30 = (__int64)dst2;
            dst2 = dst;
            if (result <= 9) {
                v_20 = 1;
                sub_1400F2D20(ptr, i2, 10, 1);
                i2 = ptr->field_10;
                i = ptr->field_0;
                ptr3 = ptr->field_8;
            }
            dst = (__int64 *)v_a0;
            result = ptr2->field_8;
            *(__int64 *)(ptr3 + i2 + 8) = (__int64)(result);
            result = ptr2->field_0;
            *(__int64 *)(ptr3 + i2) = (__int64)(result);
            i2 += 10;
            ptr->field_10 = i2;
            off_140108030();
            off_140108038(result, 0, ptr2);
            i -= i2;
            if (i <= 2) {
                v_20 = 1;
                sub_1400F2D20(ptr, i2, 3, 1);
                ptr3 = ptr->field_8;
                i2 = ptr->field_10;
            }
            *(__int64 *)(ptr3 + i2 + 2) = (__int64)(211);
            *(__int64 *)(ptr3 + i2) = (__int64)(0x294D);
            i2 += 3;
            ptr->field_10 = i2;
            result = dst;
            result = (__int64 *)((__int64)(__int64)result >> 32);
            if (!((result != 0))) {
                if (dst <= 0x1FFFFFFF) {
                    sub_14002EDF0(0, 5);
                    if (result != 0) {
                        i = (struct Struct_1_t *)result;
                        ptr2 =  + (__int64)(__int64)dst*4;
                        *result = 233;
                        arg_1 = (__int64)ptr2;
                        dst = ptr->field_0;
                        result = dst;
                        result -= i2;
                        if (result <= 4) {
                            v_20 = 1;
                            sub_1400F2D20(ptr, i2, 5, 1);
                            dst = ptr->field_0;
                            i2 = ptr->field_10;
                        }
                        ptr3 = ptr->field_8;
                        result = i->field_4;
                        *(__int64 *)(ptr3 + i2 + 4) = (__int64)(result);
                        result = i->field_0;
                        *(__int64 *)(ptr3 + i2) = (__int64)(result);
                        i2 += 5;
                        ptr->field_10 = i2;
                        off_140108030();
                        off_140108038(result, 0, i);
                        dst -= i2;
                        i = (struct Struct_1_t *)i2;
                        if (ptr2 > dst) {
                            v_20 = 1;
                            sub_1400F2D20(ptr, i2, ptr2, 1);
                            ptr3 = ptr->field_8;
                            i = ptr->field_10;
                        }
                        a1 = (__int64)ptr3 + (__int64)i;
                        sub_1400F27F0(a1, dst2, ptr2);
                        i = (struct Struct_1_t *)((__int64)i + (__int64)ptr2);
                        ptr->field_10 = i;
                        result = v6 + 5;
                        dst = (__int64 *)v_30;
                        *dst = result;
                        result = (__int64 *)i;
                        result += 7;
                        ptr2 = (struct Struct_3_t *)v_a0;
                        if (!((result < 0))) {
                            i2 -= (__int64)result;
                            result = (__int64 *)i2;
                            if (i2 == i2) {
                                result = ptr->field_0;
                                result = (__int64 *)((__int64)result - (__int64)i);
                                if (result <= 2) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, i, 3, 1);
                                    ptr3 = ptr->field_8;
                                    i = ptr->field_10;
                                }
                                *(__int64 *)((__int64)ptr3 + (__int64)i + 2) = 53;
                                *(__int64 *)((__int64)ptr3 + (__int64)i) = 0x8D48;
                                i += 3;
                                ptr->field_10 = i;
                                a2 = ptr->field_0;
                                result = (__int64 *)a2;
                                result = (__int64 *)((__int64)result - (__int64)i);
                                if (result <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, i, 4, 1);
                                    a2 = ptr->field_0;
                                    i = ptr->field_10;
                                }
                                result = ptr->field_8;
                                *(__int64 *)((__int64)result + (__int64)i) = i2;
                                i += 4;
                                ptr->field_10 = i;
                                if (a2 == i) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, a2, 1, 1);
                                    i = ptr->field_10;
                                    a2 = ptr->field_0;
                                    result = ptr->field_8;
                                }
                                *(__int64 *)((__int64)result + (__int64)i) = 185;
                                ++i;
                                ptr->field_10 = i;
                                a2 = (size_t *)((__int64)a2 - (__int64)i);
                                if (a2 <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, i, 4, 1);
                                    result = ptr->field_8;
                                    i = ptr->field_10;
                                }
                                *(__int64 *)((__int64)result + (__int64)i) = ptr2;
                                i += 4;
                                ptr->field_10 = i;
                                result = v6 + 7;
                                *dst = result;
                                sub_14002EDF0(0, 8);
                                if (result != 0) {
                                    ptr3 = (struct Struct_4_t *)result;
                                    *(__int64 *)ptr3 = (__int64)(result);
                                    ptr2 = ptr->field_0;
                                    result = (__int64 *)ptr2;
                                    result = (__int64 *)((__int64)result - (__int64)i);
                                    if (result <= 7) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, i, 8, 1);
                                        ptr2 = ptr->field_0;
                                        i = ptr->field_10;
                                    }
                                    dst = ptr->field_8;
                                    result = ptr3->field_0;
                                    *(__int64 *)((__int64)dst + (__int64)i) = result;
                                    i2 = i + 8;
                                    ptr->field_10 = i2;
                                    off_140108030(0xD0249C8B48);
                                    off_140108038(result, 0, ptr3);
                                    result = (__int64 *)ptr2;
                                    result -= i2;
                                    a2 = (size_t *)i2;
                                    if (result <= 1) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, i2, 2, 1);
                                        a2 = ptr->field_10;
                                        ptr2 = ptr->field_0;
                                        dst = ptr->field_8;
                                    }
                                    *(__int64 *)((__int64)dst + (__int64)a2) = 0x68B;
                                    a2 += 2;
                                    ptr->field_10 = a2;
                                    ptr2 = (struct Struct_3_t *)((__int64)ptr2 - (__int64)a2);
                                    if (ptr2 <= 2) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, a2, 3, 1);
                                        dst = ptr->field_8;
                                        a2 = ptr->field_10;
                                    }
                                    *(__int64 *)((__int64)dst + (__int64)a2 + 2) = 216;
                                    *(__int64 *)((__int64)dst + (__int64)a2) = 328;
                                    a2 += 3;
                                    ptr->field_10 = a2;
                                    result = ptr->field_0;
                                    a1 = (size_t *)result;
                                    a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                    if (a1 <= 2) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, a2, 3, 1);
                                        result = ptr->field_0;
                                        a2 = ptr->field_10;
                                    }
                                    dst2 = (__int64 *)v_30;
                                    a1 = ptr->field_8;
                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 2) = 24;
                                    *(__int64 *)((__int64)a1 + (__int64)a2) = 332;
                                    a2 += 3;
                                    ptr->field_10 = a2;
                                    a3 = v6 + 11;
                                    *dst2 = a3;
                                    a3 = (size_t *)result;
                                    a3 = (size_t *)((__int64)a3 - (__int64)a2);
                                    if (a3 <= 3) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, a2, 4, 1);
                                        a2 = ptr->field_10;
                                        result = ptr->field_0;
                                        a1 = ptr->field_8;
                                    }
                                    *(__int64 *)((__int64)a1 + (__int64)a2) = 0x4C68348;
                                    a2 += 4;
                                    ptr->field_10 = a2;
                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                    if (result <= 1) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, a2, 2, 1);
                                        a1 = ptr->field_8;
                                        a2 = ptr->field_10;
                                    }
                                    *(__int64 *)((__int64)a1 + (__int64)a2) = 0xC9FF;
                                    result = a2 + 2;
                                    ptr->field_10 = result;
                                    if (i <= 0x7FFFFFF7) {
                                        if (a2 <= 0x7FFFFFFB) {
                                            i2 -= (__int64)result;
                                            i2 += 0xFFFFFFFE;
                                            a1 = (size_t *)i2;
                                            if (i2 != i2) {
                                                result = &off_14011C3D0;
                                                v_20 = (__int64)result;
                                                a1 = &off_14011C3B0;
                                                a4 = &off_14011D3F8;
                                                a3 = rsp + 47;
                                                sub_1400F3B80(a1, 28, a3, a4);
                                            } else {
                                                a1 = ptr->field_0;
                                                a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                if (a1 <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr, result, 2, 1);
                                                    result = ptr->field_10;
                                                }
                                                a1 = ptr->field_8;
                                                i2 <<= 8;
                                                i2 |= 117;
                                                *(__int64 *)((__int64)a1 + (__int64)result) = i2;
                                                result += 2;
                                                ptr->field_10 = result;
                                                v6 += 14;
                                                *dst2 = v6;
                                                return v6;
                                            }
                                            return v6;
                                        }
                                    }
                                    result = &off_14011B988;
                                    v_20 = (__int64)result;
                                    a1 = &off_14011B970;
                                    a4 = &off_14011D3F8;
                                    a3 = rsp + 47;
                                    sub_1400F3B80(a1, 23, a3, a4);
                                }
                                sub_1400F3326(1, 8);
                                sub_1400F3326(1, 10);
                                result = &off_14011B390;
                                v_20 = (__int64)result;
                                a1 = &off_14011B34D;
                                a4 = &off_14011D3F8;
                                a3 = rsp + 47;
                                sub_1400F3B80(a1, 35, a3, a4);
                                sub_1400F3326(1, 5);
                                result = &off_14011B3E0;
                                v_20 = (__int64)result;
                                a1 = &off_14011B3C3;
                                a4 = &off_14011D3F8;
                                a3 = rsp + 47;
                                sub_1400F3B80(a1, 23, a3, a4);
                            }
                            result = &off_14011C398;
                            v_20 = (__int64)result;
                            a1 = &off_14011C378;
                            a4 = &off_14011D3F8;
                            a3 = rsp + 47;
                            sub_1400F3B80(a1, 29, a3, a4);
                            dst = (__int64 *)a4;
                            i = (struct Struct_1_t *)a3;
                            ptr2 = (struct Struct_3_t *)a2;
                            ptr = (struct Struct_2_t *)a1;
                            sub_14002EDF0(0, 8);
                            if (result == 0) JUMPOUT(0x1400dae5b);
                            ptr3 = (struct Struct_4_t *)result;
                            *result = 0x244C8D48;
                            arg_4 = 32;
                            result = ptr->field_0;
                            i2 = ptr->field_10;
                            result -= i2;
                            if (result <= 4) JUMPOUT(0x1400dadb2);
                            dst2 = ptr->field_8;
                            result = ptr3->field_4;
                            *(dst2 + i2 + 4) = result;
                            result = ptr3->field_0;
                            *(dst2 + i2) = result;
                            i2 += 5;
                            ptr->field_10 = i2;
                            off_140108030();
                            off_140108038(result, 0, ptr3);
                            v6 = ptr2->field_0;
                            result = v6 + 1;
                            v_40 = (__int64)ptr2;
                            *(__int64 *)ptr2 = (__int64)(result);
                            sub_14002EDF0(0, 8);
                            if (result == 0) JUMPOUT(0x1400dae5b);
                            v_28 = 8;
                            v_30 = (__int64)result;
                            *result = 0x8D48;
                            v_38 = 2;
                            a1 = rsp + 40;
                            sub_1400D4F50(a1, 2, 4, dst);
                            dst = (__int64 *)v_28;
                            ptr3 = (struct Struct_4_t *)v_30;
                            ptr2 = (struct Struct_3_t *)v_38;
                            result = ptr->field_0;
                            result -= i2;
                            if (ptr2 > result) JUMPOUT(0x1400daddb);
                            a1 = dst2 + i2;
                            sub_1400F27F0(a1, ptr3, ptr2);
                            i2 += (__int64)ptr2;
                            ptr->field_10 = i2;
                            if (dst != 0) {
                                off_140108030();
                                off_140108038(result, 0, ptr3);
                            }
                            result = (__int64 *)i2;
                            result += 5;
                            ptr3 = (struct Struct_4_t *)v_40;
                            if ((result < 0)) JUMPOUT(0x1400dae6a);
                            i = (struct Struct_1_t *)((__int64)i - (__int64)result);
                            result = (__int64 *)i;
                            if (i != i) JUMPOUT(0x1400dae93);
                            if (ptr->field_0 == i2) JUMPOUT(0x1400dae05);
                            *(dst2 + i2) = 232;
                            ++i2;
                            ptr->field_10 = i2;
                            result = ptr->field_0;
                            result -= i2;
                            if (result <= 3) JUMPOUT(0x1400dae32);
                            result = ptr->field_8;
                            *(result + i2) = i;
                            i2 += 4;
                            ptr->field_10 = i2;
                            v6 += 3;
                            *(__int64 *)ptr3 = (__int64)(v6);
                            return v6;
                        }
                        return v6;
                    }
                    return v6;
                }
                return v6;
            }
            return v6;
        }
        return v6;
    }
    return (__int64)result;
}