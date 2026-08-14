// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_1400F3510();
__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400D5BD0();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400F3B80();
__int64 sub_1400D5C76();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;
extern __int64 off_14011CD40;
extern __int64 off_14011CD30;
extern __int64 off_14011D3F8;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011CCF0;
extern __int64 off_14011CCE8;
extern __int64 off_14011CD18;
extern __int64 off_14011CD08;

__int64 __fastcall sub_1400D5320(size_t *a1, int *a2, int a3, int a4) {
    __int64 rsp;
    int arg_1;
    int arg_2;
    int arg_8;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    int v_48;
    __int64 v_50;
    int v_90;
    __int64 *dst;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v2;
    __int64 *src;
    struct Struct_2_t *ptr2;
    __int64 *dst2;
    __int64 v8;
    struct Struct_3_t *ptr3;
    __int64 v5;

    dst = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    v2 = a1[2];
    if (v2 == result) {
        sub_1400F3510(ptr, a2, result);
        result = ptr->field_0;
    }
    a1 = ptr->field_8;
    *(a1 + v2) = 72;
    a2 = v2 + 1;
    ptr->field_10 = a2;
    if (a2 == result) {
        sub_1400F3510(ptr);
        result = ptr->field_0;
        a1 = ptr->field_8;
    }
    *(a1 + v2 + 1) = 49;
    a2 = v2 + 2;
    ptr->field_10 = a2;
    if (a2 == result) {
        sub_1400F3510(ptr);
        a1 = ptr->field_8;
    }
    *(a1 + v2 + 2) = 255;
    v2 += 3;
    ptr->field_10 = v2;
    src = *dst;
    result = src + 1;
    *dst = result;
    sub_14002EDF0(0, 7);
    if (result != 0) {
        ptr2 = (struct Struct_2_t *)result;
        *result = 0xFD8349;
        result = ptr->field_0;
        result -= v2;
        if (result <= 3) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr, v2, 4, 1);
                a1 = ptr->field_10;
            } while (true);
        }
        dst2 = ptr->field_8;
        result = ptr2->field_0;
        *(__int64 *)((__int64)dst2 + (__int64)a1) = result;
        v_48 = (int)a1;
        v8 = a1 + 4;
        ptr->field_10 = v8;
        off_140108030(v2);
        off_140108038(result, 0, ptr2);
        sub_14002EDF0(0, 6);
        if (result != 0) {
            ptr2 = (struct Struct_2_t *)result;
            *result = 0x840F;
            arg_2 = 0;
            result = ptr->field_0;
            result -= v8;
            if (result <= 5) {
                v_20 = 1;
                sub_1400F2D20(ptr, v8, 6, 1);
                dst2 = ptr->field_8;
                v8 = ptr->field_10;
            }
            result = ptr2->field_4;
            *(dst2 + v8 + 4) = result;
            result = ptr2->field_0;
            *(dst2 + v8) = result;
            v8 += 6;
            ptr->field_10 = v8;
            off_140108030();
            off_140108038(result, 0, ptr2);
            result = src + 3;
            *dst = result;
            sub_14002EDF0(0, 7);
            if (result != 0) {
                ptr3 = (struct Struct_3_t *)result;
                *result = 0x40FF8348;
                result = ptr->field_0;
                result -= v8;
                if (result <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr, v8, 4, 1);
                    dst2 = ptr->field_8;
                    v8 = ptr->field_10;
                }
                result = ptr3->field_0;
                *(dst2 + v8) = result;
                ptr2 = v8 + 4;
                ptr->field_10 = ptr2;
                off_140108030();
                off_140108038(result, 0, ptr3);
                sub_14002EDF0(0, 6);
                if (result != 0) {
                    ptr3 = (struct Struct_3_t *)result;
                    *result = 0x840F;
                    arg_2 = 0;
                    result = ptr->field_0;
                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                    if (result <= 5) {
                        v_20 = 1;
                        sub_1400F2D20(ptr, ptr2, 6, 1);
                        ptr2 = ptr->field_10;
                    }
                    dst2 = ptr->field_8;
                    result = ptr3->field_4;
                    *(__int64 *)((__int64)dst2 + (__int64)ptr2 + 4) = result;
                    result = ptr3->field_0;
                    *(__int64 *)((__int64)dst2 + (__int64)ptr2) = result;
                    ptr2 += 6;
                    ptr->field_10 = ptr2;
                    off_140108030();
                    off_140108038(result, 0, ptr3);
                    v_40 = (__int64)src;
                    result = src + 5;
                    v_50 = (__int64)dst;
                    *dst = result;
                    sub_14002EDF0(0, 9);
                    if (result != 0) {
                        v_28 = 9;
                        v_30 = (__int64)result;
                        *result = 0xB60F;
                        v_38 = 2;
                        v_20 = 72;
                        a1 = rsp + 40;
                        sub_1400D5BD0(a1, 0, 7, 0);
                        dst = (__int64 *)v_28;
                        ptr3 = (struct Struct_3_t *)v_30;
                        src = (__int64 *)v_38;
                        result = ptr->field_0;
                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                        if (src > result) {
                            v_20 = 1;
                            sub_1400F2D20(ptr, ptr2, src, 1);
                            dst2 = ptr->field_8;
                            ptr2 = ptr->field_10;
                        }
                        a1 = (__int64)dst2 + (__int64)ptr2;
                        sub_1400F27F0(a1, ptr3, src);
                        ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)src);
                        ptr->field_10 = ptr2;
                        if (dst == 0) {
                            src = (__int64 *)v_40;
                            result = src + 6;
                            dst = (__int64 *)v_50;
                            *dst = result;
                            sub_14002EDF0(0, 8);
                            if (result != 0) {
                                ptr3 = (struct Struct_3_t *)result;
                                *result = 0x1CB60F41;
                                result = ptr->field_0;
                                ptr3->field_4 = 36;
                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                if (result <= 4) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, ptr2, 5, 1);
                                    dst2 = ptr->field_8;
                                    ptr2 = ptr->field_10;
                                }
                                result = ptr3->field_4;
                                *(__int64 *)((__int64)dst2 + (__int64)ptr2 + 4) = result;
                                result = ptr3->field_0;
                                *(__int64 *)((__int64)dst2 + (__int64)ptr2) = result;
                                dst2 = ptr2 + 5;
                                ptr->field_10 = dst2;
                                off_140108030();
                                off_140108038(result, 0, ptr3);
                                a1 = ptr->field_0;
                                if (dst2 == a1) {
                                    sub_1400F3510(ptr);
                                    a1 = ptr->field_0;
                                }
                                result = ptr->field_8;
                                *(__int64 *)((__int64)result + (__int64)ptr2 + 5) = 49;
                                a2 = ptr2 + 6;
                                ptr->field_10 = a2;
                                if (a2 == a1) {
                                    sub_1400F3510(ptr);
                                    a1 = ptr->field_0;
                                    result = ptr->field_8;
                                }
                                *(__int64 *)((__int64)result + (__int64)ptr2 + 6) = 195;
                                ptr2 += 7;
                                ptr->field_10 = ptr2;
                                a1 = (size_t *)((__int64)a1 - (__int64)ptr2);
                                if (a1 <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, ptr2, 4, 1);
                                    result = ptr->field_8;
                                    ptr2 = ptr->field_10;
                                }
                                *(__int64 *)((__int64)result + (__int64)ptr2) = 0x241C8841;
                                ptr2 += 4;
                                ptr->field_10 = ptr2;
                                result = src + 9;
                                *dst = result;
                                sub_14002EDF0(0, 7);
                                if (result != 0) {
                                    ptr3 = (struct Struct_3_t *)result;
                                    *result = 0x1C78348;
                                    result = ptr->field_0;
                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                    if (result <= 3) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, ptr2, 4, 1);
                                        ptr2 = ptr->field_10;
                                    }
                                    dst2 = ptr->field_8;
                                    result = ptr3->field_0;
                                    *(__int64 *)((__int64)dst2 + (__int64)ptr2) = result;
                                    ptr2 += 4;
                                    ptr->field_10 = ptr2;
                                    off_140108030();
                                    off_140108038(result, 0, ptr3);
                                    sub_14002EDF0(0, 7);
                                    if (result != 0) {
                                        ptr3 = (struct Struct_3_t *)result;
                                        *result = 0x1C48349;
                                        result = ptr->field_0;
                                        result = (__int64 *)((__int64)result - (__int64)ptr2);
                                        if (result <= 3) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr, ptr2, 4, 1);
                                            dst2 = ptr->field_8;
                                            ptr2 = ptr->field_10;
                                        }
                                        result = ptr3->field_0;
                                        *(__int64 *)((__int64)dst2 + (__int64)ptr2) = result;
                                        ptr2 += 4;
                                        ptr->field_10 = ptr2;
                                        off_140108030();
                                        off_140108038(result, 0, ptr3);
                                        result = src + 11;
                                        *dst = result;
                                        sub_14002EDF0(0, 7);
                                        if (result != 0) {
                                            src = result;
                                            *result = 0x1ED8349;
                                            result = ptr->field_0;
                                            result = (__int64 *)((__int64)result - (__int64)ptr2);
                                            if (result <= 3) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr, ptr2, 4, 1);
                                                dst2 = ptr->field_8;
                                                ptr2 = ptr->field_10;
                                            }
                                            result = *src;
                                            *(__int64 *)((__int64)dst2 + (__int64)ptr2) = result;
                                            ptr3 = ptr2 + 4;
                                            ptr->field_10 = ptr3;
                                            off_140108030();
                                            off_140108038(result, 0, src);
                                            ptr2 += 9;
                                            if (!((ptr2 < 0))) {
                                                v2 -= (__int64)ptr2;
                                                result = (__int64 *)v2;
                                                src = (__int64 *)v_40;
                                                if (v2 == v2) {
                                                    sub_14002EDF0(0, 5);
                                                    if (result != 0) {
                                                        ptr2 = (struct Struct_2_t *)result;
                                                        *result = 233;
                                                        arg_1 = v2;
                                                        result = ptr->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)ptr3);
                                                        if (result <= 4) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr, ptr3, 5, 1);
                                                            ptr3 = ptr->field_10;
                                                        }
                                                        dst2 = ptr->field_8;
                                                        result = ptr2->field_4;
                                                        *(__int64 *)((__int64)dst2 + (__int64)ptr3 + 4) = result;
                                                        result = ptr2->field_0;
                                                        *(__int64 *)((__int64)dst2 + (__int64)ptr3) = result;
                                                        ptr3 += 5;
                                                        ptr->field_10 = ptr3;
                                                        off_140108030();
                                                        off_140108038(result, 0, ptr2);
                                                        src += 13;
                                                        *dst = src;
                                                        a1 = (size_t *)v_48;
                                                        a2 = (int *)a1;
                                                        a2 += 10;
                                                        if (!((a2 < 0))) {
                                                            result = (__int64 *)ptr3;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result == result) {
                                                                if (ptr3 < a2) {
                                                                    a1 += 6;
                                                                    a4 = &off_14011D380;
                                                                    sub_1400F3600(a1, a2, ptr3, a4);
                                                                    v8 += 6;
                                                                    a4 = &off_14011D380;
                                                                    sub_1400F3600(v8, a2, ptr3, a4);
                                                                }
                                                                *(__int64 *)((__int64)dst2 + (__int64)a1 + 6) = result;
                                                                a2 = (int *)v8;
                                                                a2 += 10;
                                                                if (!((a2 < 0))) {
                                                                    result = (__int64 *)ptr3;
                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                    a1 = (size_t *)result;
                                                                    if (result == result) {
                                                                        if (ptr3 < a2) {
                                                                            return (__int64)a1;
                                                                        }
                                                                        *(dst2 + v8 + 6) = result;
                                                                        return (__int64)a1;
                                                                    }
                                                                    result = &off_14011CD40;
                                                                    v_20 = (__int64)result;
                                                                    a1 = &off_14011CD30;
                                                                    a4 = &off_14011D3F8;
                                                                    a3 = rsp + 40;
                                                                    sub_1400F3B80(a1, 10, a3, a4);
                                                                    ptr = (struct Struct_1_t *)v_90;
                                                                    result = (__int64 *)ptr;
                                                                    result = (result != ptr) ? 1 : 0;
                                                                    ++result;
                                                                    src = result;
                                                                    if (ptr == 0) src = ptr;
                                                                    result = src;
                                                                    result = (__int64 *)((__int64)(__int64)result << 6);
                                                                    a2 = (int *)((__int64)(__int64)a2 << 3);
                                                                    a2 = (int *)((__int64)(__int64)a2 | (__int64)result);
                                                                    a2 = (int *)((__int64)(__int64)a2 | 4);
                                                                    v5 = *a1;
                                                                    v2 = a1[2];
                                                                    if (v2 == v5) JUMPOUT(0x1400d5c89);
                                                                    result = (__int64 *)arg_8;
                                                                    *(result + v2) = a2;
                                                                    a2 = v2 + 1;
                                                                    a1[2] = a2;
                                                                    a4 <<= 6;
                                                                    a3 <<= 3;
                                                                    a3 |= a4;
                                                                    a3 |= 4;
                                                                    if (a2 == v5) JUMPOUT(0x1400d5cae);
                                                                    *(result + v2 + 1) = a3;
                                                                    a2 = v2 + 2;
                                                                    a1[2] = a2;
                                                                    if (src == 0) JUMPOUT(0x1400d5c7a);
                                                                    a3 = (int)src;
                                                                    if (src != 1) JUMPOUT(0x1400d5c60);
                                                                    if (a2 == *a1) JUMPOUT(0x1400d5cc8);
                                                                    *(result + v2 + 2) = ptr;
                                                                    v2 += 3;
                                                                    return sub_1400D5C76();
                                                                }
                                                                result = &off_14011B3E0;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011B3C3;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 40;
                                                                sub_1400F3B80(a1, 23, a3, a4);
                                                                sub_1400F3326(1, 6);
                                                                sub_1400F3326(1, 9);
                                                                sub_1400F3326(1, 8);
                                                                result = &off_14011CCF0;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011CCE8;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 40;
                                                                sub_1400F3B80(a1, 7, a3, a4);
                                                                sub_1400F3326(1, 5);
                                                            }
                                                            result = &off_14011CD18;
                                                            v_20 = (__int64)result;
                                                            a1 = &off_14011CD08;
                                                            a4 = &off_14011D3F8;
                                                            a3 = rsp + 40;
                                                            sub_1400F3B80(a1, 10, a3, a4);
                                                            return a3;
                                                        }
                                                        return a3;
                                                    }
                                                    return a3;
                                                }
                                                return a3;
                                            }
                                            return a3;
                                        }
                                    }
                                }
                                sub_1400F3326(1, 7);
                                return a3;
                            }
                            return a3;
                        }
                        off_140108030();
                        off_140108038(result, 0, ptr3);
                        return a3;
                    }
                    return a3;
                }
                return a3;
            }
            return a3;
        }
        return a3;
    }
    return (__int64)result;
}