// inferred from 4 accesses on `result`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int16 field_2; // offset 2
    char field_4; // offset 4
    __int64 field_5; // offset 5
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int16 field_0; // offset 0
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr4`
struct Struct_5_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `ptr5`
struct Struct_6_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr6`
struct Struct_7_t {
    __int16 field_0; // offset 0
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_1400D34C0();
__int64 sub_1400D3870();
__int64 sub_1400F3340();
__int64 sub_1400F3600();
__int64 sub_1400F3510();
__int64 sub_1400F3B80();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;
extern __int64 off_14011C688;
extern __int64 off_14011C678;
extern __int64 off_14011D3F8;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011B838;
extern __int64 off_14011B828;
extern __int64 off_14011B860;
extern __int64 off_14011B850;
extern __int64 off_14011B888;
extern __int64 off_14011B878;
extern __int64 off_14011B8B0;
extern __int64 off_14011B8A0;
extern __int64 off_14011C660;
extern __int64 off_14011C650;

__int64 __fastcall sub_1400D0A70(int *a1, int *a2, int *a3) {
    __int64 rsp;
    __int64 arg_1;
    int arg_2;
    int arg_20;
    int arg_24;
    __int64 arg_3;
    int arg_4;
    int arg_8;
    __int64 v_20;
    __int64 v_38;
    __int64 v_40;
    struct Struct_4_t *ptr3;
    struct Struct_3_t *ptr2;
    struct Struct_5_t *ptr4;
    __int64 *i;
    __int64 *dst;
    struct Struct_1_t *result;
    struct Struct_7_t *ptr6;
    struct Struct_2_t *ptr;
    struct Struct_6_t *ptr5;
    __int64 v6;
    __int64 v5;

    ptr3 = (struct Struct_4_t *)a2;
    ptr2 = (struct Struct_3_t *)a1;
    ptr4 = (struct Struct_5_t *)arg_20;
    v_38 = (__int64)a3;
    i = (__int64 *)arg_24;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        dst = (__int64 *)result;
        *dst = result;
        result = ptr2->field_0;
        ptr6 = ptr2->field_10;
        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
        if (result <= 7) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr2, ptr6, 8, 1);
                ptr6 = ptr2->field_10;
            } while (true);
        }
        ptr = ptr2->field_8;
        result = *dst;
        *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
        ptr6 += 8;
        ptr2->field_10 = ptr6;
        off_140108030(0xD024848B48);
        off_140108038(result, 0, dst);
        ptr5 = ptr3->field_0;
        sub_14002EDF0(0, 7);
        if (result != 0) {
            dst = (__int64 *)result;
            *(__int64 *)result = (__int64)(72);
            result = (struct Struct_1_t *)ptr4;
            if (ptr4 == ptr4) {
                arg_3 = (__int64)ptr4;
                ptr4 = 4;
                result = 131;
                arg_1 = (__int64)result;
                arg_2 = 192;
                result = ptr2->field_0;
                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                if (ptr4 > result) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr6, ptr4, 1);
                    ptr = ptr2->field_8;
                    ptr6 = ptr2->field_10;
                }
                a1 = (__int64)ptr + (__int64)ptr6;
                sub_1400F27F0(a1, dst, ptr4);
                ptr6 = (struct Struct_7_t *)((__int64)ptr6 + (__int64)ptr4);
                ptr2->field_10 = ptr6;
                off_140108030();
                off_140108038(result, 0, dst);
                result = ptr5 + 2;
                *(__int64 *)ptr3 = (__int64)(result);
                sub_14002EDF0(0, 8);
                if (result != 0) {
                    dst = (__int64 *)result;
                    *(__int64 *)result = (__int64)(0x24448948);
                    result->field_4 = 56;
                    v6 = ptr2->field_0;
                    result = (struct Struct_1_t *)v6;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                    if (result <= 4) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr6, 5, 1);
                        ptr6 = ptr2->field_10;
                        v6 = ptr2->field_0;
                        ptr = ptr2->field_8;
                    }
                    result = (struct Struct_1_t *)arg_4;
                    *(__int64 *)((__int64)ptr + (__int64)ptr6 + 4) = result;
                    result = *dst;
                    *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                    ptr6 += 5;
                    ptr2->field_10 = ptr6;
                    off_140108030();
                    off_140108038(result, 0, dst);
                    sub_14002EDF0(0, 12);
                    if (result != 0) {
                        dst = (__int64 *)result;
                        *(__int64 *)result = (__int64)(0x2444C748);
                        result->field_4 = 64;
                        result->field_5 = i;
                        v6 -= (__int64)ptr6;
                        if (v6 <= 8) {
                            v_20 = 1;
                            sub_1400F2D20(ptr2, ptr6, 9, 1);
                            ptr6 = ptr2->field_10;
                        }
                        i = (__int64 *)v_38;
                        result = ptr2->field_8;
                        a1 = (int *)arg_8;
                        *(__int64 *)((__int64)result + (__int64)ptr6 + 8) = a1;
                        a1 = *dst;
                        *(__int64 *)((__int64)result + (__int64)ptr6) = a1;
                        ptr6 += 9;
                        ptr2->field_10 = ptr6;
                        off_140108030(a1);
                        off_140108038(result, 0, dst);
                        ptr5 += 4;
                        *(__int64 *)ptr3 = (__int64)(ptr5);
                        sub_1400D34C0(ptr2, ptr3, 4);
                        sub_14002EDF0(0, 8);
                        if (result != 0) {
                            dst = (__int64 *)result;
                            *(__int64 *)result = (__int64)(0x24448B48);
                            result->field_4 = 56;
                            result = ptr2->field_0;
                            ptr6 = ptr2->field_10;
                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                            if (result <= 4) {
                                v_20 = 1;
                                sub_1400F2D20(ptr2, ptr6, 5, 1);
                                ptr6 = ptr2->field_10;
                            }
                            ptr = ptr2->field_8;
                            result = (struct Struct_1_t *)arg_4;
                            *(__int64 *)((__int64)ptr + (__int64)ptr6 + 4) = result;
                            result = *dst;
                            *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                            ptr6 += 5;
                            ptr2->field_10 = ptr6;
                            off_140108030();
                            off_140108038(result, 0, dst);
                            ptr5 = ptr3->field_0;
                            sub_14002EDF0(0, 7);
                            if (result != 0) {
                                dst = (__int64 *)result;
                                *(__int64 *)result = (__int64)(0x8C08348);
                                result = ptr2->field_0;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                                if (result <= 3) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, ptr6, 4, 1);
                                    ptr = ptr2->field_8;
                                    ptr6 = ptr2->field_10;
                                }
                                result = *dst;
                                *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                                ptr6 += 4;
                                ptr2->field_10 = ptr6;
                                off_140108030();
                                off_140108038(result, 0, dst);
                                result = ptr5 + 2;
                                *(__int64 *)ptr3 = (__int64)(result);
                                sub_14002EDF0(0, 8);
                                if (result != 0) {
                                    dst = (__int64 *)result;
                                    *(__int64 *)result = (__int64)(0x24448948);
                                    result->field_4 = 56;
                                    result = ptr2->field_0;
                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                                    if (result <= 4) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr2, ptr6, 5, 1);
                                        ptr = ptr2->field_8;
                                        ptr6 = ptr2->field_10;
                                    }
                                    result = (struct Struct_1_t *)arg_4;
                                    *(__int64 *)((__int64)ptr + (__int64)ptr6 + 4) = result;
                                    result = *dst;
                                    *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                                    ptr6 += 5;
                                    ptr2->field_10 = ptr6;
                                    off_140108030();
                                    off_140108038(result, 0, dst);
                                    sub_14002EDF0(0, 8);
                                    if (result != 0) {
                                        dst = (__int64 *)result;
                                        *(__int64 *)result = (__int64)(0x24448B48);
                                        result->field_4 = 64;
                                        result = ptr2->field_0;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                                        if (result <= 4) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr2, ptr6, 5, 1);
                                            ptr6 = ptr2->field_10;
                                        }
                                        ptr = ptr2->field_8;
                                        result = (struct Struct_1_t *)arg_4;
                                        *(__int64 *)((__int64)ptr + (__int64)ptr6 + 4) = result;
                                        result = *dst;
                                        *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                                        ptr6 += 5;
                                        ptr2->field_10 = ptr6;
                                        off_140108030();
                                        off_140108038(result, 0, dst);
                                        result = ptr5 + 4;
                                        *(__int64 *)ptr3 = (__int64)(result);
                                        sub_14002EDF0(0, 7);
                                        if (result != 0) {
                                            dst = (__int64 *)result;
                                            *(__int64 *)result = (__int64)(0x8E88348);
                                            result = ptr2->field_0;
                                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                                            if (result <= 3) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr2, ptr6, 4, 1);
                                                ptr = ptr2->field_8;
                                                ptr6 = ptr2->field_10;
                                            }
                                            result = *dst;
                                            *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                                            ptr6 += 4;
                                            ptr2->field_10 = ptr6;
                                            off_140108030();
                                            off_140108038(result, 0, dst);
                                            sub_14002EDF0(0, 8);
                                            if (result != 0) {
                                                ptr4 = (struct Struct_5_t *)result;
                                                dst = i + 40;
                                                *(__int64 *)result = (__int64)(0x24448948);
                                                result->field_4 = 64;
                                                result = ptr2->field_0;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr6);
                                                if (result <= 4) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, ptr6, 5, 1);
                                                    ptr = ptr2->field_8;
                                                    ptr6 = ptr2->field_10;
                                                }
                                                result = ptr4->field_4;
                                                *(__int64 *)((__int64)ptr + (__int64)ptr6 + 4) = result;
                                                result = ptr4->field_0;
                                                *(__int64 *)((__int64)ptr + (__int64)ptr6) = result;
                                                ptr6 += 5;
                                                ptr2->field_10 = ptr6;
                                                off_140108030();
                                                off_140108038(result, 0, ptr4);
                                                ptr5 += 6;
                                                *(__int64 *)ptr3 = (__int64)(ptr5);
                                                sub_1400D3870(ptr2, ptr3, i, dst);
                                                sub_14002EDF0(0, 8);
                                                if (result != 0) {
                                                    ptr = (struct Struct_2_t *)result;
                                                    *(__int64 *)result = (__int64)(0x245C8B48);
                                                    result = ptr2->field_0;
                                                    a2 = ptr2->field_10;
                                                    ptr->field_4 = 56;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                    if (result <= 4) {
                                                        v_20 = 1;
                                                        sub_1400F2D20(ptr2, a2, 5, 1);
                                                        a2 = ptr2->field_10;
                                                    }
                                                    result = ptr2->field_8;
                                                    a1 = ptr->field_4;
                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                    a1 = ptr->field_0;
                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                    a2 += 5;
                                                    ptr2->field_10 = a2;
                                                    off_140108030(a1, a2);
                                                    off_140108038(result, 0, ptr);
                                                    ptr6 = ptr3->field_0;
                                                    result = ptr6 + 1;
                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                    sub_14002EDF0(0, 8);
                                                    if (result != 0) {
                                                        ptr = (struct Struct_2_t *)result;
                                                        *(__int64 *)result = (__int64)(0x24448B48);
                                                        result = ptr2->field_0;
                                                        a2 = ptr2->field_10;
                                                        ptr->field_4 = 64;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                        if (result <= 4) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 5, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        a1 = ptr->field_4;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                        a1 = ptr->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 5;
                                                        ptr2->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr);
                                                        result = ptr6 + 2;
                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                        sub_14002EDF0(0, 3);
                                                        if (result == 0) {
                                                            sub_1400F3340(1, 3);
                                                            ptr5 += 5;
                                                            v5 = &off_14011D380;
                                                            sub_1400F3600(ptr5, a2, a3, v5);
                                                            ++i;
                                                            v5 = &off_14011D380;
                                                            sub_1400F3600(i, a2, a3, v5);
                                                            dst += 5;
                                                            v5 = &off_14011D380;
                                                            sub_1400F3600(dst, a2, a3, v5);
                                                            ptr4 += 5;
                                                            v5 = &off_14011D380;
                                                            sub_1400F3600(ptr4, a2, a3, v5);
                                                        }
                                                        ptr = (struct Struct_2_t *)result;
                                                        *(__int64 *)result = (__int64)(0x8948);
                                                        result->field_2 = 222;
                                                        result = ptr2->field_0;
                                                        a2 = ptr2->field_10;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                        if (result <= 2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        a1 = ptr->field_2;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                        a1 = ptr->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 3;
                                                        ptr2->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr);
                                                        ptr = ptr2->field_10;
                                                        if (ptr == ptr2->field_0) {
                                                            sub_1400F3510(ptr2, a2, a3);
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)ptr) = 72;
                                                        result = ptr + 1;
                                                        ptr2->field_10 = result;
                                                        if (result == ptr2->field_0) {
                                                            sub_1400F3510(ptr2);
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)ptr + 1) = 1;
                                                        result = ptr + 2;
                                                        ptr2->field_10 = result;
                                                        if (result == ptr2->field_0) {
                                                            sub_1400F3510(ptr2);
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 198;
                                                        ptr += 3;
                                                        ptr2->field_10 = ptr;
                                                        result = ptr6 + 4;
                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                        sub_14002EDF0(0, 8);
                                                        if (result != 0) {
                                                            ptr = (struct Struct_2_t *)result;
                                                            *(__int64 *)result = (__int64)(0x24B48B4C);
                                                            result = ptr2->field_0;
                                                            a2 = ptr2->field_10;
                                                            ptr->field_4 = 208;
                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                            if (result <= 7) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 8, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            result = ptr2->field_8;
                                                            a1 = ptr->field_0;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                            a2 += 8;
                                                            ptr2->field_10 = a2;
                                                            off_140108030(a1, a2);
                                                            off_140108038(result, 0, ptr);
                                                            result = ptr6 + 5;
                                                            *(__int64 *)ptr3 = (__int64)(result);
                                                            sub_14002EDF0(0, 8);
                                                            if (result != 0) {
                                                                ptr = (struct Struct_2_t *)result;
                                                                *(__int64 *)result = (__int64)(0x8B44);
                                                                result->field_2 = 43;
                                                                result = ptr2->field_0;
                                                                a2 = ptr2->field_10;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                if (result <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                    a2 = ptr2->field_10;
                                                                }
                                                                result = ptr2->field_8;
                                                                a1 = ptr->field_2;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                a1 = ptr->field_0;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                a2 += 3;
                                                                ptr2->field_10 = a2;
                                                                off_140108030(a1, a2);
                                                                off_140108038(result, 0, ptr);
                                                                result = ptr6 + 6;
                                                                *(__int64 *)ptr3 = (__int64)(result);
                                                                sub_14002EDF0(0, 7);
                                                                if (result != 0) {
                                                                    ptr = (struct Struct_2_t *)result;
                                                                    *(__int64 *)result = (__int64)(0x4C38348);
                                                                    result = ptr2->field_0;
                                                                    a2 = ptr2->field_10;
                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                    if (result <= 3) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr2, a2, 4, 1);
                                                                        a2 = ptr2->field_10;
                                                                    }
                                                                    result = ptr2->field_8;
                                                                    a1 = ptr->field_0;
                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                    a2 += 4;
                                                                    ptr2->field_10 = a2;
                                                                    off_140108030(a1, a2);
                                                                    off_140108038(result, 0, ptr);
                                                                    result = ptr2->field_0;
                                                                    ptr = ptr2->field_10;
                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                    ptr5 = (struct Struct_6_t *)ptr;
                                                                    if (result <= 2) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr2, ptr, 3, 1);
                                                                        ptr5 = ptr2->field_10;
                                                                    }
                                                                    result = ptr2->field_8;
                                                                    *(__int64 *)((__int64)result + (__int64)ptr5 + 2) = 237;
                                                                    *(__int64 *)((__int64)result + (__int64)ptr5) = 0x854D;
                                                                    a2 = ptr5 + 3;
                                                                    ptr2->field_10 = a2;
                                                                    result = ptr2->field_0;
                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                    v_38 = (__int64)ptr;
                                                                    if (result <= 5) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr2, a2, 6, 1);
                                                                        a2 = ptr2->field_10;
                                                                    }
                                                                    result = ptr2->field_8;
                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 0x840F;
                                                                    a2 += 6;
                                                                    ptr2->field_10 = a2;
                                                                    result = ptr6 + 9;
                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                    sub_14002EDF0(0, 8);
                                                                    if (result != 0) {
                                                                        ptr = (struct Struct_2_t *)result;
                                                                        *(__int64 *)result = (__int64)(0x3B70F48);
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                        if (result <= 3) {
                                                                            v_20 = 1;
                                                                            sub_1400F2D20(ptr2, a2, 4, 1);
                                                                            a2 = ptr2->field_10;
                                                                        }
                                                                        result = ptr2->field_8;
                                                                        a1 = ptr->field_0;
                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                        a2 += 4;
                                                                        ptr2->field_10 = a2;
                                                                        off_140108030(a1, a2);
                                                                        off_140108038(result, 0, ptr);
                                                                        result = ptr6 + 10;
                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                        sub_14002EDF0(0, 7);
                                                                        if (result != 0) {
                                                                            ptr = (struct Struct_2_t *)result;
                                                                            *(__int64 *)result = (__int64)(0x2C38348);
                                                                            result = ptr2->field_0;
                                                                            a2 = ptr2->field_10;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                a2 = ptr2->field_10;
                                                                            }
                                                                            result = ptr2->field_8;
                                                                            a1 = ptr->field_0;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                            a2 += 4;
                                                                            ptr2->field_10 = a2;
                                                                            off_140108030(a1, a2);
                                                                            off_140108038(result, 0, ptr);
                                                                            result = ptr6 + 11;
                                                                            *(__int64 *)ptr3 = (__int64)(result);
                                                                            sub_14002EDF0(0, 8);
                                                                            if (result != 0) {
                                                                                dst = (__int64 *)result;
                                                                                *(__int64 *)result = (__int64)(0x24448948);
                                                                                result = ptr2->field_0;
                                                                                a2 = ptr2->field_10;
                                                                                arg_4 = 48;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                if (result <= 4) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                a1 = (int *)arg_4;
                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                a1 = *dst;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 5;
                                                                                ptr2->field_10 = a2;
                                                                                off_140108030(a1, a2);
                                                                                off_140108038(result, 0, dst);
                                                                                result = ptr6 + 12;
                                                                                *(__int64 *)ptr3 = (__int64)(result);
                                                                                sub_14002EDF0(0, 3);
                                                                                if (result == 0) {
                                                                                    return (__int64)result;
                                                                                }
                                                                                dst = (__int64 *)result;
                                                                                *(__int64 *)result = (__int64)(0x8948);
                                                                                result->field_2 = 217;
                                                                                result = ptr2->field_0;
                                                                                a2 = ptr2->field_10;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                if (result <= 2) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                a1 = (int *)arg_2;
                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                a1 = *dst;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 3;
                                                                                ptr2->field_10 = a2;
                                                                                off_140108030(a1, a2);
                                                                                off_140108038(result, 0, dst);
                                                                                result = ptr2->field_0;
                                                                                a2 = ptr2->field_10;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                if (result <= 2) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 210;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                                                                                a2 += 3;
                                                                                ptr2->field_10 = a2;
                                                                                result = ptr2->field_0;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                if (result <= 5) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 6, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x1000B841;
                                                                                a2 += 6;
                                                                                ptr2->field_10 = a2;
                                                                                result = ptr6 + 15;
                                                                                *(__int64 *)ptr3 = (__int64)(result);
                                                                                sub_14002EDF0(0, 8);
                                                                                if (result != 0) {
                                                                                    dst = (__int64 *)result;
                                                                                    *(__int64 *)result = (__int64)(0x24448B48);
                                                                                    result = ptr2->field_0;
                                                                                    a2 = ptr2->field_10;
                                                                                    arg_4 = 40;
                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                    if (result <= 4) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                        a2 = ptr2->field_10;
                                                                                    }
                                                                                    result = ptr2->field_8;
                                                                                    a1 = (int *)arg_4;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                    a1 = *dst;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                    a2 += 5;
                                                                                    ptr2->field_10 = a2;
                                                                                    off_140108030(a1, a2);
                                                                                    off_140108038(result, 0, dst);
                                                                                    result = ptr6 + 16;
                                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                                    sub_14002EDF0(0, 3);
                                                                                    if (result != 0) {
                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                        *(__int64 *)result = (__int64)(0xD0FF);
                                                                                        result = ptr2->field_0;
                                                                                        a2 = ptr2->field_10;
                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 1) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(ptr2, a2, 2, 1);
                                                                                            a2 = ptr2->field_10;
                                                                                        }
                                                                                        result = ptr2->field_8;
                                                                                        a1 = ptr->field_0;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                        a2 += 2;
                                                                                        ptr2->field_10 = a2;
                                                                                        off_140108030(a1, a2);
                                                                                        off_140108038(result, 0, ptr);
                                                                                        result = ptr6 + 17;
                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                        sub_14002EDF0(0, 3);
                                                                                        if (result == 0) {
                                                                                            return (__int64)result;
                                                                                        }
                                                                                        dst = (__int64 *)result;
                                                                                        *(__int64 *)result = (__int64)(0x8949);
                                                                                        result->field_2 = 199;
                                                                                        result = ptr2->field_0;
                                                                                        a2 = ptr2->field_10;
                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                            a2 = ptr2->field_10;
                                                                                        }
                                                                                        result = ptr2->field_8;
                                                                                        a1 = (int *)arg_2;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                        a1 = *dst;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                        a2 += 3;
                                                                                        ptr2->field_10 = a2;
                                                                                        off_140108030(a1, a2);
                                                                                        off_140108038(result, 0, dst);
                                                                                        result = ptr6 + 18;
                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                        sub_14002EDF0(0, 8);
                                                                                        if (result != 0) {
                                                                                            dst = (__int64 *)result;
                                                                                            *(__int64 *)result = (__int64)(0x24448B48);
                                                                                            result = ptr2->field_0;
                                                                                            a2 = ptr2->field_10;
                                                                                            arg_4 = 48;
                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                            if (result <= 4) {
                                                                                                v_20 = 1;
                                                                                                sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                a2 = ptr2->field_10;
                                                                                            }
                                                                                            result = ptr2->field_8;
                                                                                            a1 = (int *)arg_4;
                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                            a1 = *dst;
                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                            a2 += 5;
                                                                                            ptr2->field_10 = a2;
                                                                                            off_140108030(a1, a2);
                                                                                            off_140108038(result, 0, dst);
                                                                                            ptr = ptr2->field_10;
                                                                                            if (ptr == ptr2->field_0) {
                                                                                                sub_1400F3510(ptr2);
                                                                                            }
                                                                                            result = ptr2->field_8;
                                                                                            *(__int64 *)((__int64)result + (__int64)ptr) = 72;
                                                                                            result = ptr + 1;
                                                                                            ptr2->field_10 = result;
                                                                                            if (result == ptr2->field_0) {
                                                                                                sub_1400F3510(ptr2);
                                                                                            }
                                                                                            result = ptr2->field_8;
                                                                                            *(__int64 *)((__int64)result + (__int64)ptr + 1) = 1;
                                                                                            result = ptr + 2;
                                                                                            ptr2->field_10 = result;
                                                                                            if (result == ptr2->field_0) {
                                                                                                sub_1400F3510(ptr2);
                                                                                            }
                                                                                            result = ptr2->field_8;
                                                                                            *(__int64 *)((__int64)result + (__int64)ptr + 2) = 195;
                                                                                            ptr += 3;
                                                                                            ptr2->field_10 = ptr;
                                                                                            result = ptr6 + 20;
                                                                                            *(__int64 *)ptr3 = (__int64)(result);
                                                                                            sub_14002EDF0(0, 8);
                                                                                            if (result != 0) {
                                                                                                dst = (__int64 *)result;
                                                                                                *(__int64 *)result = (__int64)(0x8B44);
                                                                                                result->field_2 = 35;
                                                                                                result = ptr2->field_0;
                                                                                                a2 = ptr2->field_10;
                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                if (result <= 2) {
                                                                                                    v_20 = 1;
                                                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                                    a2 = ptr2->field_10;
                                                                                                }
                                                                                                result = ptr2->field_8;
                                                                                                a1 = (int *)arg_2;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                                a1 = *dst;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                a2 += 3;
                                                                                                ptr2->field_10 = a2;
                                                                                                off_140108030(a1, a2);
                                                                                                off_140108038(result, 0, dst);
                                                                                                result = ptr6 + 21;
                                                                                                *(__int64 *)ptr3 = (__int64)(result);
                                                                                                sub_14002EDF0(0, 7);
                                                                                                if (result != 0) {
                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                    *(__int64 *)result = (__int64)(0x4C38348);
                                                                                                    result = ptr2->field_0;
                                                                                                    a2 = ptr2->field_10;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                    if (result <= 3) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                                        a2 = ptr2->field_10;
                                                                                                    }
                                                                                                    result = ptr2->field_8;
                                                                                                    a1 = ptr->field_0;
                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                    a2 += 4;
                                                                                                    ptr2->field_10 = a2;
                                                                                                    off_140108030(a1, a2);
                                                                                                    off_140108038(result, 0, ptr);
                                                                                                    result = ptr2->field_0;
                                                                                                    ptr4 = ptr2->field_10;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr4);
                                                                                                    dst = (__int64 *)ptr4;
                                                                                                    if (result <= 2) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr2, ptr4, 3, 1);
                                                                                                        dst = ptr2->field_10;
                                                                                                    }
                                                                                                    result = ptr2->field_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)dst + 2) = 228;
                                                                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x854D;
                                                                                                    a2 = dst + 3;
                                                                                                    ptr2->field_10 = a2;
                                                                                                    result = ptr2->field_0;
                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                    if (result <= 5) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr2, a2, 6, 1);
                                                                                                        a2 = ptr2->field_10;
                                                                                                    }
                                                                                                    result = ptr2->field_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = 0x840F;
                                                                                                    a2 += 6;
                                                                                                    ptr2->field_10 = a2;
                                                                                                    result = ptr6 + 24;
                                                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                                                    sub_14002EDF0(0, 8);
                                                                                                    if (result != 0) {
                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                        *(__int64 *)result = (__int64)(0x3B8B);
                                                                                                        result = ptr2->field_0;
                                                                                                        a2 = ptr2->field_10;
                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                        v_40 = (__int64)ptr5;
                                                                                                        if (result <= 1) {
                                                                                                            v_20 = 1;
                                                                                                            sub_1400F2D20(ptr2, a2, 2, 1);
                                                                                                            a2 = ptr2->field_10;
                                                                                                        }
                                                                                                        result = ptr2->field_8;
                                                                                                        a1 = ptr->field_0;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                        a2 += 2;
                                                                                                        ptr2->field_10 = a2;
                                                                                                        off_140108030(a1, a2);
                                                                                                        off_140108038(result, 0, ptr);
                                                                                                        result = ptr6 + 25;
                                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                                        sub_14002EDF0(0, 8);
                                                                                                        if (result != 0) {
                                                                                                            ptr5 = (struct Struct_6_t *)result;
                                                                                                            *(__int64 *)result = (__int64)(0x6BB70F48);
                                                                                                            result = ptr2->field_0;
                                                                                                            a2 = ptr2->field_10;
                                                                                                            ptr5->field_4 = 4;
                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                            if (result <= 4) {
                                                                                                                v_20 = 1;
                                                                                                                sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                a2 = ptr2->field_10;
                                                                                                            }
                                                                                                            result = ptr2->field_8;
                                                                                                            a1 = ptr5->field_4;
                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                            a1 = ptr5->field_0;
                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                            a2 += 5;
                                                                                                            ptr2->field_10 = a2;
                                                                                                            off_140108030(a1, a2);
                                                                                                            off_140108038(result, 0, ptr5);
                                                                                                            result = ptr6 + 26;
                                                                                                            *(__int64 *)ptr3 = (__int64)(result);
                                                                                                            sub_14002EDF0(0, 8);
                                                                                                            if (result != 0) {
                                                                                                                ptr5 = (struct Struct_6_t *)result;
                                                                                                                *(__int64 *)result = (__int64)(0x4BB70F48);
                                                                                                                result = ptr2->field_0;
                                                                                                                a2 = ptr2->field_10;
                                                                                                                ptr5->field_4 = 6;
                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                if (result <= 4) {
                                                                                                                    v_20 = 1;
                                                                                                                    sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                    a2 = ptr2->field_10;
                                                                                                                }
                                                                                                                result = ptr2->field_8;
                                                                                                                a1 = ptr5->field_4;
                                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                a1 = ptr5->field_0;
                                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                a2 += 5;
                                                                                                                ptr2->field_10 = a2;
                                                                                                                off_140108030(a1, a2);
                                                                                                                off_140108038(result, 0, ptr5);
                                                                                                                result = ptr6 + 27;
                                                                                                                *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                sub_14002EDF0(0, 7);
                                                                                                                if (result != 0) {
                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                    *(__int64 *)result = (__int64)(0x8C38348);
                                                                                                                    result = ptr2->field_0;
                                                                                                                    a2 = ptr2->field_10;
                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                    if (result <= 3) {
                                                                                                                        v_20 = 1;
                                                                                                                        sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                                                        a2 = ptr2->field_10;
                                                                                                                    }
                                                                                                                    result = ptr2->field_8;
                                                                                                                    a1 = ptr->field_0;
                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                    a2 += 4;
                                                                                                                    ptr2->field_10 = a2;
                                                                                                                    off_140108030(a1, a2);
                                                                                                                    off_140108038(result, 0, ptr);
                                                                                                                    result = ptr6 + 28;
                                                                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                    if (result != 0) {
                                                                                                                        ptr5 = (struct Struct_6_t *)result;
                                                                                                                        *(__int64 *)result = (__int64)(0x244C8948);
                                                                                                                        result = ptr2->field_0;
                                                                                                                        a2 = ptr2->field_10;
                                                                                                                        ptr5->field_4 = 48;
                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                        if (result <= 4) {
                                                                                                                            v_20 = 1;
                                                                                                                            sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                            a2 = ptr2->field_10;
                                                                                                                        }
                                                                                                                        result = ptr2->field_8;
                                                                                                                        a1 = ptr5->field_4;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                        a1 = ptr5->field_0;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                        a2 += 5;
                                                                                                                        ptr2->field_10 = a2;
                                                                                                                        off_140108030(a1, a2);
                                                                                                                        off_140108038(result, 0, ptr5);
                                                                                                                        result = ptr2->field_0;
                                                                                                                        ptr5 = ptr2->field_10;
                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr5);
                                                                                                                        if (result <= 2) {
                                                                                                                            v_20 = 1;
                                                                                                                            sub_1400F2D20(ptr2, ptr5, 3, 1);
                                                                                                                            ptr5 = ptr2->field_10;
                                                                                                                        }
                                                                                                                        result = ptr2->field_8;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr5 + 2) = 237;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr5) = 0x8548;
                                                                                                                        a2 = ptr5 + 3;
                                                                                                                        ptr2->field_10 = a2;
                                                                                                                        result = ptr2->field_0;
                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                        if (result <= 5) {
                                                                                                                            v_20 = 1;
                                                                                                                            sub_1400F2D20(ptr2, a2, 6, 1);
                                                                                                                            a2 = ptr2->field_10;
                                                                                                                        }
                                                                                                                        result = ptr2->field_8;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x840F;
                                                                                                                        a2 += 6;
                                                                                                                        ptr2->field_10 = a2;
                                                                                                                        result = ptr6 + 31;
                                                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                        sub_14002EDF0(0, 3);
                                                                                                                        if (result == 0) {
                                                                                                                            return (__int64)result;
                                                                                                                        }
                                                                                                                        i = (__int64 *)result;
                                                                                                                        *(__int64 *)result = (__int64)(0x8948);
                                                                                                                        result->field_2 = 234;
                                                                                                                        result = ptr2->field_0;
                                                                                                                        a2 = ptr2->field_10;
                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                        if (result <= 2) {
                                                                                                                            v_20 = 1;
                                                                                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                                                            a2 = ptr2->field_10;
                                                                                                                        }
                                                                                                                        result = ptr2->field_8;
                                                                                                                        a1 = (int *)arg_2;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                                                        a1 = *i;
                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                        a2 += 3;
                                                                                                                        ptr2->field_10 = a2;
                                                                                                                        off_140108030(a1, a2);
                                                                                                                        off_140108038(result, 0, i);
                                                                                                                        result = ptr6 + 32;
                                                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                        i = ptr2->field_10;
                                                                                                                        sub_14002EDF0(0, 5);
                                                                                                                        if (result != 0) {
                                                                                                                            ptr = (struct Struct_2_t *)result;
                                                                                                                            *(__int64 *)result = (__int64)(233);
                                                                                                                            result->field_1 = 0;
                                                                                                                            result = ptr2->field_0;
                                                                                                                            a2 = ptr2->field_10;
                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                            if (result <= 4) {
                                                                                                                                v_20 = 1;
                                                                                                                                sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                                a2 = ptr2->field_10;
                                                                                                                            }
                                                                                                                            result = ptr2->field_8;
                                                                                                                            a1 = ptr->field_4;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                            a1 = ptr->field_0;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                            a2 += 5;
                                                                                                                            ptr2->field_10 = a2;
                                                                                                                            off_140108030(a1, a2);
                                                                                                                            off_140108038(result, 0, ptr);
                                                                                                                            a2 = (int *)ptr5;
                                                                                                                            a2 += 9;
                                                                                                                            if (!((a2 < 0))) {
                                                                                                                                a3 = ptr2->field_10;
                                                                                                                                result = (struct Struct_1_t *)a3;
                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                a1 = (int *)result;
                                                                                                                                if (result == result) {
                                                                                                                                    if (a3 < a2) {
                                                                                                                                        return (__int64)a1;
                                                                                                                                    }
                                                                                                                                    a1 = ptr2->field_8;
                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)ptr5 + 5) = result;
                                                                                                                                    sub_14002EDF0(0, 3, a3);
                                                                                                                                    if (result == 0) {
                                                                                                                                        return (__int64)a1;
                                                                                                                                    }
                                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                                    *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                    result->field_2 = 218;
                                                                                                                                    result = ptr2->field_0;
                                                                                                                                    a2 = ptr2->field_10;
                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                    if (result <= 2) {
                                                                                                                                        v_20 = 1;
                                                                                                                                        sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                                                                        a2 = ptr2->field_10;
                                                                                                                                    }
                                                                                                                                    result = ptr2->field_8;
                                                                                                                                    a1 = ptr->field_2;
                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                                                                    a1 = ptr->field_0;
                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                    a2 += 3;
                                                                                                                                    ptr2->field_10 = a2;
                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                    off_140108038(result, 0, ptr);
                                                                                                                                    result = ptr6 + 34;
                                                                                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                                    a2 = (int *)i;
                                                                                                                                    a2 += 5;
                                                                                                                                    if (!((a2 < 0))) {
                                                                                                                                        a3 = ptr2->field_10;
                                                                                                                                        result = (struct Struct_1_t *)a3;
                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                        a1 = (int *)result;
                                                                                                                                        if (result == result) {
                                                                                                                                            if (a3 < a2) {
                                                                                                                                                return (__int64)a1;
                                                                                                                                            }
                                                                                                                                            a1 = ptr2->field_8;
                                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)i + 1) = result;
                                                                                                                                            sub_14002EDF0(0, 3, a3);
                                                                                                                                            if (result == 0) {
                                                                                                                                                return (__int64)a1;
                                                                                                                                            }
                                                                                                                                            ptr = (struct Struct_2_t *)result;
                                                                                                                                            *(__int64 *)result = (__int64)(0x894C);
                                                                                                                                            result->field_2 = 249;
                                                                                                                                            result = ptr2->field_0;
                                                                                                                                            a2 = ptr2->field_10;
                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                            if (result <= 2) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                                                                                a2 = ptr2->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr2->field_8;
                                                                                                                                            a1 = ptr->field_2;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                                                                            a1 = ptr->field_0;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                            a2 += 3;
                                                                                                                                            ptr2->field_10 = a2;
                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                            off_140108038(result, 0, ptr);
                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                            if (result != 0) {
                                                                                                                                                ptr = (struct Struct_2_t *)result;
                                                                                                                                                *(__int64 *)result = (__int64)(0x24848B48);
                                                                                                                                                result = ptr2->field_0;
                                                                                                                                                a2 = ptr2->field_10;
                                                                                                                                                ptr->field_4 = 200;
                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                if (result <= 7) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    sub_1400F2D20(ptr2, a2, 8, 1);
                                                                                                                                                    a2 = ptr2->field_10;
                                                                                                                                                }
                                                                                                                                                result = ptr2->field_8;
                                                                                                                                                a1 = ptr->field_0;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                a2 += 8;
                                                                                                                                                ptr2->field_10 = a2;
                                                                                                                                                off_140108030(a1, a2);
                                                                                                                                                off_140108038(result, 0, ptr);
                                                                                                                                                result = ptr6 + 36;
                                                                                                                                                *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                                                sub_14002EDF0(0, 3);
                                                                                                                                                if (result != 0) {
                                                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                                                    *(__int64 *)result = (__int64)(0xD0FF);
                                                                                                                                                    result = ptr2->field_0;
                                                                                                                                                    a2 = ptr2->field_10;
                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                    if (result <= 1) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        sub_1400F2D20(ptr2, a2, 2, 1);
                                                                                                                                                        a2 = ptr2->field_10;
                                                                                                                                                    }
                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                    a1 = ptr->field_0;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                    a2 += 2;
                                                                                                                                                    ptr2->field_10 = a2;
                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                    off_140108038(result, 0, ptr);
                                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                                    if (result == 0) {
                                                                                                                                                        return (__int64)a2;
                                                                                                                                                    }
                                                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                                                    *(__int64 *)result = (__int64)(0x894D);
                                                                                                                                                    result->field_2 = 241;
                                                                                                                                                    result = ptr2->field_0;
                                                                                                                                                    a2 = ptr2->field_10;
                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                    if (result <= 2) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                                                                                        a2 = ptr2->field_10;
                                                                                                                                                    }
                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                    a1 = ptr->field_2;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                                                                                                                                    a1 = ptr->field_0;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                    a2 += 3;
                                                                                                                                                    ptr2->field_10 = a2;
                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                    off_140108038(result, 0, ptr);
                                                                                                                                                    result = ptr6 + 38;
                                                                                                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                                                    ptr5 = ptr2->field_10;
                                                                                                                                                    if (ptr5 == ptr2->field_0) {
                                                                                                                                                        sub_1400F3510(ptr2);
                                                                                                                                                    }
                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr5) = 73;
                                                                                                                                                    result = ptr5 + 1;
                                                                                                                                                    ptr2->field_10 = result;
                                                                                                                                                    if (result == ptr2->field_0) {
                                                                                                                                                        sub_1400F3510(ptr2);
                                                                                                                                                    }
                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr5 + 1) = 1;
                                                                                                                                                    result = ptr5 + 2;
                                                                                                                                                    ptr2->field_10 = result;
                                                                                                                                                    if (result == ptr2->field_0) {
                                                                                                                                                        sub_1400F3510(ptr2);
                                                                                                                                                    }
                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr5 + 2) = 249;
                                                                                                                                                    ptr5 += 3;
                                                                                                                                                    ptr2->field_10 = ptr5;
                                                                                                                                                    result = ptr2->field_0;
                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr5);
                                                                                                                                                    if (result <= 2) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        sub_1400F2D20(ptr2, ptr5, 3, 1);
                                                                                                                                                        ptr5 = ptr2->field_10;
                                                                                                                                                    }
                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr5 + 2) = 1;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr5) = 0x8949;
                                                                                                                                                    ptr5 += 3;
                                                                                                                                                    ptr2->field_10 = ptr5;
                                                                                                                                                    result = ptr6 + 40;
                                                                                                                                                    *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                    if (result != 0) {
                                                                                                                                                        ptr = (struct Struct_2_t *)result;
                                                                                                                                                        *(__int64 *)result = (__int64)(0x244C8B48);
                                                                                                                                                        result = ptr2->field_0;
                                                                                                                                                        a2 = ptr2->field_10;
                                                                                                                                                        ptr->field_4 = 48;
                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                        if (result <= 4) {
                                                                                                                                                            v_20 = 1;
                                                                                                                                                            sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                                                            a2 = ptr2->field_10;
                                                                                                                                                        }
                                                                                                                                                        result = ptr2->field_8;
                                                                                                                                                        a1 = ptr->field_4;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                        a1 = ptr->field_0;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                        a2 += 5;
                                                                                                                                                        ptr2->field_10 = a2;
                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                        off_140108038(result, 0, ptr);
                                                                                                                                                        ptr = ptr2->field_10;
                                                                                                                                                        if (ptr == ptr2->field_0) {
                                                                                                                                                            sub_1400F3510(ptr2);
                                                                                                                                                        }
                                                                                                                                                        result = ptr2->field_8;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr) = 72;
                                                                                                                                                        result = ptr + 1;
                                                                                                                                                        ptr2->field_10 = result;
                                                                                                                                                        if (result == ptr2->field_0) {
                                                                                                                                                            sub_1400F3510(ptr2);
                                                                                                                                                        }
                                                                                                                                                        result = ptr2->field_8;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr + 1) = 1;
                                                                                                                                                        result = ptr + 2;
                                                                                                                                                        ptr2->field_10 = result;
                                                                                                                                                        if (result == ptr2->field_0) {
                                                                                                                                                            sub_1400F3510(ptr2);
                                                                                                                                                        }
                                                                                                                                                        result = ptr2->field_8;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 203;
                                                                                                                                                        ptr += 3;
                                                                                                                                                        ptr2->field_10 = ptr;
                                                                                                                                                        result = ptr6 + 42;
                                                                                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                                                        sub_14002EDF0(0, 7);
                                                                                                                                                        if (result != 0) {
                                                                                                                                                            ptr = (struct Struct_2_t *)result;
                                                                                                                                                            *(__int64 *)result = (__int64)(0x1EC8349);
                                                                                                                                                            result = ptr2->field_0;
                                                                                                                                                            a2 = ptr2->field_10;
                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                v_20 = 1;
                                                                                                                                                                sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                                                                                                a2 = ptr2->field_10;
                                                                                                                                                            }
                                                                                                                                                            result = ptr2->field_8;
                                                                                                                                                            a1 = ptr->field_0;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                            a2 += 4;
                                                                                                                                                            ptr2->field_10 = a2;
                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                            off_140108038(result, 0, ptr);
                                                                                                                                                            result = ptr2->field_10;
                                                                                                                                                            result += 5;
                                                                                                                                                            if (!((result < 0))) {
                                                                                                                                                                ptr4 = (struct Struct_5_t *)((__int64)ptr4 - (__int64)result);
                                                                                                                                                                result = (struct Struct_1_t *)ptr4;
                                                                                                                                                                if (ptr4 == ptr4) {
                                                                                                                                                                    sub_14002EDF0(0, 5);
                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                        ptr5 = (struct Struct_6_t *)result;
                                                                                                                                                                        *(__int64 *)result = (__int64)(233);
                                                                                                                                                                        result->field_1 = ptr4;
                                                                                                                                                                        result = ptr2->field_0;
                                                                                                                                                                        a2 = ptr2->field_10;
                                                                                                                                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                            sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                                                                            a2 = ptr2->field_10;
                                                                                                                                                                        }
                                                                                                                                                                        result = ptr2->field_8;
                                                                                                                                                                        a1 = ptr5->field_4;
                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                        a1 = ptr5->field_0;
                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                        a2 += 5;
                                                                                                                                                                        ptr2->field_10 = a2;
                                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                                        off_140108038(result, 0, ptr5);
                                                                                                                                                                        result = ptr6 + 44;
                                                                                                                                                                        *(__int64 *)ptr3 = (__int64)(result);
                                                                                                                                                                        a2 = (int *)dst;
                                                                                                                                                                        a2 += 9;
                                                                                                                                                                        if (!((a2 < 0))) {
                                                                                                                                                                            a3 = ptr2->field_10;
                                                                                                                                                                            result = (struct Struct_1_t *)a3;
                                                                                                                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                                            a1 = (int *)result;
                                                                                                                                                                            ptr4 = (struct Struct_5_t *)v_40;
                                                                                                                                                                            if (result == result) {
                                                                                                                                                                                if (a3 < a2) {
                                                                                                                                                                                    return (__int64)ptr4;
                                                                                                                                                                                }
                                                                                                                                                                                a1 = ptr2->field_8;
                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)dst + 5) = result;
                                                                                                                                                                                sub_14002EDF0(0, 7, a3);
                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                    ptr = (struct Struct_2_t *)result;
                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x1ED8349);
                                                                                                                                                                                    result = ptr2->field_0;
                                                                                                                                                                                    a2 = ptr2->field_10;
                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                                                    if (result <= 3) {
                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                        sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                                                                                                                        a2 = ptr2->field_10;
                                                                                                                                                                                    }
                                                                                                                                                                                    result = ptr2->field_8;
                                                                                                                                                                                    a1 = ptr->field_0;
                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                    a2 += 4;
                                                                                                                                                                                    ptr2->field_10 = a2;
                                                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                                                    off_140108038(result, 0, ptr);
                                                                                                                                                                                    result = ptr2->field_10;
                                                                                                                                                                                    result += 5;
                                                                                                                                                                                    if (!((result < 0))) {
                                                                                                                                                                                        ptr = (struct Struct_2_t *)v_38;
                                                                                                                                                                                        ptr = (struct Struct_2_t *)((__int64)ptr - (__int64)result);
                                                                                                                                                                                        result = (struct Struct_1_t *)ptr;
                                                                                                                                                                                        if (ptr == ptr) {
                                                                                                                                                                                            sub_14002EDF0(0, 5);
                                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                                dst = (__int64 *)result;
                                                                                                                                                                                                *(__int64 *)result = (__int64)(233);
                                                                                                                                                                                                result->field_1 = ptr;
                                                                                                                                                                                                result = ptr2->field_0;
                                                                                                                                                                                                a2 = ptr2->field_10;
                                                                                                                                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                if (result <= 4) {
                                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                                    sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                                                                                                                                    a2 = ptr2->field_10;
                                                                                                                                                                                                }
                                                                                                                                                                                                result = ptr2->field_8;
                                                                                                                                                                                                a1 = (int *)arg_4;
                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                a1 = *dst;
                                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                a2 += 5;
                                                                                                                                                                                                ptr2->field_10 = a2;
                                                                                                                                                                                                off_140108030(a1, a2);
                                                                                                                                                                                                off_140108038(result, 0, dst);
                                                                                                                                                                                                ptr6 += 46;
                                                                                                                                                                                                *(__int64 *)ptr3 = (__int64)(ptr6);
                                                                                                                                                                                                a2 = (int *)ptr4;
                                                                                                                                                                                                a2 += 9;
                                                                                                                                                                                                if (!((a2 < 0))) {
                                                                                                                                                                                                    a3 = ptr2->field_10;
                                                                                                                                                                                                    result = (struct Struct_1_t *)a3;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                    a1 = (int *)result;
                                                                                                                                                                                                    if (result == result) {
                                                                                                                                                                                                        if (a3 < a2) {
                                                                                                                                                                                                            return (__int64)a1;
                                                                                                                                                                                                        }
                                                                                                                                                                                                        a1 = ptr2->field_8;
                                                                                                                                                                                                        *(__int64 *)((__int64)a1 + (__int64)ptr4 + 5) = result;
                                                                                                                                                                                                        return (__int64)a1;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = &off_14011C688;
                                                                                                                                                                                                    v_20 = (__int64)result;
                                                                                                                                                                                                    a1 = &off_14011C678;
                                                                                                                                                                                                    v5 = &off_14011D3F8;
                                                                                                                                                                                                    a3 = rsp + 55;
                                                                                                                                                                                                    sub_1400F3B80(a1, 14, a3, v5);
                                                                                                                                                                                                    ptr2 = (struct Struct_3_t *)a2;
                                                                                                                                                                                                    ptr3 = (struct Struct_4_t *)a1;
                                                                                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                                                                                    if (result == 0) JUMPOUT(0x1400d2e74);
                                                                                                                                                                                                    ptr6 = (struct Struct_7_t *)result;
                                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x3148);
                                                                                                                                                                                                    result->field_2 = 192;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    ptr = ptr3->field_10;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 2) JUMPOUT(0x1400d2e83);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    a1 = ptr6->field_2;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = a1;
                                                                                                                                                                                                    a1 = ptr6->field_0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                                                                                                                                                                                                    ptr += 3;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    off_140108030(a1);
                                                                                                                                                                                                    off_140108038(result, 0, ptr6);
                                                                                                                                                                                                    dst = ptr2->field_0;
                                                                                                                                                                                                    result = dst + 1;
                                                                                                                                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                                                                                    if (result == 0) JUMPOUT(0x1400d2e74);
                                                                                                                                                                                                    ptr6 = (struct Struct_7_t *)result;
                                                                                                                                                                                                    *(__int64 *)result = (__int64)(0x8948);
                                                                                                                                                                                                    result->field_2 = 231;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 2) JUMPOUT(0x1400d2eac);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    a1 = ptr6->field_2;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = a1;
                                                                                                                                                                                                    a1 = ptr6->field_0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                                                                                                                                                                                                    ptr += 3;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    off_140108030(a1);
                                                                                                                                                                                                    off_140108038(result, 0, ptr6);
                                                                                                                                                                                                    sub_14002EDF0(0, 6);
                                                                                                                                                                                                    if (result == 0) JUMPOUT(0x1400d31e0);
                                                                                                                                                                                                    ptr6 = (struct Struct_7_t *)result;
                                                                                                                                                                                                    *(__int64 *)result = (__int64)(185);
                                                                                                                                                                                                    result->field_1 = 472;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d2ed5);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    a1 = ptr6->field_4;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = a1;
                                                                                                                                                                                                    a1 = ptr6->field_0;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    off_140108030(a1);
                                                                                                                                                                                                    off_140108038(result, 0, ptr6);
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 2) JUMPOUT(0x1400d2efe);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 170;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xF3FC;
                                                                                                                                                                                                    ptr += 3;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = dst + 4;
                                                                                                                                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d2f27);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xC0EF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d2f50);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xC9EF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d2f79);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xD2EF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d2fa2);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xDBEF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = dst + 8;
                                                                                                                                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d2fcb);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE4EF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d2ff4);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEDEF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d301d);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xF6EF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 3) JUMPOUT(0x1400d3046);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xFFEF0F66;
                                                                                                                                                                                                    ptr += 4;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d306f);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 192;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d3098);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 201;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = dst + 14;
                                                                                                                                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d30c1);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 210;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d30ea);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 219;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d3113);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 228;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d313c);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 237;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = dst + 18;
                                                                                                                                                                                                    *(__int64 *)ptr2 = (__int64)(result);
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d3165);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 246;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 4) JUMPOUT(0x1400d318e);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEF0F4566;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 255;
                                                                                                                                                                                                    ptr += 5;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    result = ptr3->field_0;
                                                                                                                                                                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                                                                                                                                                                                    if (result <= 1) JUMPOUT(0x1400d31b7);
                                                                                                                                                                                                    result = ptr3->field_8;
                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE3DB;
                                                                                                                                                                                                    ptr += 2;
                                                                                                                                                                                                    ptr3->field_10 = ptr;
                                                                                                                                                                                                    dst += 21;
                                                                                                                                                                                                    *(__int64 *)ptr2 = (__int64)(dst);
                                                                                                                                                                                                    return (__int64)dst;
                                                                                                                                                                                                }
                                                                                                                                                                                                result = &off_14011B3E0;
                                                                                                                                                                                                v_20 = (__int64)result;
                                                                                                                                                                                                a1 = &off_14011B3C3;
                                                                                                                                                                                                v5 = &off_14011D3F8;
                                                                                                                                                                                                a3 = rsp + 55;
                                                                                                                                                                                                sub_1400F3B80(a1, 23, a3, v5);
                                                                                                                                                                                            }
                                                                                                                                                                                            sub_1400F3326(1, 5);
                                                                                                                                                                                            sub_1400F3326(1, 3);
                                                                                                                                                                                            sub_1400F3326(1, 12);
                                                                                                                                                                                            result = &off_14011B838;
                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                            a1 = &off_14011B828;
                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                            a3 = rsp + 55;
                                                                                                                                                                                            sub_1400F3B80(a1, 15, a3, v5);
                                                                                                                                                                                            result = &off_14011B860;
                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                            a1 = &off_14011B850;
                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                            a3 = rsp + 55;
                                                                                                                                                                                            sub_1400F3B80(a1, 16, a3, v5);
                                                                                                                                                                                            result = &off_14011B888;
                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                            a1 = &off_14011B878;
                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                            a3 = rsp + 55;
                                                                                                                                                                                            sub_1400F3B80(a1, 9, a3, v5);
                                                                                                                                                                                            result = &off_14011B8B0;
                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                            a1 = &off_14011B8A0;
                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                            a3 = rsp + 55;
                                                                                                                                                                                            sub_1400F3B80(a1, 14, a3, v5);
                                                                                                                                                                                        }
                                                                                                                                                                                        result = &off_14011C660;
                                                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                                                        a1 = &off_14011C650;
                                                                                                                                                                                        v5 = &off_14011D3F8;
                                                                                                                                                                                        a3 = rsp + 55;
                                                                                                                                                                                        sub_1400F3B80(a1, 9, a3, v5);
                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                    }
                                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                                }
                                                                                                                                                                                sub_1400F3326(1, 7);
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
                                                                                                                                                    sub_1400F3326(1, 8);
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
                                                                                                        }
                                                                                                    }
                                                                                                    return (__int64)a3;
                                                                                                }
                                                                                                return (__int64)a3;
                                                                                            }
                                                                                        }
                                                                                        return (__int64)a3;
                                                                                    }
                                                                                    return (__int64)a3;
                                                                                }
                                                                            }
                                                                            return (__int64)a3;
                                                                        }
                                                                        return (__int64)a3;
                                                                    }
                                                                    return (__int64)a3;
                                                                }
                                                                return (__int64)a3;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            return (__int64)a3;
                                        }
                                        return (__int64)a3;
                                    }
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
            arg_3 = (__int64)ptr4;
            ptr4 = 7;
            result = 129;
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}