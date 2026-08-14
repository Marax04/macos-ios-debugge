// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int64 field_2; // offset 2
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr4`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400D4F50();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3B80();
__int64 sub_1400F3326();
__int64 sub_1400F3869();
__int64 sub_1400F3600();
__int64 sub_1400C4641();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011CEC0;
extern __int64 off_14011CEA8;
extern __int64 off_14011D3F8;
extern __int64 off_14011CEE8;
extern __int64 off_14011CED8;
extern __int64 off_14011CF18;
extern __int64 off_14011CF00;
extern __int64 off_14011CF40;
extern __int64 off_14011CF30;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D368;
extern __int64 off_14011CF70;
extern __int64 off_14011CF58;
extern __int64 off_14011D380;
extern __int64 off_14011CF98;
extern __int64 off_14011CF88;

__int64 __fastcall sub_1400C46B0() {
    __int64 rsp;
    __int64 arg_10;
    int arg_8;
    __int64 v_20;
    int v_30;
    int v_38;
    int v_40;
    int v_70;
    int v_e0;
    int v_e8;
    struct Struct_4_t *ptr3;
    __int64 v12;
    struct Struct_3_t *ptr2;
    struct Struct_2_t *ptr;
    struct Struct_1_t *result;
    __int64 v14;
    __int64 *dst;
    __int64 *dst2;
    __int64 *src;
    __int64 v11;
    __m128i xmm0;
    __int64 *i;
    __int64 *dst3;
    __int64 v10;
    struct Struct_5_t *ptr4;

    ptr3 = rsp + 48;
    sub_1400D4F50(ptr3, 7, 4, ptr2);
    v12 = v_30;
    ptr2 = (struct Struct_3_t *)v_38;
    ptr = (struct Struct_2_t *)v_40;
    result = ptr4->field_0;
    v14 = ptr4->field_10;
    result -= v14;
    if (ptr > result) {
        v_20 = 1;
        sub_1400F2D20(ptr4, v14, ptr, 1);
        v14 = ptr4->field_10;
    }
    ptr3 = ptr4->field_8;
    ptr3 += v14;
    sub_1400F27F0(ptr3, ptr2, ptr);
    v14 += (__int64)ptr;
    ptr4->field_10 = v14;
    if (v12 != 0) {
        off_140108030();
        off_140108038(result, 0, ptr2);
    }
    result = v11 + 2;
    *i = result;
    sub_14002EDF0(0, 3);
    if (result == 0) {
        sub_1400F3340(1, 3);
    } else {
        ptr2 = (struct Struct_3_t *)result;
        *(__int64 *)result = (__int64)(0x3148);
        result->field_2 = 201;
        result = ptr4->field_0;
        dst = ptr4->field_10;
        result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr4, dst, 3, 1);
            dst = ptr4->field_10;
        }
        result = ptr4->field_8;
        ptr3 = ptr2->field_2;
        *(__int64 *)((__int64)result + (__int64)dst + 2) = ptr3;
        ptr3 = ptr2->field_0;
        *(__int64 *)((__int64)result + (__int64)dst) = ptr3;
        dst += 3;
        ptr4->field_10 = dst;
        off_140108030(ptr3, dst);
        off_140108038(result, 0, ptr2);
        result = v11 + 3;
        *i = result;
        v12 = ptr4->field_10;
        sub_14002EDF0(0, 7);
        if (result != 0) {
            ptr2 = (struct Struct_3_t *)result;
            *(__int64 *)result = (__int64)(0x20F98348);
            result = ptr4->field_0;
            dst = ptr4->field_10;
            result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr4, dst, 4, 1);
                dst = ptr4->field_10;
            }
            result = ptr4->field_8;
            ptr3 = ptr2->field_0;
            *(__int64 *)((__int64)result + (__int64)dst) = ptr3;
            dst += 4;
            ptr4->field_10 = dst;
            off_140108030(ptr3, dst);
            off_140108038(result, 0, ptr2);
            result = v11 + 4;
            *i = result;
            ptr2 = ptr4->field_10;
            sub_14002EDF0(0, 6);
            if (result != 0) {
                ptr = (struct Struct_2_t *)result;
                *(__int64 *)result = (__int64)(0x840F);
                result->field_2 = 0;
                result = ptr4->field_0;
                dst = ptr4->field_10;
                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                if (result <= 5) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, dst, 6, 1);
                    dst = ptr4->field_10;
                }
                result = ptr4->field_8;
                ptr3 = ptr->field_4;
                *(__int64 *)((__int64)result + (__int64)dst + 4) = ptr3;
                ptr3 = ptr->field_0;
                *(__int64 *)((__int64)result + (__int64)dst) = ptr3;
                dst += 6;
                ptr4->field_10 = dst;
                off_140108030(ptr3, dst);
                off_140108038(result, 0, ptr);
                result = v11 + 5;
                *i = result;
                result = ptr4->field_0;
                ptr = ptr4->field_10;
                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, ptr, 3, 1);
                    ptr = ptr4->field_10;
                }
                result = ptr4->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 78;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x48A;
                ptr += 3;
                ptr4->field_10 = ptr;
                result = ptr4->field_0;
                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, ptr, 2, 1);
                    ptr = ptr4->field_10;
                }
                result = ptr4->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x200C;
                ptr += 2;
                ptr4->field_10 = ptr;
                result = ptr4->field_0;
                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, ptr, 2, 1);
                    ptr = ptr4->field_10;
                }
                result = ptr4->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x393C;
                v14 = ptr + 2;
                ptr4->field_10 = v14;
                result = ptr4->field_0;
                result -= v14;
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, v14, 2, 1);
                    v14 = ptr4->field_10;
                }
                result = ptr4->field_8;
                *(__int64 *)(result + v14) = (__int64)(118);
                v14 += 2;
                ptr4->field_10 = v14;
                result = v11 + 9;
                *i = result;
                result = ptr4->field_0;
                result -= v14;
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, v14, 2, 1);
                    v14 = ptr4->field_10;
                }
                result = ptr4->field_8;
                *(__int64 *)(result + v14) = (__int64)(0x572C);
                dst = v14 + 2;
                ptr4->field_10 = dst;
                result = ptr4->field_0;
                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr4, dst, 2, 1);
                    dst = ptr4->field_10;
                }
                result = ptr4->field_8;
                *(__int64 *)((__int64)result + (__int64)dst) = 235;
                dst += 2;
                ptr4->field_10 = dst;
                ptr3 = (struct Struct_4_t *)ptr;
                ptr3 += 4;
                if (!((ptr3 < 0))) {
                    result = (struct Struct_1_t *)dst;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                    ptr3 = (struct Struct_4_t *)result;
                    if (result != result) {
                        result = &off_14011CEC0;
                        v_20 = (__int64)result;
                        ptr3 = &off_14011CEA8;
                        dst2 = &off_14011D3F8;
                        src = rsp + 48;
                        sub_1400F3B80(ptr3, 17, src, dst2);
                    } else {
                        ptr += 3;
                        if (ptr < dst) {
                            ptr3 = ptr4->field_8;
                            *(__int64 *)((__int64)ptr3 + (__int64)ptr) = result;
                            result = ptr4->field_0;
                            dst = ptr4->field_10;
                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                            if (result <= 1) {
                                v_20 = 1;
                                sub_1400F2D20(ptr4, dst, 2, 1);
                                dst = ptr4->field_10;
                            }
                            result = ptr4->field_8;
                            *(__int64 *)((__int64)result + (__int64)dst) = 0x302C;
                            dst += 2;
                            ptr4->field_10 = dst;
                            result = v11 + 12;
                            *i = result;
                            ptr3 = (struct Struct_4_t *)v14;
                            ptr3 += 4;
                            if (!((ptr3 < 0))) {
                                result = (struct Struct_1_t *)dst;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                ptr3 = (struct Struct_4_t *)result;
                                if (result != result) {
                                    result = &off_14011CEE8;
                                    v_20 = (__int64)result;
                                    ptr3 = &off_14011CED8;
                                    dst2 = &off_14011D3F8;
                                    src = rsp + 48;
                                    sub_1400F3B80(ptr3, 16, src, dst2);
                                } else {
                                    v14 += 3;
                                    if (v14 < dst) {
                                        ptr3 = ptr4->field_8;
                                        *(__int64 *)(ptr3 + v14) = (__int64)(result);
                                        result = ptr4->field_0;
                                        ptr = ptr4->field_10;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                        if (result <= 2) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, ptr, 3, 1);
                                            ptr = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 4;
                                        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE0C0;
                                        ptr += 3;
                                        ptr4->field_10 = ptr;
                                        result = ptr4->field_0;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                        if (result <= 1) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, ptr, 2, 1);
                                            ptr = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)((__int64)result + (__int64)ptr) = 0xC288;
                                        ptr += 2;
                                        ptr4->field_10 = ptr;
                                        result = ptr4->field_0;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                        if (result <= 3) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, ptr, 4, 1);
                                            ptr = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)((__int64)result + (__int64)ptr) = 0x14E448A;
                                        ptr += 4;
                                        ptr4->field_10 = ptr;
                                        result = ptr4->field_0;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                        if (result <= 1) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, ptr, 2, 1);
                                            ptr = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)((__int64)result + (__int64)ptr) = 0x200C;
                                        ptr += 2;
                                        ptr4->field_10 = ptr;
                                        result = v11 + 16;
                                        *i = result;
                                        result = ptr4->field_0;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
                                        if (result <= 1) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, ptr, 2, 1);
                                            ptr = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)((__int64)result + (__int64)ptr) = 0x393C;
                                        v14 = ptr + 2;
                                        ptr4->field_10 = v14;
                                        result = ptr4->field_0;
                                        result -= v14;
                                        if (result <= 1) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, v14, 2, 1);
                                            v14 = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)(result + v14) = (__int64)(118);
                                        v14 += 2;
                                        ptr4->field_10 = v14;
                                        result = ptr4->field_0;
                                        result -= v14;
                                        if (result <= 1) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, v14, 2, 1);
                                            v14 = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)(result + v14) = (__int64)(0x572C);
                                        dst = v14 + 2;
                                        ptr4->field_10 = dst;
                                        result = ptr4->field_0;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                        if (result <= 1) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr4, dst, 2, 1);
                                            dst = ptr4->field_10;
                                        }
                                        result = ptr4->field_8;
                                        *(__int64 *)((__int64)result + (__int64)dst) = 235;
                                        dst += 2;
                                        ptr4->field_10 = dst;
                                        ptr3 = (struct Struct_4_t *)ptr;
                                        ptr3 += 4;
                                        if (!((ptr3 < 0))) {
                                            result = (struct Struct_1_t *)dst;
                                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                            ptr3 = (struct Struct_4_t *)result;
                                            if (result != result) {
                                                result = &off_14011CF18;
                                                v_20 = (__int64)result;
                                                ptr3 = &off_14011CF00;
                                                dst2 = &off_14011D3F8;
                                                src = rsp + 48;
                                                sub_1400F3B80(ptr3, 17, src, dst2);
                                            } else {
                                                ptr += 3;
                                                if (ptr < dst) {
                                                    ptr3 = ptr4->field_8;
                                                    *(__int64 *)((__int64)ptr3 + (__int64)ptr) = result;
                                                    result = ptr4->field_0;
                                                    dst = ptr4->field_10;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                    if (result <= 1) {
                                                        v_20 = 1;
                                                        sub_1400F2D20(ptr4, dst, 2, 1);
                                                        dst = ptr4->field_10;
                                                    }
                                                    result = ptr4->field_8;
                                                    *(__int64 *)((__int64)result + (__int64)dst) = 0x302C;
                                                    dst += 2;
                                                    ptr4->field_10 = dst;
                                                    ptr3 = (struct Struct_4_t *)v14;
                                                    ptr3 += 4;
                                                    if (!((ptr3 < 0))) {
                                                        result = (struct Struct_1_t *)dst;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                                        ptr3 = (struct Struct_4_t *)result;
                                                        if (result != result) {
                                                            result = &off_14011CF40;
                                                            v_20 = (__int64)result;
                                                            ptr3 = &off_14011CF30;
                                                            dst2 = &off_14011D3F8;
                                                            src = rsp + 48;
                                                            sub_1400F3B80(ptr3, 16, src, dst2);
                                                        } else {
                                                            v14 += 3;
                                                            if (v14 < dst) {
                                                                ptr3 = ptr4->field_8;
                                                                *(__int64 *)(ptr3 + v14) = (__int64)(result);
                                                                result = ptr4->field_0;
                                                                dst = ptr4->field_10;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                if (result <= 1) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr4, dst, 2, 1);
                                                                    dst = ptr4->field_10;
                                                                }
                                                                result = ptr4->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)dst) = 0xD008;
                                                                dst += 2;
                                                                ptr4->field_10 = dst;
                                                                result = v11 + 22;
                                                                *i = result;
                                                                result = ptr4->field_0;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                if (result <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr4, dst, 3, 1);
                                                                    dst = ptr4->field_10;
                                                                }
                                                                result = ptr4->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)dst + 2) = 15;
                                                                *(__int64 *)((__int64)result + (__int64)dst) = 0x488;
                                                                dst += 3;
                                                                ptr4->field_10 = dst;
                                                                result = ptr4->field_0;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                if (result <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr4, dst, 3, 1);
                                                                    dst = ptr4->field_10;
                                                                }
                                                                result = ptr4->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)dst + 2) = 193;
                                                                *(__int64 *)((__int64)result + (__int64)dst) = 0xFF48;
                                                                result = dst + 3;
                                                                ptr4->field_10 = result;
                                                                dst += 8;
                                                                if (!((dst < 0))) {
                                                                    v12 -= (__int64)dst;
                                                                    result = (struct Struct_1_t *)v12;
                                                                    if (v12 == v12) {
                                                                        sub_14002EDF0(0, 5);
                                                                        if (result != 0) {
                                                                            ptr = (struct Struct_2_t *)result;
                                                                            *(__int64 *)result = (__int64)(233);
                                                                            result->field_1 = v12;
                                                                            result = ptr4->field_0;
                                                                            dst = ptr4->field_10;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                            if (result <= 4) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr4, dst, 5, 1);
                                                                                dst = ptr4->field_10;
                                                                            }
                                                                            result = ptr4->field_8;
                                                                            ptr3 = ptr->field_4;
                                                                            *(__int64 *)((__int64)result + (__int64)dst + 4) = ptr3;
                                                                            ptr3 = ptr->field_0;
                                                                            *(__int64 *)((__int64)result + (__int64)dst) = ptr3;
                                                                            dst += 5;
                                                                            ptr4->field_10 = dst;
                                                                            off_140108030(ptr3, dst);
                                                                            off_140108038(result, 0, ptr);
                                                                            v11 += 25;
                                                                            *i = v11;
                                                                            dst = (__int64 *)ptr2;
                                                                            dst += 6;
                                                                            if ((dst < 0)) {
                                                                                result = &off_14011B3E0;
                                                                                v_20 = (__int64)result;
                                                                                ptr3 = &off_14011B3C3;
                                                                                dst2 = &off_14011D3F8;
                                                                                src = rsp + 48;
                                                                                sub_1400F3B80(ptr3, 23, src, dst2);
                                                                                sub_1400F3326(1, 8);
                                                                                src = &off_14011D368;
                                                                                sub_1400F3869(ptr, dst, src);
                                                                                src = &off_14011D368;
                                                                                sub_1400F3869(v14, dst, src);
                                                                                sub_1400F3326(1, 7);
                                                                                sub_1400F3326(1, 6);
                                                                                result = &off_14011CF70;
                                                                                v_20 = (__int64)result;
                                                                                ptr3 = &off_14011CF58;
                                                                                dst2 = &off_14011D3F8;
                                                                                src = rsp + 48;
                                                                                sub_1400F3B80(ptr3, 17, src, dst2);
                                                                                sub_1400F3326(1, 5);
                                                                            } else {
                                                                                src = ptr4->field_10;
                                                                                result = (struct Struct_1_t *)src;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)dst);
                                                                                ptr3 = (struct Struct_4_t *)result;
                                                                                if (result == result) {
                                                                                    if (src < dst) {
                                                                                        ptr2 += 2;
                                                                                        dst2 = &off_14011D380;
                                                                                        sub_1400F3600(ptr2, dst, src, dst2);
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr4, v11, v14, 1);
                                                                                        v11 = ptr4->field_10;
                                                                                        return sub_1400C4641();
                                                                                    } else {
                                                                                        ptr3 = ptr4->field_8;
                                                                                        *(__int64 *)((__int64)ptr3 + (__int64)ptr2 + 2) = result;
                                                                                        return (__int64)ptr3;
                                                                                    }
                                                                                }
                                                                            }
                                                                            result = &off_14011CF98;
                                                                            v_20 = (__int64)result;
                                                                            ptr3 = &off_14011CF88;
                                                                            dst2 = &off_14011D3F8;
                                                                            src = rsp + 48;
                                                                            sub_1400F3B80(ptr3, 12, src, dst2);
                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_e8);
                                                                            _mm_storeu_si128((__m128i *)&v_70, xmm0);
                                                                            result = ptr3->field_0;
                                                                            i = ptr3->field_10;
                                                                            dst3 = (__int64 *)result;
                                                                            dst3 = (__int64 *)((__int64)dst3 - (__int64)i);
                                                                            if (dst3 <= 1) JUMPOUT(0x1400c5518);
                                                                            dst3 = ptr3->field_8;
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i) = 0x310F;
                                                                            i += 2;
                                                                            ptr3->field_10 = i;
                                                                            ptr = *dst;
                                                                            v10 = (__int64)result;
                                                                            v10 -= (__int64)i;
                                                                            if (v10 <= 3) JUMPOUT(0x1400c5559);
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i) = 0x20E2C148;
                                                                            i += 4;
                                                                            ptr3->field_10 = i;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                            if (result <= 2) JUMPOUT(0x1400c559e);
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i + 2) = 208;
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i) = 0x948;
                                                                            i += 3;
                                                                            ptr3->field_10 = i;
                                                                            result = ptr3->field_0;
                                                                            dst3 = (__int64 *)result;
                                                                            dst3 = (__int64 *)((__int64)dst3 - (__int64)i);
                                                                            if (dst3 <= 2) JUMPOUT(0x1400c55e0);
                                                                            dst3 = ptr3->field_8;
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i + 2) = 195;
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i) = 0x8949;
                                                                            i += 3;
                                                                            ptr3->field_10 = i;
                                                                            v10 = ptr + 4;
                                                                            *dst = v10;
                                                                            if (result == i) JUMPOUT(0x1400c5621);
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i) = 185;
                                                                            ++i;
                                                                            ptr3->field_10 = i;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                            if (result <= 3) JUMPOUT(0x1400c5666);
                                                                            *(__int64 *)((__int64)dst3 + (__int64)i) = dst2;
                                                                            result = i + 4;
                                                                            ptr3->field_10 = result;
                                                                            dst2 = ptr3->field_0;
                                                                            dst2 = (__int64 *)((__int64)dst2 - (__int64)result);
                                                                            if (dst2 <= 1) JUMPOUT(0x1400c56a8);
                                                                            dst2 = ptr3->field_8;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)result) = 0xC9FF;
                                                                            ptr4 = result + 2;
                                                                            ptr3->field_10 = ptr4;
                                                                            dst3 = (__int64 *)result;
                                                                            dst3 += 4;
                                                                            if ((dst3 < 0)) JUMPOUT(0x1400c5957);
                                                                            i = (__int64 *)((__int64)i - (__int64)result);
                                                                            result = (struct Struct_1_t *)i;
                                                                            if (i != i) JUMPOUT(0x1400c56e0);
                                                                            result = ptr3->field_0;
                                                                            dst3 = (__int64 *)result;
                                                                            dst3 = (__int64 *)((__int64)dst3 - (__int64)ptr4);
                                                                            if (dst3 <= 1) JUMPOUT(0x1400c5738);
                                                                            i = (__int64 *)((__int64)(__int64)i << 8);
                                                                            i = (__int64 *)((__int64)(__int64)i | 117);
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = i;
                                                                            ptr4 += 2;
                                                                            ptr3->field_10 = ptr4;
                                                                            dst3 = ptr + 7;
                                                                            *dst = dst3;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr4);
                                                                            if (result <= 1) JUMPOUT(0x1400c5777);
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0x310F;
                                                                            ptr4 += 2;
                                                                            ptr3->field_10 = ptr4;
                                                                            result = ptr3->field_0;
                                                                            dst2 = (__int64 *)result;
                                                                            dst2 = (__int64 *)((__int64)dst2 - (__int64)ptr4);
                                                                            if (dst2 <= 3) JUMPOUT(0x1400c57b3);
                                                                            dst2 = ptr3->field_8;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0x20E2C148;
                                                                            ptr4 += 4;
                                                                            ptr3->field_10 = ptr4;
                                                                            dst3 = (__int64 *)result;
                                                                            dst3 = (__int64 *)((__int64)dst3 - (__int64)ptr4);
                                                                            if (dst3 <= 2) JUMPOUT(0x1400c57ee);
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4 + 2) = 208;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0x948;
                                                                            ptr4 += 3;
                                                                            ptr3->field_10 = ptr4;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr4);
                                                                            if (result <= 2) JUMPOUT(0x1400c582d);
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4 + 2) = 216;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0x294C;
                                                                            ptr4 += 3;
                                                                            ptr3->field_10 = ptr4;
                                                                            result = ptr + 11;
                                                                            *dst = result;
                                                                            result = ptr3->field_0;
                                                                            dst2 = (__int64 *)result;
                                                                            dst2 = (__int64 *)((__int64)dst2 - (__int64)ptr4);
                                                                            if (dst2 <= 1) JUMPOUT(0x1400c5869);
                                                                            ptr2 = (struct Struct_3_t *)v_e0;
                                                                            dst2 = ptr3->field_8;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0xB948;
                                                                            ptr4 += 2;
                                                                            ptr3->field_10 = ptr4;
                                                                            dst3 = (__int64 *)result;
                                                                            dst3 = (__int64 *)((__int64)dst3 - (__int64)ptr4);
                                                                            if (dst3 <= 7) JUMPOUT(0x1400c58a4);
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = ptr2;
                                                                            ptr4 += 8;
                                                                            ptr3->field_10 = ptr4;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr4);
                                                                            if (result <= 2) JUMPOUT(0x1400c58e3);
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4 + 2) = 200;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)ptr4) = 0x3948;
                                                                            ptr4 += 3;
                                                                            ptr3->field_10 = ptr4;
                                                                            dst2 = ptr3->field_0;
                                                                            dst2 = (__int64 *)((__int64)dst2 - (__int64)ptr4);
                                                                            result = (struct Struct_1_t *)ptr4;
                                                                            if (dst2 <= 5) JUMPOUT(0x1400c591f);
                                                                            dst2 = ptr3->field_8;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)result + 4) = 0;
                                                                            *(__int64 *)((__int64)dst2 + (__int64)result) = 0x870F;
                                                                            result += 6;
                                                                            ptr3->field_10 = result;
                                                                            ptr += 14;
                                                                            *dst = ptr;
                                                                            i = (__int64 *)arg_10;
                                                                            if (i == *src) JUMPOUT(0x1400c5508);
                                                                            result = (struct Struct_1_t *)arg_8;
                                                                            ((__int64 *)result)[(__int64)i] = (__int64)(ptr4);
                                                                            ++i;
                                                                            arg_10 = (__int64)i;
                                                                            return arg_10;
                                                                        }
                                                                        return arg_10;
                                                                    }
                                                                    return arg_10;
                                                                }
                                                                return arg_10;
                                                            }
                                                            return arg_10;
                                                        }
                                                        return arg_10;
                                                    }
                                                    return arg_10;
                                                }
                                                return arg_10;
                                            }
                                            return arg_10;
                                        }
                                        return arg_10;
                                    }
                                    return arg_10;
                                }
                                return arg_10;
                            }
                            return arg_10;
                        }
                        return arg_10;
                    }
                    return arg_10;
                }
                return arg_10;
            }
            return arg_10;
        }
        return arg_10;
    }
    return (__int64)result;
}