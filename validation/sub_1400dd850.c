// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int16 field_0; // offset 0
    char _pad_0[1];
    char field_3; // offset 3
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 5 accesses on `i`
struct Struct_4_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    char field_3; // offset 3
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F3600();
__int64 sub_1400F3340();
__int64 sub_1400F3510();
__int64 sub_1400DFDB0();
__int64 sub_1400F3B80();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;
extern __int64 off_14011CDC0;
extern __int64 off_14011CDA8;
extern __int64 off_14011D3F8;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011CB00;
extern __int64 off_14011CAE8;
extern __int64 off_14011C6A8;
extern __int64 off_14011C6A0;
extern __int64 off_14011C6C8;
extern __int64 off_14011C6C0;
extern __int64 off_14011C6F0;
extern __int64 off_14011C6E0;
extern __int64 off_14011C718;
extern __int64 off_14011C708;
extern __int64 off_14011C740;
extern __int64 off_14011C730;
extern __int64 off_14011C3F8;
extern __int64 off_14011C3E8;
extern __int64 off_14011C428;
extern __int64 off_14011C410;
extern __int64 off_14011CD68;
extern __int64 off_14011CD58;
extern __int64 off_14011CD90;
extern __int64 off_14011CD80;

__int64 __fastcall sub_1400DD850(size_t *a1, size_t *a2, int *a3) {
    __int64 rsp;
    __int64 arg_1;
    __int64 arg_2;
    int arg_4;
    int arg_5;
    __int64 v_20;
    int v_28;
    int v_2f;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 *dst;
    struct Struct_1_t *ptr;
    struct Struct_4_t *i;
    __int64 *i2;
    struct Struct_2_t *ptr2;
    __int64 *result;
    __int64 *src;
    struct Struct_3_t *ptr3;
    __int64 i3;
    __int64 v5;

    v_2f = (int)a3;
    dst = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    i = a1[2];
    sub_14002EDF0(0, 5);
    if (result != 0) {
        i2 = result;
        *result = 233;
        arg_1 = 0;
        ptr2 = ptr->field_0;
        result = (__int64 *)ptr2;
        result = (__int64 *)((__int64)result - (__int64)i);
        src = (__int64 *)i;
        if (result <= 4) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr, i, 5, 1);
                ptr2 = ptr->field_0;
                src = ptr->field_10;
            } while (true);
        }
        ptr3 = ptr->field_8;
        result = (__int64 *)arg_4;
        *(__int64 *)((__int64)ptr3 + (__int64)src + 4) = result;
        result = *i2;
        *(__int64 *)((__int64)ptr3 + (__int64)src) = result;
        src += 5;
        ptr->field_10 = src;
        off_140108030();
        off_140108038(result, 0, i2);
        i3 = *dst;
        result = (__int64 *)ptr2;
        result = (__int64 *)((__int64)result - (__int64)src);
        i2 = src;
        if (result <= 1) {
            v_20 = 1;
            sub_1400F2D20(ptr, src, 2, 1);
            i2 = ptr->field_10;
            ptr2 = ptr->field_0;
            ptr3 = ptr->field_8;
        }
        *(__int64 *)((__int64)ptr3 + (__int64)i2) = 0xB0F;
        i2 += 2;
        ptr->field_10 = i2;
        ptr2 = (struct Struct_2_t *)((__int64)ptr2 - (__int64)i2);
        if (ptr2 <= 1) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 2, 1);
            ptr3 = ptr->field_8;
            i2 = ptr->field_10;
        }
        *(__int64 *)((__int64)ptr3 + (__int64)i2) = 0x29CD;
        i2 += 2;
        ptr->field_10 = i2;
        result = ptr->field_0;
        if (result == i2) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 1, 1);
            result = ptr->field_0;
            i2 = ptr->field_10;
        }
        a1 = ptr->field_8;
        *(__int64 *)((__int64)a1 + (__int64)i2) = 204;
        ++i2;
        ptr->field_10 = i2;
        a2 = i3 + 4;
        *dst = a2;
        a2 = (size_t *)result;
        a2 = (size_t *)((__int64)a2 - (__int64)i2);
        if (a2 <= 7) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 8, 1);
            i2 = ptr->field_10;
            result = ptr->field_0;
            a1 = ptr->field_8;
        }
        *(__int64 *)((__int64)a1 + (__int64)i2) = 0x25048948;
        i2 += 8;
        ptr->field_10 = i2;
        result = (__int64 *)((__int64)result - (__int64)i2);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 3, 1);
            a1 = ptr->field_8;
            i2 = ptr->field_10;
        }
        *(__int64 *)((__int64)a1 + (__int64)i2 + 2) = 228;
        *(__int64 *)((__int64)a1 + (__int64)i2) = 0x3148;
        i2 += 3;
        ptr->field_10 = i2;
        result = ptr->field_0;
        if (result == i2) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 1, 1);
            result = ptr->field_0;
            i2 = ptr->field_10;
        }
        ptr2 = ptr->field_8;
        *(__int64 *)((__int64)ptr2 + (__int64)i2) = 195;
        ++i2;
        ptr->field_10 = i2;
        result = (__int64 *)((__int64)result - (__int64)i2);
        if (result <= 1) {
            v_20 = 1;
            sub_1400F2D20(ptr, i2, 2, 1);
            ptr2 = ptr->field_8;
            i2 = ptr->field_10;
        }
        *(__int64 *)((__int64)ptr2 + (__int64)i2) = 0xFEEB;
        i2 += 2;
        ptr->field_10 = i2;
        result = i3 + 8;
        *dst = result;
        a2 = (size_t *)i;
        a2 += 5;
        if (!((a2 < 0))) {
            result = i2;
            result = (__int64 *)((__int64)result - (__int64)a2);
            a1 = (size_t *)result;
            if (result == result) {
                if (i2 < a2) {
                    ++i;
                    v5 = &off_14011D380;
                    sub_1400F3600(i, a2, i2, v5);
                    ptr2 += 2;
                    v5 = &off_14011D380;
                    sub_1400F3600(ptr2, a2, a3, v5);
                    ptr3 += 2;
                    v5 = &off_14011D380;
                    sub_1400F3600(ptr3, a2, result, v5);
                    ptr2 += 4;
                    v5 = &off_14011D380;
                    sub_1400F3600(ptr2, a2, a3, v5);
                    a1 += 2;
                    v5 = &off_14011D380;
                    sub_1400F3600(a1, a2, a3, v5);
                }
                *(__int64 *)((__int64)ptr2 + (__int64)i + 1) = result;
                sub_14002EDF0(0, 9);
                if (result != 0) {
                    i = (struct Struct_4_t *)result;
                    *result = 0x248B4C65;
                    arg_4 = 37;
                    arg_5 = 96;
                    result = ptr->field_0;
                    result = (__int64 *)((__int64)result - (__int64)i2);
                    if (result <= 8) {
                        v_20 = 1;
                        sub_1400F2D20(ptr, i2, 9, 1);
                        ptr2 = ptr->field_8;
                        i2 = ptr->field_10;
                    }
                    result = i->field_8;
                    *(__int64 *)((__int64)ptr2 + (__int64)i2 + 8) = result;
                    result = i->field_0;
                    *(__int64 *)((__int64)ptr2 + (__int64)i2) = result;
                    i2 += 9;
                    ptr->field_10 = i2;
                    off_140108030();
                    off_140108038(result, 0, i);
                    sub_14002EDF0(0, 8);
                    if (result != 0) {
                        i = (struct Struct_4_t *)result;
                        *result = 0x246C8B4D;
                        arg_4 = 24;
                        result = ptr->field_0;
                        result = (__int64 *)((__int64)result - (__int64)i2);
                        if (result <= 4) {
                            v_20 = 1;
                            sub_1400F2D20(ptr, i2, 5, 1);
                            i2 = ptr->field_10;
                        }
                        ptr2 = ptr->field_8;
                        result = i->field_4;
                        *(__int64 *)((__int64)ptr2 + (__int64)i2 + 4) = result;
                        result = i->field_0;
                        *(__int64 *)((__int64)ptr2 + (__int64)i2) = result;
                        i2 += 5;
                        ptr->field_10 = i2;
                        off_140108030();
                        off_140108038(result, 0, i);
                        result = i3 + 10;
                        *dst = result;
                        sub_14002EDF0(0, 8);
                        if (result != 0) {
                            i = (struct Struct_4_t *)result;
                            *result = 0x24448B49;
                            arg_4 = 16;
                            result = ptr->field_0;
                            result = (__int64 *)((__int64)result - (__int64)i2);
                            if (result <= 4) {
                                v_20 = 1;
                                sub_1400F2D20(ptr, i2, 5, 1);
                                ptr2 = ptr->field_8;
                                i2 = ptr->field_10;
                            }
                            result = i->field_4;
                            *(__int64 *)((__int64)ptr2 + (__int64)i2 + 4) = result;
                            result = i->field_0;
                            *(__int64 *)((__int64)ptr2 + (__int64)i2) = result;
                            i2 += 5;
                            ptr->field_10 = i2;
                            off_140108030();
                            off_140108038(result, 0, i);
                            sub_14002EDF0(0, 8);
                            if (result != 0) {
                                i = (struct Struct_4_t *)result;
                                *(__int64 *)i = (__int64)(result);
                                result = ptr->field_0;
                                result = (__int64 *)((__int64)result - (__int64)i2);
                                if (result <= 7) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr, i2, 8, 1);
                                    ptr2 = ptr->field_8;
                                    i2 = ptr->field_10;
                                }
                                result = i->field_0;
                                *(__int64 *)((__int64)ptr2 + (__int64)i2) = result;
                                i2 += 8;
                                ptr->field_10 = i2;
                                off_140108030(0xD024848948);
                                off_140108038(result, 0, i);
                                result = i3 + 12;
                                *dst = result;
                                sub_14002EDF0(0, 8);
                                if (result != 0) {
                                    i = (struct Struct_4_t *)result;
                                    *result = 0x10758D4D;
                                    result = ptr->field_0;
                                    result = (__int64 *)((__int64)result - (__int64)i2);
                                    if (result <= 3) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr, i2, 4, 1);
                                        i2 = ptr->field_10;
                                    }
                                    ptr2 = ptr->field_8;
                                    result = i->field_0;
                                    *(__int64 *)((__int64)ptr2 + (__int64)i2) = result;
                                    i2 += 4;
                                    ptr->field_10 = i2;
                                    off_140108030();
                                    off_140108038(result, 0, i);
                                    sub_14002EDF0(0, 8);
                                    if (result != 0) {
                                        i = (struct Struct_4_t *)result;
                                        *result = 0x8B4D;
                                        arg_2 = 62;
                                        result = ptr->field_0;
                                        result = (__int64 *)((__int64)result - (__int64)i2);
                                        if (result <= 2) {
                                            v_20 = 1;
                                            sub_1400F2D20(ptr, i2, 3, 1);
                                            ptr2 = ptr->field_8;
                                            i2 = ptr->field_10;
                                        }
                                        result = i->field_2;
                                        *(__int64 *)((__int64)ptr2 + (__int64)i2 + 2) = result;
                                        result = i->field_0;
                                        *(__int64 *)((__int64)ptr2 + (__int64)i2) = result;
                                        i2 += 3;
                                        ptr->field_10 = i2;
                                        off_140108030();
                                        off_140108038(result, 0, i);
                                        result = i3 + 14;
                                        *dst = result;
                                        ptr2 = ptr->field_10;
                                        sub_14002EDF0(0, 8);
                                        if (result != 0) {
                                            i2 = result;
                                            *result = 0x8B4D;
                                            arg_2 = 63;
                                            result = ptr->field_0;
                                            a2 = ptr->field_10;
                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr, a2, 3, 1);
                                                a2 = ptr->field_10;
                                            }
                                            result = ptr->field_8;
                                            a1 = (size_t *)arg_2;
                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                            a1 = *i2;
                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                            a2 += 3;
                                            ptr->field_10 = a2;
                                            off_140108030(a1, a2);
                                            off_140108038(result, 0, i2);
                                            result = i3 + 15;
                                            *dst = result;
                                            sub_14002EDF0(0, 3);
                                            if (result == 0) {
                                                sub_1400F3340(1, 3);
                                                i += 2;
                                                v5 = &off_14011D380;
                                                sub_1400F3600(i, a2, a3, v5);
                                                return v5;
                                            }
                                            i2 = result;
                                            *result = 0x394D;
                                            arg_2 = 247;
                                            result = ptr->field_0;
                                            a2 = ptr->field_10;
                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                            if (result <= 2) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr, a2, 3, 1);
                                                a2 = ptr->field_10;
                                            }
                                            result = ptr->field_8;
                                            a1 = (size_t *)arg_2;
                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                                            a1 = *i2;
                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                            a2 += 3;
                                            ptr->field_10 = a2;
                                            off_140108030(a1, a2);
                                            off_140108038(result, 0, i2);
                                            result = i3 + 16;
                                            *dst = result;
                                            result = ptr->field_10;
                                            v_38 = (__int64)result;
                                            sub_14002EDF0(0, 6);
                                            if (result != 0) {
                                                i = (struct Struct_4_t *)result;
                                                *result = 0x840F;
                                                arg_2 = 0;
                                                result = ptr->field_0;
                                                a2 = ptr->field_10;
                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                if (result <= 5) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr, a2, 6, 1);
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
                                                result = i3 + 17;
                                                *dst = result;
                                                sub_14002EDF0(0, 8);
                                                if (result != 0) {
                                                    i = (struct Struct_4_t *)result;
                                                    *result = 0x4FB70F49;
                                                    result = ptr->field_0;
                                                    a2 = ptr->field_10;
                                                    i->field_4 = 88;
                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                    if (result <= 4) {
                                                        v_20 = 1;
                                                        sub_1400F2D20(ptr, a2, 5, 1);
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
                                                    result = i3 + 18;
                                                    *dst = result;
                                                    sub_14002EDF0(0, 8);
                                                    if (result != 0) {
                                                        i = (struct Struct_4_t *)result;
                                                        *result = 0x8B49;
                                                        arg_2 = 87;
                                                        result = ptr->field_0;
                                                        a2 = ptr->field_10;
                                                        i->field_3 = 96;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr, a2, 4, 1);
                                                            a2 = ptr->field_10;
                                                        }
                                                        result = ptr->field_8;
                                                        a1 = i->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 4;
                                                        ptr->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, i);
                                                        result = i3 + 19;
                                                        *dst = result;
                                                        sub_14002EDF0(0, 6);
                                                        if (result != 0) {
                                                            i = (struct Struct_4_t *)result;
                                                            *result = 184;
                                                            arg_1 = 0x811C9DC5;
                                                            result = ptr->field_0;
                                                            a2 = ptr->field_10;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 4) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr, a2, 5, 1);
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
                                                            i2 = ptr->field_10;
                                                            if (i2 == ptr->field_0) {
                                                                sub_1400F3510(ptr, a2, a3);
                                                            }
                                                            result = ptr->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)i2) = 72;
                                                            result = i2 + 1;
                                                            ptr->field_10 = result;
                                                            if (result == ptr->field_0) {
                                                                sub_1400F3510(ptr);
                                                            }
                                                            result = ptr->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)i2 + 1) = 49;
                                                            result = i2 + 2;
                                                            ptr->field_10 = result;
                                                            if (result == ptr->field_0) {
                                                                sub_1400F3510(ptr);
                                                            }
                                                            result = ptr->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)i2 + 2) = 246;
                                                            i2 += 3;
                                                            ptr->field_10 = i2;
                                                            result = i3 + 21;
                                                            *dst = result;
                                                            sub_14002EDF0(0, 3);
                                                            if (result == 0) {
                                                                return (__int64)result;
                                                            }
                                                            i = (struct Struct_4_t *)result;
                                                            *result = 0x3948;
                                                            arg_2 = 206;
                                                            result = ptr->field_0;
                                                            a2 = ptr->field_10;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            v_40 = (__int64)ptr2;
                                                            if (result <= 2) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr, a2, 3, 1);
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
                                                            result = i3 + 22;
                                                            *dst = result;
                                                            i = ptr->field_10;
                                                            sub_14002EDF0(0, 6);
                                                            if (result != 0) {
                                                                ptr2 = (struct Struct_2_t *)result;
                                                                *result = 0x840F;
                                                                arg_2 = 0;
                                                                result = ptr->field_0;
                                                                a2 = ptr->field_10;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 5) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr, a2, 6, 1);
                                                                    a2 = ptr->field_10;
                                                                }
                                                                result = ptr->field_8;
                                                                a1 = ptr2->field_4;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                a1 = ptr2->field_0;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                a2 += 6;
                                                                ptr->field_10 = a2;
                                                                off_140108030(a1, a2);
                                                                off_140108038(result, 0, ptr2);
                                                                result = i3 + 23;
                                                                *dst = result;
                                                                sub_14002EDF0(0, 9);
                                                                if (result != 0) {
                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                    *result = 0xB60F;
                                                                    arg_2 = 28;
                                                                    result = ptr->field_0;
                                                                    a2 = ptr->field_10;
                                                                    ptr2->field_3 = 50;
                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                    if (result <= 3) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr, a2, 4, 1);
                                                                        a2 = ptr->field_10;
                                                                    }
                                                                    result = ptr->field_8;
                                                                    a1 = ptr2->field_0;
                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                    a2 += 4;
                                                                    ptr->field_10 = a2;
                                                                    off_140108030(a1, a2);
                                                                    off_140108038(result, 0, ptr2);
                                                                    sub_14002EDF0(0, 7);
                                                                    if (result != 0) {
                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                        *result = 0x41FB8348;
                                                                        result = ptr->field_0;
                                                                        a2 = ptr->field_10;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                        if (result <= 3) {
                                                                            v_20 = 1;
                                                                            sub_1400F2D20(ptr, a2, 4, 1);
                                                                            a2 = ptr->field_10;
                                                                        }
                                                                        result = ptr->field_8;
                                                                        a1 = ptr2->field_0;
                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                        a2 += 4;
                                                                        ptr->field_10 = a2;
                                                                        off_140108030(a1, a2);
                                                                        off_140108038(result, 0, ptr2);
                                                                        result = i3 + 25;
                                                                        *dst = result;
                                                                        ptr2 = ptr->field_10;
                                                                        sub_14002EDF0(0, 6);
                                                                        if (result != 0) {
                                                                            ptr3 = (struct Struct_3_t *)result;
                                                                            *result = 0x820F;
                                                                            arg_2 = 0;
                                                                            result = ptr->field_0;
                                                                            a2 = ptr->field_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                            if (result <= 5) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr, a2, 6, 1);
                                                                                a2 = ptr->field_10;
                                                                            }
                                                                            result = ptr->field_8;
                                                                            a1 = ptr3->field_4;
                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                            a1 = ptr3->field_0;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                            a2 += 6;
                                                                            ptr->field_10 = a2;
                                                                            off_140108030(a1, a2);
                                                                            off_140108038(result, 0, ptr3);
                                                                            sub_14002EDF0(0, 7);
                                                                            if (result != 0) {
                                                                                ptr3 = (struct Struct_3_t *)result;
                                                                                *result = 0x5AFB8348;
                                                                                result = ptr->field_0;
                                                                                a2 = ptr->field_10;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 3) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr, a2, 4, 1);
                                                                                    a2 = ptr->field_10;
                                                                                }
                                                                                v_30 = (__int64)src;
                                                                                result = ptr->field_8;
                                                                                a1 = ptr3->field_0;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 4;
                                                                                ptr->field_10 = a2;
                                                                                off_140108030(a1, a2);
                                                                                off_140108038(result, 0, ptr3);
                                                                                a1 = ptr->field_0;
                                                                                ptr3 = ptr->field_10;
                                                                                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                                                                                result = (__int64 *)ptr3;
                                                                                if (a1 <= 5) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr, ptr3, 6, 1);
                                                                                    result = ptr->field_10;
                                                                                }
                                                                                a1 = ptr->field_8;
                                                                                *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
                                                                                *(__int64 *)((__int64)a1 + (__int64)result) = 0x870F;
                                                                                result += 6;
                                                                                ptr->field_10 = result;
                                                                                result = i3 + 28;
                                                                                *dst = result;
                                                                                sub_14002EDF0(0, 7);
                                                                                if (result != 0) {
                                                                                    src = result;
                                                                                    *result = 0x20C38348;
                                                                                    result = ptr->field_0;
                                                                                    a2 = ptr->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                    if (result <= 3) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr, a2, 4, 1);
                                                                                        a2 = ptr->field_10;
                                                                                    }
                                                                                    result = ptr->field_8;
                                                                                    a1 = *src;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                    a2 += 4;
                                                                                    ptr->field_10 = a2;
                                                                                    off_140108030(a1, a2);
                                                                                    off_140108038(result, 0, src);
                                                                                    a2 = (size_t *)ptr2;
                                                                                    a2 += 6;
                                                                                    if (!((a2 < 0))) {
                                                                                        a3 = ptr->field_10;
                                                                                        result = (__int64 *)a3;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        a1 = (size_t *)result;
                                                                                        if (result == result) {
                                                                                            if (a3 < a2) {
                                                                                                return (__int64)a1;
                                                                                            }
                                                                                            a1 = ptr->field_8;
                                                                                            *(__int64 *)((__int64)a1 + (__int64)ptr2 + 2) = result;
                                                                                            a2 = (size_t *)ptr3;
                                                                                            a2 += 6;
                                                                                            if (!((a2 < 0))) {
                                                                                                a3 = (int *)((__int64)a3 - (__int64)a2);
                                                                                                result = (__int64 *)a3;
                                                                                                if (a3 == a3) {
                                                                                                    result = ptr->field_10;
                                                                                                    if (a2 > result) {
                                                                                                        return (__int64)result;
                                                                                                    }
                                                                                                    result = ptr->field_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr3 + 2) = a3;
                                                                                                    ptr2 = ptr->field_10;
                                                                                                    if (ptr2 == ptr->field_0) {
                                                                                                        sub_1400F3510(ptr);
                                                                                                    }
                                                                                                    result = ptr->field_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2) = 49;
                                                                                                    result = ptr2 + 1;
                                                                                                    ptr->field_10 = result;
                                                                                                    if (result == ptr->field_0) {
                                                                                                        sub_1400F3510(ptr);
                                                                                                    }
                                                                                                    result = ptr->field_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2 + 1) = 216;
                                                                                                    ptr2 += 2;
                                                                                                    ptr->field_10 = ptr2;
                                                                                                    result = i3 + 30;
                                                                                                    *dst = result;
                                                                                                    result = ptr->field_0;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                    if (result <= 5) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr, ptr2, 6, 1);
                                                                                                        ptr2 = ptr->field_10;
                                                                                                    }
                                                                                                    result = ptr->field_8;
                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2 + 4) = 256;
                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2) = 0x193C069;
                                                                                                    ptr2 += 6;
                                                                                                    ptr->field_10 = ptr2;
                                                                                                    sub_14002EDF0(0, 7, a3);
                                                                                                    if (result != 0) {
                                                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                                                        *result = 0x2C68348;
                                                                                                        result = ptr->field_0;
                                                                                                        a2 = ptr->field_10;
                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                        if (result <= 3) {
                                                                                                            v_20 = 1;
                                                                                                            sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                            a2 = ptr->field_10;
                                                                                                        }
                                                                                                        result = ptr->field_8;
                                                                                                        a1 = ptr2->field_0;
                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                        a2 += 4;
                                                                                                        ptr->field_10 = a2;
                                                                                                        off_140108030(a1, a2);
                                                                                                        off_140108038(result, 0, ptr2);
                                                                                                        result = i3 + 32;
                                                                                                        *dst = result;
                                                                                                        result = ptr->field_10;
                                                                                                        result += 5;
                                                                                                        if (!((result < 0))) {
                                                                                                            i2 = (__int64 *)((__int64)i2 - (__int64)result);
                                                                                                            result = i2;
                                                                                                            if (i2 == i2) {
                                                                                                                sub_14002EDF0(0, 5);
                                                                                                                if (result != 0) {
                                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                                    *result = 233;
                                                                                                                    arg_1 = (__int64)i2;
                                                                                                                    result = ptr->field_0;
                                                                                                                    a2 = ptr->field_10;
                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                    if (result <= 4) {
                                                                                                                        v_20 = 1;
                                                                                                                        sub_1400F2D20(ptr, a2, 5, 1);
                                                                                                                        a2 = ptr->field_10;
                                                                                                                    }
                                                                                                                    result = ptr->field_8;
                                                                                                                    a1 = ptr2->field_4;
                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                    a1 = ptr2->field_0;
                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                    a2 += 5;
                                                                                                                    ptr->field_10 = a2;
                                                                                                                    off_140108030(a1, a2);
                                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                                    a2 = (size_t *)i;
                                                                                                                    a2 += 6;
                                                                                                                    if (!((a2 < 0))) {
                                                                                                                        a3 = ptr->field_10;
                                                                                                                        result = (__int64 *)a3;
                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                        a1 = (size_t *)result;
                                                                                                                        i2 = (__int64 *)v_40;
                                                                                                                        if (result == result) {
                                                                                                                            if (a3 < a2) {
                                                                                                                                return (__int64)i2;
                                                                                                                            }
                                                                                                                            a1 = ptr->field_8;
                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)i + 2) = result;
                                                                                                                            a2 = ptr->field_10;
                                                                                                                            if (ptr->field_0 == a2) {
                                                                                                                                v_20 = 1;
                                                                                                                                sub_1400F2D20(ptr, a2, 1, 1);
                                                                                                                                a2 = ptr->field_10;
                                                                                                                            }
                                                                                                                            result = ptr->field_8;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 61;
                                                                                                                            ++a2;
                                                                                                                            ptr->field_10 = a2;
                                                                                                                            result = ptr->field_0;
                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                            if (result <= 3) {
                                                                                                                                v_20 = 1;
                                                                                                                                sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                a2 = ptr->field_10;
                                                                                                                            }
                                                                                                                            result = ptr->field_8;
                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xA3E6F6C3;
                                                                                                                            result = a2 + 4;
                                                                                                                            ptr->field_10 = result;
                                                                                                                            result = i3 + 34;
                                                                                                                            *dst = result;
                                                                                                                            a2 += 10;
                                                                                                                            if (!((a2 < 0))) {
                                                                                                                                i2 = (__int64 *)((__int64)i2 - (__int64)a2);
                                                                                                                                result = i2;
                                                                                                                                if (i2 == i2) {
                                                                                                                                    sub_14002EDF0(0, 6, a3);
                                                                                                                                    if (result != 0) {
                                                                                                                                        i = (struct Struct_4_t *)result;
                                                                                                                                        *result = 0x850F;
                                                                                                                                        arg_2 = (__int64)i2;
                                                                                                                                        result = ptr->field_0;
                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                        if (result <= 5) {
                                                                                                                                            v_20 = 1;
                                                                                                                                            sub_1400F2D20(ptr, a2, 6, 1);
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
                                                                                                                                        if (result != 0) {
                                                                                                                                            i = (struct Struct_4_t *)result;
                                                                                                                                            *result = 0x8B4D;
                                                                                                                                            arg_2 = 103;
                                                                                                                                            result = ptr->field_0;
                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                            i->field_3 = 48;
                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                            if (result <= 3) {
                                                                                                                                                v_20 = 1;
                                                                                                                                                sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                            }
                                                                                                                                            result = ptr->field_8;
                                                                                                                                            a1 = i->field_0;
                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                            a2 += 4;
                                                                                                                                            ptr->field_10 = a2;
                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                            result = i3 + 36;
                                                                                                                                            *dst = result;
                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                            if (result != 0) {
                                                                                                                                                i = (struct Struct_4_t *)result;
                                                                                                                                                *result = 0x246C8B45;
                                                                                                                                                result = ptr->field_0;
                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                i->field_4 = 60;
                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                if (result <= 4) {
                                                                                                                                                    v_20 = 1;
                                                                                                                                                    sub_1400F2D20(ptr, a2, 5, 1);
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
                                                                                                                                                i2 = ptr->field_10;
                                                                                                                                                result = i3 + 37;
                                                                                                                                                *dst = result;
                                                                                                                                                if (i2 == ptr->field_0) {
                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                }
                                                                                                                                                result = ptr->field_8;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2) = 77;
                                                                                                                                                result = i2 + 1;
                                                                                                                                                ptr->field_10 = result;
                                                                                                                                                if (result == ptr->field_0) {
                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                }
                                                                                                                                                result = ptr->field_8;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2 + 1) = 1;
                                                                                                                                                result = i2 + 2;
                                                                                                                                                ptr->field_10 = result;
                                                                                                                                                if (result == ptr->field_0) {
                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                }
                                                                                                                                                result = ptr->field_8;
                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2 + 2) = 229;
                                                                                                                                                i2 += 3;
                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                if (result != 0) {
                                                                                                                                                    i = (struct Struct_4_t *)result;
                                                                                                                                                    *result = 0x8B41;
                                                                                                                                                    arg_2 = 157;
                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                    i->field_3 = 136;
                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                    if (result <= 6) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        sub_1400F2D20(ptr, a2, 7, 1);
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
                                                                                                                                                    result = i3 + 39;
                                                                                                                                                    *dst = result;
                                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                                    if (result == 0) {
                                                                                                                                                        return (__int64)result;
                                                                                                                                                    }
                                                                                                                                                    i = (struct Struct_4_t *)result;
                                                                                                                                                    *result = 0x894D;
                                                                                                                                                    arg_2 = 229;
                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                    if (result <= 2) {
                                                                                                                                                        v_20 = 1;
                                                                                                                                                        sub_1400F2D20(ptr, a2, 3, 1);
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
                                                                                                                                                    i2 = ptr->field_10;
                                                                                                                                                    if (i2 == ptr->field_0) {
                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                    }
                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i2) = 73;
                                                                                                                                                    result = i2 + 1;
                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                    }
                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i2 + 1) = 1;
                                                                                                                                                    result = i2 + 2;
                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                    }
                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)i2 + 2) = 221;
                                                                                                                                                    i2 += 3;
                                                                                                                                                    ptr->field_10 = i2;
                                                                                                                                                    result = i3 + 41;
                                                                                                                                                    *dst = result;
                                                                                                                                                    sub_14002EDF0(0, 8);
                                                                                                                                                    if (result != 0) {
                                                                                                                                                        i = (struct Struct_4_t *)result;
                                                                                                                                                        *result = 0x8B41;
                                                                                                                                                        arg_2 = 109;
                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                        i->field_3 = 24;
                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                        if (result <= 3) {
                                                                                                                                                            v_20 = 1;
                                                                                                                                                            sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                        }
                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                        a1 = i->field_0;
                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                        a2 += 4;
                                                                                                                                                        ptr->field_10 = a2;
                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                        off_140108038(result, 0, i);
                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                        if (result != 0) {
                                                                                                                                                            i = (struct Struct_4_t *)result;
                                                                                                                                                            *result = 0x8B45;
                                                                                                                                                            arg_2 = 117;
                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                            i->field_3 = 28;
                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                v_20 = 1;
                                                                                                                                                                sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                            }
                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                            a1 = i->field_0;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                            a2 += 4;
                                                                                                                                                            ptr->field_10 = a2;
                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                            off_140108038(result, 0, i);
                                                                                                                                                            i2 = ptr->field_10;
                                                                                                                                                            result = i3 + 43;
                                                                                                                                                            *dst = result;
                                                                                                                                                            if (i2 == ptr->field_0) {
                                                                                                                                                                sub_1400F3510(ptr);
                                                                                                                                                            }
                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)i2) = 77;
                                                                                                                                                            result = i2 + 1;
                                                                                                                                                            ptr->field_10 = result;
                                                                                                                                                            if (result == ptr->field_0) {
                                                                                                                                                                sub_1400F3510(ptr);
                                                                                                                                                            }
                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)i2 + 1) = 1;
                                                                                                                                                            result = i2 + 2;
                                                                                                                                                            ptr->field_10 = result;
                                                                                                                                                            if (result == ptr->field_0) {
                                                                                                                                                                sub_1400F3510(ptr);
                                                                                                                                                            }
                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)i2 + 2) = 230;
                                                                                                                                                            i2 += 3;
                                                                                                                                                            ptr->field_10 = i2;
                                                                                                                                                            sub_14002EDF0(0, 8);
                                                                                                                                                            if (result != 0) {
                                                                                                                                                                i = (struct Struct_4_t *)result;
                                                                                                                                                                *result = 0x8B41;
                                                                                                                                                                arg_2 = 117;
                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                                i->field_3 = 32;
                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                if (result <= 3) {
                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                    sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                }
                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                a1 = i->field_0;
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                a2 += 4;
                                                                                                                                                                ptr->field_10 = a2;
                                                                                                                                                                off_140108030(a1, a2);
                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                i2 = ptr->field_10;
                                                                                                                                                                result = i3 + 45;
                                                                                                                                                                *dst = result;
                                                                                                                                                                if (i2 == ptr->field_0) {
                                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                                }
                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2) = 76;
                                                                                                                                                                result = i2 + 1;
                                                                                                                                                                ptr->field_10 = result;
                                                                                                                                                                if (result == ptr->field_0) {
                                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                                }
                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2 + 1) = 1;
                                                                                                                                                                result = i2 + 2;
                                                                                                                                                                ptr->field_10 = result;
                                                                                                                                                                if (result == ptr->field_0) {
                                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                                }
                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2 + 2) = 230;
                                                                                                                                                                i2 += 3;
                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                if (result != 0) {
                                                                                                                                                                    i = (struct Struct_4_t *)result;
                                                                                                                                                                    *result = 0x8B41;
                                                                                                                                                                    arg_2 = 125;
                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                    i->field_3 = 36;
                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                    if (result <= 3) {
                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                        sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    a1 = i->field_0;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                    a2 += 4;
                                                                                                                                                                    ptr->field_10 = a2;
                                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                                    off_140108038(result, 0, i);
                                                                                                                                                                    src = ptr->field_10;
                                                                                                                                                                    result = i3 + 47;
                                                                                                                                                                    *dst = result;
                                                                                                                                                                    if (src == ptr->field_0) {
                                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)src) = 76;
                                                                                                                                                                    result = src + 1;
                                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)src + 1) = 1;
                                                                                                                                                                    result = src + 2;
                                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)src + 2) = 231;
                                                                                                                                                                    result = src + 3;
                                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)src + 3) = 77;
                                                                                                                                                                    result = src + 4;
                                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)src + 4) = 49;
                                                                                                                                                                    result = src + 5;
                                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                                    if (result == ptr->field_0) {
                                                                                                                                                                        sub_1400F3510(ptr);
                                                                                                                                                                    }
                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)src + 5) = 237;
                                                                                                                                                                    src += 6;
                                                                                                                                                                    ptr->field_10 = src;
                                                                                                                                                                    result = i3 + 49;
                                                                                                                                                                    *dst = result;
                                                                                                                                                                    sub_14002EDF0(0, 3);
                                                                                                                                                                    if (result == 0) {
                                                                                                                                                                        return (__int64)result;
                                                                                                                                                                    }
                                                                                                                                                                    i = (struct Struct_4_t *)result;
                                                                                                                                                                    *result = 0x3949;
                                                                                                                                                                    arg_2 = 237;
                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                    if (result <= 2) {
                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                        sub_1400F2D20(ptr, a2, 3, 1);
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
                                                                                                                                                                    result = i3 + 50;
                                                                                                                                                                    *dst = result;
                                                                                                                                                                    i = ptr->field_10;
                                                                                                                                                                    sub_14002EDF0(0, 6);
                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                                                                                                                        *result = 0x840F;
                                                                                                                                                                        arg_2 = 0;
                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                        if (result <= 5) {
                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                            sub_1400F2D20(ptr, a2, 6, 1);
                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                        }
                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                        a1 = ptr2->field_4;
                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                        a1 = ptr2->field_0;
                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                        a2 += 6;
                                                                                                                                                                        ptr->field_10 = a2;
                                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                                        off_140108038(result, 0, ptr2);
                                                                                                                                                                        result = i3 + 51;
                                                                                                                                                                        *dst = result;
                                                                                                                                                                        sub_14002EDF0(0, 8);
                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                            ptr2 = (struct Struct_2_t *)result;
                                                                                                                                                                            *result = 0x8B42;
                                                                                                                                                                            arg_2 = 28;
                                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                            ptr2->field_3 = 174;
                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                                            }
                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                            a1 = ptr2->field_0;
                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                            a2 += 4;
                                                                                                                                                                            ptr->field_10 = a2;
                                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                                            off_140108038(result, 0, ptr2);
                                                                                                                                                                            ptr2 = ptr->field_10;
                                                                                                                                                                            result = i3 + 52;
                                                                                                                                                                            *dst = result;
                                                                                                                                                                            if (ptr2 == ptr->field_0) {
                                                                                                                                                                                sub_1400F3510(ptr);
                                                                                                                                                                            }
                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)ptr2) = 76;
                                                                                                                                                                            result = ptr2 + 1;
                                                                                                                                                                            ptr->field_10 = result;
                                                                                                                                                                            if (result == ptr->field_0) {
                                                                                                                                                                                sub_1400F3510(ptr);
                                                                                                                                                                            }
                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)ptr2 + 1) = 1;
                                                                                                                                                                            result = ptr2 + 2;
                                                                                                                                                                            ptr->field_10 = result;
                                                                                                                                                                            if (result == ptr->field_0) {
                                                                                                                                                                                sub_1400F3510(ptr);
                                                                                                                                                                            }
                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)ptr2 + 2) = 227;
                                                                                                                                                                            ptr2 += 3;
                                                                                                                                                                            ptr->field_10 = ptr2;
                                                                                                                                                                            sub_14002EDF0(0, 6);
                                                                                                                                                                            if (result != 0) {
                                                                                                                                                                                ptr3 = (struct Struct_3_t *)result;
                                                                                                                                                                                *result = 184;
                                                                                                                                                                                arg_1 = 0x811C9DC5;
                                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                if (result <= 4) {
                                                                                                                                                                                    v_20 = 1;
                                                                                                                                                                                    sub_1400F2D20(ptr, ptr2, 5, 1);
                                                                                                                                                                                    ptr2 = ptr->field_10;
                                                                                                                                                                                }
                                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                                a1 = ptr3->field_4;
                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)ptr2 + 4) = a1;
                                                                                                                                                                                a1 = ptr3->field_0;
                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)ptr2) = a1;
                                                                                                                                                                                ptr2 += 5;
                                                                                                                                                                                ptr->field_10 = ptr2;
                                                                                                                                                                                off_140108030(a1);
                                                                                                                                                                                off_140108038(result, 0, ptr3);
                                                                                                                                                                                result = i3 + 54;
                                                                                                                                                                                *dst = result;
                                                                                                                                                                                i2 = ptr->field_10;
                                                                                                                                                                                if (i2 == ptr->field_0) {
                                                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                                                }
                                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2) = 72;
                                                                                                                                                                                result = i2 + 1;
                                                                                                                                                                                ptr->field_10 = result;
                                                                                                                                                                                if (result == ptr->field_0) {
                                                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                                                }
                                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2 + 1) = 49;
                                                                                                                                                                                result = i2 + 2;
                                                                                                                                                                                ptr->field_10 = result;
                                                                                                                                                                                if (result == ptr->field_0) {
                                                                                                                                                                                    sub_1400F3510(ptr);
                                                                                                                                                                                }
                                                                                                                                                                                result = ptr->field_8;
                                                                                                                                                                                *(__int64 *)((__int64)result + (__int64)i2 + 2) = 201;
                                                                                                                                                                                i2 += 3;
                                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                                sub_14002EDF0(0, 9);
                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                                                                                                    *result = 0xB60F;
                                                                                                                                                                                    arg_2 = 20;
                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                                    ptr2->field_3 = 11;
                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                    if (result <= 3) {
                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                        sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                    }
                                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                                    a1 = ptr2->field_0;
                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                    a2 += 4;
                                                                                                                                                                                    ptr->field_10 = a2;
                                                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                    ptr2 = ptr->field_10;
                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr2);
                                                                                                                                                                                    if (result <= 1) {
                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                        sub_1400F2D20(ptr, ptr2, 2, 1);
                                                                                                                                                                                        ptr2 = ptr->field_10;
                                                                                                                                                                                    }
                                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)ptr2) = 0xD285;
                                                                                                                                                                                    result = ptr2 + 2;
                                                                                                                                                                                    ptr->field_10 = result;
                                                                                                                                                                                    result = i3 + 57;
                                                                                                                                                                                    *dst = result;
                                                                                                                                                                                    sub_14002EDF0(0, 6);
                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                        ptr3 = (struct Struct_3_t *)result;
                                                                                                                                                                                        *result = 0x840F;
                                                                                                                                                                                        arg_2 = 0;
                                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                        if (result <= 5) {
                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                            sub_1400F2D20(ptr, a2, 6, 1);
                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                        }
                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                        a1 = ptr3->field_4;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                        a1 = ptr3->field_0;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                        a2 += 6;
                                                                                                                                                                                        ptr->field_10 = a2;
                                                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                                                        off_140108038(result, 0, ptr3);
                                                                                                                                                                                        ptr3 = ptr->field_10;
                                                                                                                                                                                        if (ptr3 == ptr->field_0) {
                                                                                                                                                                                            sub_1400F3510(ptr);
                                                                                                                                                                                        }
                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr3) = 49;
                                                                                                                                                                                        result = ptr3 + 1;
                                                                                                                                                                                        ptr->field_10 = result;
                                                                                                                                                                                        if (result == ptr->field_0) {
                                                                                                                                                                                            sub_1400F3510(ptr);
                                                                                                                                                                                        }
                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr3 + 1) = 208;
                                                                                                                                                                                        ptr3 += 2;
                                                                                                                                                                                        ptr->field_10 = ptr3;
                                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr3);
                                                                                                                                                                                        if (result <= 5) {
                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                            sub_1400F2D20(ptr, ptr3, 6, 1);
                                                                                                                                                                                            ptr3 = ptr->field_10;
                                                                                                                                                                                        }
                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr3 + 4) = 256;
                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)ptr3) = 0x193C069;
                                                                                                                                                                                        ptr3 += 6;
                                                                                                                                                                                        ptr->field_10 = ptr3;
                                                                                                                                                                                        result = i3 + 60;
                                                                                                                                                                                        *dst = result;
                                                                                                                                                                                        sub_14002EDF0(0, 7);
                                                                                                                                                                                        if (result != 0) {
                                                                                                                                                                                            ptr3 = (struct Struct_3_t *)result;
                                                                                                                                                                                            *result = 0x1C18348;
                                                                                                                                                                                            result = ptr->field_0;
                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                            if (result <= 3) {
                                                                                                                                                                                                v_20 = 1;
                                                                                                                                                                                                sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                                                a2 = ptr->field_10;
                                                                                                                                                                                            }
                                                                                                                                                                                            result = ptr->field_8;
                                                                                                                                                                                            a1 = ptr3->field_0;
                                                                                                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                            a2 += 4;
                                                                                                                                                                                            ptr->field_10 = a2;
                                                                                                                                                                                            off_140108030(a1, a2);
                                                                                                                                                                                            off_140108038(result, 0, ptr3);
                                                                                                                                                                                            result = ptr->field_10;
                                                                                                                                                                                            result += 5;
                                                                                                                                                                                            if (!((result < 0))) {
                                                                                                                                                                                                i2 = (__int64 *)((__int64)i2 - (__int64)result);
                                                                                                                                                                                                result = i2;
                                                                                                                                                                                                if (i2 == i2) {
                                                                                                                                                                                                    sub_14002EDF0(0, 5);
                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                        ptr3 = (struct Struct_3_t *)result;
                                                                                                                                                                                                        *result = 233;
                                                                                                                                                                                                        arg_1 = (__int64)i2;
                                                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                        if (result <= 4) {
                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                            sub_1400F2D20(ptr, a2, 5, 1);
                                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                                        }
                                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                                        a1 = ptr3->field_4;
                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                        a1 = ptr3->field_0;
                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                        a2 += 5;
                                                                                                                                                                                                        ptr->field_10 = a2;
                                                                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                                                                        off_140108038(result, 0, ptr3);
                                                                                                                                                                                                        i3 += 62;
                                                                                                                                                                                                        *dst = i3;
                                                                                                                                                                                                        a2 = (size_t *)ptr2;
                                                                                                                                                                                                        a2 += 8;
                                                                                                                                                                                                        if (!((a2 < 0))) {
                                                                                                                                                                                                            a3 = ptr->field_10;
                                                                                                                                                                                                            result = (__int64 *)a3;
                                                                                                                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                            a1 = (size_t *)result;
                                                                                                                                                                                                            if (result == result) {
                                                                                                                                                                                                                if (a3 < a2) {
                                                                                                                                                                                                                    return (__int64)a1;
                                                                                                                                                                                                                }
                                                                                                                                                                                                                a1 = ptr->field_8;
                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)ptr2 + 4) = result;
                                                                                                                                                                                                                sub_1400DFDB0(ptr, dst, 0x820621F3, 32);
                                                                                                                                                                                                                sub_1400DFDB0(ptr, dst, 0x6D10460, 40);
                                                                                                                                                                                                                sub_1400DFDB0(ptr, dst, 0xF8F45725, 200);
                                                                                                                                                                                                                if (v_2f == 0) {
                                                                                                                                                                                                                    sub_14002EDF0(0, 7);
                                                                                                                                                                                                                    if (result != 0) {
                                                                                                                                                                                                                        ptr2 = (struct Struct_2_t *)result;
                                                                                                                                                                                                                        *result = 0x1C58349;
                                                                                                                                                                                                                        result = ptr->field_0;
                                                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                        if (result <= 3) {
                                                                                                                                                                                                                            v_20 = 1;
                                                                                                                                                                                                                            sub_1400F2D20(ptr, a2, 4, 1);
                                                                                                                                                                                                                            a2 = ptr->field_10;
                                                                                                                                                                                                                        }
                                                                                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                                                                                        a1 = ptr2->field_0;
                                                                                                                                                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                        a2 += 4;
                                                                                                                                                                                                                        ptr->field_10 = a2;
                                                                                                                                                                                                                        off_140108030(a1, a2);
                                                                                                                                                                                                                        off_140108038(result, 0, ptr2);
                                                                                                                                                                                                                        result = ptr->field_10;
                                                                                                                                                                                                                        result += 5;
                                                                                                                                                                                                                        if (!((result < 0))) {
                                                                                                                                                                                                                            src = (__int64 *)((__int64)src - (__int64)result);
                                                                                                                                                                                                                            result = src;
                                                                                                                                                                                                                            if (src == src) {
                                                                                                                                                                                                                                i3 = *dst;
                                                                                                                                                                                                                                sub_14002EDF0(0, 5);
                                                                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                                                                    ptr2 = (struct Struct_2_t *)result;
                                                                                                                                                                                                                                    *result = 233;
                                                                                                                                                                                                                                    arg_1 = (__int64)src;
                                                                                                                                                                                                                                    result = ptr->field_0;
                                                                                                                                                                                                                                    a2 = ptr->field_10;
                                                                                                                                                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                    if (result <= 4) {
                                                                                                                                                                                                                                        v_20 = 1;
                                                                                                                                                                                                                                        sub_1400F2D20(ptr, a2, 5, 1);
                                                                                                                                                                                                                                        a2 = ptr->field_10;
                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                    i2 = (__int64 *)v_30;
                                                                                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                                                                                    a1 = ptr2->field_4;
                                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                                                                                                                                                    a1 = ptr2->field_0;
                                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                                                                                                                                                    a2 += 5;
                                                                                                                                                                                                                                    ptr->field_10 = a2;
                                                                                                                                                                                                                                    off_140108030(a1, a2);
                                                                                                                                                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                                                                                                                                                    i3 += 2;
                                                                                                                                                                                                                                    *dst = i3;
                                                                                                                                                                                                                                    a2 = (size_t *)i;
                                                                                                                                                                                                                                    a2 += 6;
                                                                                                                                                                                                                                    if (!((a2 < 0))) {
                                                                                                                                                                                                                                        a3 = ptr->field_10;
                                                                                                                                                                                                                                        result = (__int64 *)a3;
                                                                                                                                                                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                        a1 = (size_t *)result;
                                                                                                                                                                                                                                        if (result == result) {
                                                                                                                                                                                                                                            if (a3 < a2) {
                                                                                                                                                                                                                                                return (__int64)a1;
                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                            a1 = ptr->field_8;
                                                                                                                                                                                                                                            *(__int64 *)((__int64)a1 + (__int64)i + 2) = result;
                                                                                                                                                                                                                                            a1 = (size_t *)v_38;
                                                                                                                                                                                                                                            a2 = a1;
                                                                                                                                                                                                                                            a2 += 6;
                                                                                                                                                                                                                                            if (!((a2 < 0))) {
                                                                                                                                                                                                                                                i2 = (__int64 *)((__int64)i2 - (__int64)a2);
                                                                                                                                                                                                                                                result = i2;
                                                                                                                                                                                                                                                if (i2 == i2) {
                                                                                                                                                                                                                                                    a3 = ptr->field_10;
                                                                                                                                                                                                                                                    if (a2 > a3) {
                                                                                                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                    result = ptr->field_8;
                                                                                                                                                                                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 2) = i2;
                                                                                                                                                                                                                                                    return (__int64)result;
                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                result = &off_14011CDC0;
                                                                                                                                                                                                                                                v_20 = (__int64)result;
                                                                                                                                                                                                                                                a1 = &off_14011CDA8;
                                                                                                                                                                                                                                                v5 = &off_14011D3F8;
                                                                                                                                                                                                                                                a3 = rsp + 46;
                                                                                                                                                                                                                                                sub_1400F3B80(a1, 20, a3, v5);
                                                                                                                                                                                                                                                ptr2 = (struct Struct_2_t *)v5;
                                                                                                                                                                                                                                                dst = (__int64 *)a2;
                                                                                                                                                                                                                                                ptr = (struct Struct_1_t *)a1;
                                                                                                                                                                                                                                                result = *a1;
                                                                                                                                                                                                                                                i3 = a1[2];
                                                                                                                                                                                                                                                if (result == i3) JUMPOUT(0x1400e0039);
                                                                                                                                                                                                                                                ptr3 = ptr->field_8;
                                                                                                                                                                                                                                                *(__int64 *)(ptr3 + i3) = (__int64)(61);
                                                                                                                                                                                                                                                ++i3;
                                                                                                                                                                                                                                                ptr->field_10 = i3;
                                                                                                                                                                                                                                                result -= i3;
                                                                                                                                                                                                                                                if (result <= 3) JUMPOUT(0x1400e0071);
                                                                                                                                                                                                                                                *(__int64 *)(ptr3 + i3) = (__int64)(a3);
                                                                                                                                                                                                                                                i2 = i3 + 4;
                                                                                                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                                                                                                src = *dst;
                                                                                                                                                                                                                                                sub_14002EDF0(0, 6);
                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1400e015d);
                                                                                                                                                                                                                                                i = (struct Struct_4_t *)result;
                                                                                                                                                                                                                                                *result = 0x850F;
                                                                                                                                                                                                                                                arg_2 = 0;
                                                                                                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                                                                                                                                                                                if (result <= 5) JUMPOUT(0x1400e00aa);
                                                                                                                                                                                                                                                result = i->field_4;
                                                                                                                                                                                                                                                *(__int64 *)((__int64)ptr3 + (__int64)i2 + 4) = result;
                                                                                                                                                                                                                                                result = i->field_0;
                                                                                                                                                                                                                                                *(__int64 *)((__int64)ptr3 + (__int64)i2) = result;
                                                                                                                                                                                                                                                i2 += 6;
                                                                                                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                                                                                                off_140108030();
                                                                                                                                                                                                                                                off_140108038(result, 0, i);
                                                                                                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                                                                                                a1 = (size_t *)result;
                                                                                                                                                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)i2);
                                                                                                                                                                                                                                                if (a1 <= 4) JUMPOUT(0x1400e00d7);
                                                                                                                                                                                                                                                a1 = ptr->field_8;
                                                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)i2 + 4) = 111;
                                                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)i2) = 0xCB70F4A;
                                                                                                                                                                                                                                                i2 += 5;
                                                                                                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                                                                                                a2 = src + 3;
                                                                                                                                                                                                                                                *dst = a2;
                                                                                                                                                                                                                                                a2 = (size_t *)result;
                                                                                                                                                                                                                                                a2 = (size_t *)((__int64)a2 - (__int64)i2);
                                                                                                                                                                                                                                                if (a2 <= 3) JUMPOUT(0x1400e0103);
                                                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)i2) = 0x8E148B41;
                                                                                                                                                                                                                                                a2 = i2 + 4;
                                                                                                                                                                                                                                                ptr->field_10 = a2;
                                                                                                                                                                                                                                                if (a2 == result) JUMPOUT(0x1400dfff1);
                                                                                                                                                                                                                                                *(__int64 *)((__int64)a1 + (__int64)i2 + 4) = 76;
                                                                                                                                                                                                                                                a1 = i2 + 5;
                                                                                                                                                                                                                                                ptr->field_10 = a1;
                                                                                                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                                                                                                if (a1 == result) JUMPOUT(0x1400e0002);
                                                                                                                                                                                                                                                i = ptr->field_8;
                                                                                                                                                                                                                                                *(__int64 *)((__int64)i + (__int64)i2 + 5) = 1;
                                                                                                                                                                                                                                                a1 = i2 + 6;
                                                                                                                                                                                                                                                ptr->field_10 = a1;
                                                                                                                                                                                                                                                if (a1 == result) JUMPOUT(0x1400e0012);
                                                                                                                                                                                                                                                *(__int64 *)((__int64)i + (__int64)i2 + 6) = 226;
                                                                                                                                                                                                                                                i2 += 7;
                                                                                                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                                                                                                result = src + 5;
                                                                                                                                                                                                                                                v_40 = (__int64)dst;
                                                                                                                                                                                                                                                *dst = result;
                                                                                                                                                                                                                                                sub_14002EDF0(0, 8);
                                                                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1400e016c);
                                                                                                                                                                                                                                                v_28 = 8;
                                                                                                                                                                                                                                                v_30 = (__int64)result;
                                                                                                                                                                                                                                                *result = 0x8948;
                                                                                                                                                                                                                                                v_38 = 2;
                                                                                                                                                                                                                                                a1 = rsp + 40;
                                                                                                                                                                                                                                                sub_1400D4F50(a1, 2, 4, ptr2);
                                                                                                                                                                                                                                                dst = (__int64 *)v_28;
                                                                                                                                                                                                                                                ptr2 = (struct Struct_2_t *)v_30;
                                                                                                                                                                                                                                                ptr3 = (struct Struct_3_t *)v_38;
                                                                                                                                                                                                                                                result = ptr->field_0;
                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)i2);
                                                                                                                                                                                                                                                if (ptr3 > result) JUMPOUT(0x1400e0133);
                                                                                                                                                                                                                                                i = (struct Struct_4_t *)((__int64)i + (__int64)i2);
                                                                                                                                                                                                                                                sub_1400F27F0(i, ptr2, ptr3);
                                                                                                                                                                                                                                                i2 = (__int64 *)((__int64)i2 + (__int64)ptr3);
                                                                                                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                                                                                                if (dst != 0) {
                                                                                                                                                                                                                                                    off_140108030();
                                                                                                                                                                                                                                                    off_140108038(result, 0, ptr2);
                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                src += 6;
                                                                                                                                                                                                                                                result = (__int64 *)v_40;
                                                                                                                                                                                                                                                *result = src;
                                                                                                                                                                                                                                                a2 = (size_t *)i3;
                                                                                                                                                                                                                                                a2 += 10;
                                                                                                                                                                                                                                                if ((a2 < 0)) JUMPOUT(0x1400e017b);
                                                                                                                                                                                                                                                result = i2;
                                                                                                                                                                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                                                                                                                                                                a1 = (size_t *)result;
                                                                                                                                                                                                                                                if (result != result) JUMPOUT(0x1400e01a4);
                                                                                                                                                                                                                                                if (i2 < a2) JUMPOUT(0x1400e0023);
                                                                                                                                                                                                                                                a1 = ptr->field_8;
                                                                                                                                                                                                                                                *(a1 + i3 + 6) = result;
                                                                                                                                                                                                                                                return (__int64)a1;
                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                            result = &off_14011B3E0;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011B3C3;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 23, a3, v5);
                                                                                                                                                                                                                                            sub_1400F3326(1, 6);
                                                                                                                                                                                                                                            sub_1400F3326(1, 7);
                                                                                                                                                                                                                                            sub_1400F3326(1, 5);
                                                                                                                                                                                                                                            sub_1400F3326(1, 9);
                                                                                                                                                                                                                                            result = &off_14011CB00;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011CAE8;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 17, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C6A8;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C6A0;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 6, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C6C8;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C6C0;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 6, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C6F0;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C6E0;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 13, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C718;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C708;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 13, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C740;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C730;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 15, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C3F8;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C3E8;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 12, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011C428;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011C410;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 17, a3, v5);
                                                                                                                                                                                                                                            result = &off_14011CD68;
                                                                                                                                                                                                                                            v_20 = (__int64)result;
                                                                                                                                                                                                                                            a1 = &off_14011CD58;
                                                                                                                                                                                                                                            v5 = &off_14011D3F8;
                                                                                                                                                                                                                                            a3 = rsp + 46;
                                                                                                                                                                                                                                            sub_1400F3B80(a1, 15, a3, v5);
                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                        result = &off_14011CD90;
                                                                                                                                                                                                                                        v_20 = (__int64)result;
                                                                                                                                                                                                                                        a1 = &off_14011CD80;
                                                                                                                                                                                                                                        v5 = &off_14011D3F8;
                                                                                                                                                                                                                                        a3 = rsp + 46;
                                                                                                                                                                                                                                        sub_1400F3B80(a1, 15, a3, v5);
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
                                                                                                                                                                                                                sub_1400DFDB0(ptr, dst, 0xC3D48B63, 248);
                                                                                                                                                                                                                sub_1400DFDB0(ptr, dst, 0x54FCC943, 256);
                                                                                                                                                                                                                sub_1400DFDB0(ptr, dst, 0xFABA0065, 264);
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
                                                                                                                                                                        sub_1400F3326(1, 8);
                                                                                                                                                                        return (__int64)a3;
                                                                                                                                                                    }
                                                                                                                                                                    return (__int64)a3;
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
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
                                                                            return (__int64)a3;
                                                                        }
                                                                        return (__int64)a3;
                                                                    }
                                                                    return (__int64)a3;
                                                                }
                                                                return (__int64)a3;
                                                            }
                                                        }
                                                        return (__int64)a3;
                                                    }
                                                }
                                                return (__int64)a3;
                                            }
                                            return (__int64)a3;
                                        }
                                    }
                                }
                            }
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
    return (__int64)result;
}