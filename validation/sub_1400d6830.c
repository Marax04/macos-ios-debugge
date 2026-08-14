// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    char field_3; // offset 3
    __int16 field_4; // offset 4
    char _pad_4[1];
    __int64 field_7; // offset 7
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400D9BD0();
__int64 sub_1400DAC20();
__int64 sub_1400F3326();
__int64 sub_1400F3B80();
__int64 sub_1400D9C1A();
__int64 sub_1400DAEC0();
__int64 sub_1400F3340();
__int64 sub_1400DA120();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011CAD0;
extern __int64 off_14011CAB8;

__int64 __fastcall sub_1400D6830(size_t *a1, int *a2, int a3, int *a4) {
    __int64 rsp;
    int arg_1;
    int arg_2;
    int arg_3;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    int v_44;
    __int64 v_48;
    __int64 v_50;
    int v_58;
    __int64 v_60;
    int v_d0;
    int v_d8;
    int v_e0;
    __int64 *dst;
    __int64 *dst2;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 *dst3;
    __int64 i;
    __int64 v7;
    __int64 *dst4;
    __int64 v6;
    __int64 v5;

    dst = (__int64 *)a4;
    v_48 = a3;
    dst2 = (__int64 *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        ptr = (struct Struct_1_t *)result;
        *result = 0x24648B4C;
        result = ptr2->field_0;
        a2 = ptr2->field_10;
        ptr->field_4 = 56;
        result = (__int64 *)((__int64)result - (__int64)a2);
        v_60 = (__int64)dst;
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
        dst = *dst2;
        result = dst + 1;
        *dst2 = result;
        sub_14002EDF0(0, 8);
        ptr = (struct Struct_1_t *)result;
        *result = 0x24748B4C;
        result = ptr2->field_0;
        a2 = ptr2->field_10;
        ptr->field_4 = 64;
        result = (__int64 *)((__int64)result - (__int64)a2);
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
        result = dst + 2;
        *dst2 = result;
        sub_14002EDF0(0, 7);
        if (result != 0) {
            ptr = (struct Struct_1_t *)result;
            *result = 0x8148;
            arg_3 = 320;
            arg_2 = 236;
            result = ptr2->field_0;
            a2 = ptr2->field_10;
            result = (__int64 *)((__int64)result - (__int64)a2);
            if (result <= 6) {
                v_20 = 1;
                sub_1400F2D20(ptr2, a2, 7, 1);
                a2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            a1 = ptr->field_0;
            a3 = ptr->field_3;
            *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
            *(__int64 *)((__int64)result + (__int64)a2) = a1;
            a2 += 7;
            ptr2->field_10 = a2;
            off_140108030(a1, a2, a3);
            off_140108038(result, 0, ptr);
            result = dst + 3;
            *dst2 = result;
            dst3 = 536;
            i = rsp + 40;
            v_40 = (__int64)dst2;
            do {
                sub_14002EDF0(0, 8);
                v_28 = 8;
                v_30 = (__int64)result;
                *result = 0x8B48;
                v_38 = 2;
                sub_1400D4F50(i, 0, 4, dst3);
                v7 = v_28;
                ptr = (struct Struct_1_t *)v_30;
                dst2 = (__int64 *)v_38;
                result = ptr2->field_0;
                dst4 = ptr2->field_10;
                result = (__int64 *)((__int64)result - (__int64)dst4);
                if (dst2 > result) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, dst4, dst2, 1);
                    dst4 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                sub_1400F27F0(a1, ptr, dst2);
                dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                ptr2->field_10 = dst4;
                if (v7 == 0) {
                    result = dst + 4;
                    a1 = (size_t *)v_40;
                    *a1 = result;
                    sub_14002EDF0(0, 8);
                    a4 = dst3 - 472;
                    v_28 = 8;
                    v_30 = (__int64)result;
                    *result = 0x8948;
                    v_38 = 2;
                    sub_1400D4F50(i, 0, 4, a4);
                    v7 = v_28;
                    ptr = (struct Struct_1_t *)v_30;
                    dst2 = (__int64 *)v_38;
                    result = ptr2->field_0;
                    dst4 = ptr2->field_10;
                    result = (__int64 *)((__int64)result - (__int64)dst4);
                    if (dst2 > result) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, dst4, dst2, 1);
                        dst4 = ptr2->field_10;
                    }
                    a1 = ptr2->field_8;
                    a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                    sub_1400F27F0(a1, ptr, dst2);
                    dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                    ptr2->field_10 = dst4;
                    if (v7 == 0) {
                        result = dst + 5;
                        dst2 = (__int64 *)v_40;
                        *dst2 = result;
                        dst += 2;
                        dst3 += 8;
                        sub_14002EDF0(0, 3);
                        ptr = (struct Struct_1_t *)result;
                        *result = 0x3148;
                        arg_2 = 192;
                        result = ptr2->field_0;
                        a2 = ptr2->field_10;
                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                        result = dst + 4;
                        *dst2 = result;
                        sub_14002EDF0(0, 8);
                        ptr = (struct Struct_1_t *)result;
                        *result = 0x247C8D48;
                        result = ptr2->field_0;
                        a2 = ptr2->field_10;
                        ptr->field_4 = 96;
                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                        result = dst + 5;
                        *dst2 = result;
                        sub_14002EDF0(0, 6);
                        if (result != 0) {
                            ptr = (struct Struct_1_t *)result;
                            *result = 185;
                            arg_1 = 64;
                            result = ptr2->field_0;
                            a2 = ptr2->field_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                            result = ptr2->field_0;
                            a2 = ptr2->field_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 2) {
                                v_20 = 1;
                                sub_1400F2D20(ptr2, a2, 3, 1);
                                a2 = ptr2->field_10;
                            }
                            v7 = dst + 4;
                            result = ptr2->field_8;
                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 170;
                            *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                            a2 += 3;
                            ptr2->field_10 = a2;
                            dst += 7;
                            *dst2 = dst;
                            dst3 = 64;
                            i = rsp + 40;
                            do {
                                sub_14002EDF0(0, 8);
                                v_28 = 8;
                                v_30 = (__int64)result;
                                *result = 0x8B48;
                                v_38 = 2;
                                sub_1400D4F50(i, 0, 4, dst3);
                                dst = (__int64 *)v_28;
                                ptr = (struct Struct_1_t *)v_30;
                                dst2 = (__int64 *)v_38;
                                result = ptr2->field_0;
                                dst4 = ptr2->field_10;
                                result = (__int64 *)((__int64)result - (__int64)dst4);
                                if (dst2 > result) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, dst4, dst2, 1);
                                    dst4 = ptr2->field_10;
                                }
                                a1 = ptr2->field_8;
                                a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                                sub_1400F27F0(a1, ptr, dst2);
                                dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                                ptr2->field_10 = dst4;
                                if (dst == 0) {
                                    result = v7 + 4;
                                    a1 = (size_t *)v_40;
                                    *a1 = result;
                                    sub_14002EDF0(0, 8);
                                    a4 = dst3 + 32;
                                    v_28 = 8;
                                    v_30 = (__int64)result;
                                    *result = 0x8948;
                                    v_38 = 2;
                                    sub_1400D4F50(i, 0, 4, a4);
                                    dst = (__int64 *)v_28;
                                    ptr = (struct Struct_1_t *)v_30;
                                    dst2 = (__int64 *)v_38;
                                    result = ptr2->field_0;
                                    dst4 = ptr2->field_10;
                                    result = (__int64 *)((__int64)result - (__int64)dst4);
                                    if (dst2 > result) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr2, dst4, dst2, 1);
                                        dst4 = ptr2->field_10;
                                    }
                                    a1 = ptr2->field_8;
                                    a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                                    sub_1400F27F0(a1, ptr, dst2);
                                    dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                                    ptr2->field_10 = dst4;
                                    if (dst == 0) {
                                        result = v7 + 5;
                                        dst = (__int64 *)v_40;
                                        *dst = result;
                                        dst3 += 8;
                                        v7 += 2;
                                        sub_14002EDF0(0, 11);
                                        if (result != 0) {
                                            ptr = (struct Struct_1_t *)result;
                                            *result = 0x84C7;
                                            arg_2 = 36;
                                            result = 0x6870797A00000080;
                                            ptr->field_3 = result;
                                            result = ptr2->field_0;
                                            a2 = ptr2->field_10;
                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                            if (result < 11) {
                                                v_20 = 1;
                                                sub_1400F2D20(ptr2, a2, 11, 1);
                                                a2 = ptr2->field_10;
                                            }
                                            result = ptr2->field_8;
                                            a1 = ptr->field_7;
                                            *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                            a1 = ptr->field_0;
                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                            a2 += 11;
                                            ptr2->field_10 = a2;
                                            off_140108030(a1, a2);
                                            off_140108038(result, 0, ptr);
                                            sub_14002EDF0(0, 11);
                                            if (result != 0) {
                                                ptr = (struct Struct_1_t *)result;
                                                *result = 0x84C7;
                                                arg_2 = 36;
                                                result = 0x2E61726F00000084;
                                                ptr->field_3 = result;
                                                result = ptr2->field_0;
                                                a2 = ptr2->field_10;
                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                if (result <= 10) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, a2, 11, 1);
                                                    a2 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                a1 = ptr->field_7;
                                                *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                a1 = ptr->field_0;
                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                a2 += 11;
                                                ptr2->field_10 = a2;
                                                off_140108030(a1, a2);
                                                off_140108038(result, 0, ptr);
                                                result = v7 + 5;
                                                *dst = result;
                                                sub_14002EDF0(0, 11);
                                                if (result != 0) {
                                                    ptr = (struct Struct_1_t *)result;
                                                    *result = 0x84C7;
                                                    arg_2 = 36;
                                                    result = 0x7478657400000088;
                                                    ptr->field_3 = result;
                                                    result = ptr2->field_0;
                                                    a2 = ptr2->field_10;
                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                    if (result <= 10) {
                                                        v_20 = 1;
                                                        sub_1400F2D20(ptr2, a2, 11, 1);
                                                        a2 = ptr2->field_10;
                                                    }
                                                    result = ptr2->field_8;
                                                    a1 = ptr->field_7;
                                                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                    a1 = ptr->field_0;
                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                    a2 += 11;
                                                    ptr2->field_10 = a2;
                                                    off_140108030(a1, a2);
                                                    off_140108038(result, 0, ptr);
                                                    sub_14002EDF0(0, 11);
                                                    if (result != 0) {
                                                        ptr = (struct Struct_1_t *)result;
                                                        *result = 0x84C7;
                                                        arg_2 = 36;
                                                        result = 0x63616D2E0000008C;
                                                        ptr->field_3 = result;
                                                        result = ptr2->field_0;
                                                        a2 = ptr2->field_10;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 10) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 11, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        a1 = ptr->field_7;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                        a1 = ptr->field_0;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                        a2 += 11;
                                                        ptr2->field_10 = a2;
                                                        off_140108030(a1, a2);
                                                        off_140108038(result, 0, ptr);
                                                        a2 = ptr2->field_10;
                                                        result = v7 + 7;
                                                        *dst = result;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result < 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x84C6;
                                                        a2 += 3;
                                                        ptr2->field_10 = a2;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 4, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 144;
                                                        a2 += 4;
                                                        ptr2->field_10 = a2;
                                                        if (ptr2->field_0 == a2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 1, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 46;
                                                        ++a2;
                                                        ptr2->field_10 = a2;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x84C6;
                                                        a2 += 3;
                                                        ptr2->field_10 = a2;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 4, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 145;
                                                        a2 += 4;
                                                        ptr2->field_10 = a2;
                                                        if (ptr2->field_0 == a2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 1, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 118;
                                                        ++a2;
                                                        ptr2->field_10 = a2;
                                                        result = v7 + 9;
                                                        *dst = result;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x84C6;
                                                        a2 += 3;
                                                        ptr2->field_10 = a2;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 4, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 146;
                                                        a2 += 4;
                                                        ptr2->field_10 = a2;
                                                        if (ptr2->field_0 == a2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 1, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 49;
                                                        ++a2;
                                                        ptr2->field_10 = a2;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result < 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x84C6;
                                                        a2 += 3;
                                                        ptr2->field_10 = a2;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (result <= 3) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 4, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 147;
                                                        a2 += 4;
                                                        ptr2->field_10 = a2;
                                                        if (ptr2->field_0 == a2) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, a2, 1, 1);
                                                            a2 = ptr2->field_10;
                                                        }
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 128;
                                                        ++a2;
                                                        ptr2->field_10 = a2;
                                                        result = v7 + 11;
                                                        *dst = result;
                                                        sub_14002EDF0(0, 11);
                                                        if (result != 0) {
                                                            ptr = (struct Struct_1_t *)result;
                                                            *result = 0x84C7;
                                                            arg_2 = 36;
                                                            arg_3 = 152;
                                                            result = ptr2->field_0;
                                                            a2 = ptr2->field_10;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 10) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 11, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            result = ptr2->field_8;
                                                            a1 = ptr->field_7;
                                                            *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                            a1 = ptr->field_0;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                            a2 += 11;
                                                            ptr2->field_10 = a2;
                                                            off_140108030(a1, a2);
                                                            off_140108038(result, 0, ptr);
                                                            sub_14002EDF0(0, 11);
                                                            if (result != 0) {
                                                                ptr = (struct Struct_1_t *)result;
                                                                *result = 0x84C7;
                                                                arg_2 = 36;
                                                                result = 0x980100000000009C;
                                                                ptr->field_3 = result;
                                                                result = ptr2->field_0;
                                                                a2 = ptr2->field_10;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 10) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr2, a2, 11, 1);
                                                                    a2 = ptr2->field_10;
                                                                }
                                                                result = ptr2->field_8;
                                                                a1 = ptr->field_7;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                                a1 = ptr->field_0;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                a2 += 11;
                                                                ptr2->field_10 = a2;
                                                                off_140108030(a1, a2);
                                                                off_140108038(result, 0, ptr);
                                                                v7 += 13;
                                                                *dst = v7;
                                                                a3 = v_e0;
                                                                sub_1400D9BD0(ptr2, dst, a3);
                                                                a3 = v_d0;
                                                                sub_1400DAC20(ptr2, dst, a3, 96);
                                                                dst = *dst;
                                                                i = 32;
                                                                v7 = 0;
                                                                do {
                                                                    sub_14002EDF0(0, 8);
                                                                    v_28 = 8;
                                                                    v_30 = (__int64)result;
                                                                    *result = 139;
                                                                    v_38 = 1;
                                                                    a1 = rsp + 40;
                                                                    sub_1400D4F50(a1, 0, 4, i);
                                                                    dst3 = (__int64 *)v_28;
                                                                    ptr = (struct Struct_1_t *)v_30;
                                                                    dst2 = (__int64 *)v_38;
                                                                    result = ptr2->field_0;
                                                                    dst4 = ptr2->field_10;
                                                                    result = (__int64 *)((__int64)result - (__int64)dst4);
                                                                    if (dst2 > result) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr2, dst4, dst2, 1);
                                                                        dst4 = ptr2->field_10;
                                                                    }
                                                                    a1 = ptr2->field_8;
                                                                    a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                                                                    sub_1400F27F0(a1, ptr, dst2);
                                                                    dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                                                                    ptr2->field_10 = dst4;
                                                                    if (dst3 == 0) {
                                                                        result = dst + v7;
                                                                        ++result;
                                                                        a1 = (size_t *)v_40;
                                                                        *a1 = result;
                                                                        sub_14002EDF0(0, 3);
                                                                        if (result != 0) {
                                                                            ptr = (struct Struct_1_t *)result;
                                                                            *result = 0xC80F;
                                                                            result = ptr2->field_0;
                                                                            a2 = ptr2->field_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                            sub_14002EDF0(0, 8);
                                                                            a4 = i + 32;
                                                                            v_28 = 8;
                                                                            v_30 = (__int64)result;
                                                                            *result = 137;
                                                                            v_38 = 1;
                                                                            a1 = rsp + 40;
                                                                            sub_1400D4F50(a1, 0, 4, a4);
                                                                            v6 = v_28;
                                                                            ptr = (struct Struct_1_t *)v_30;
                                                                            dst2 = (__int64 *)v_38;
                                                                            result = ptr2->field_0;
                                                                            dst4 = ptr2->field_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)dst4);
                                                                            if (dst2 > result) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, dst4, dst2, 1);
                                                                                dst4 = ptr2->field_10;
                                                                            }
                                                                            a1 = ptr2->field_8;
                                                                            a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                                                                            sub_1400F27F0(a1, ptr, dst2);
                                                                            dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                                                                            ptr2->field_10 = dst4;
                                                                            if (v6 == 0) {
                                                                                ptr = dst + v7;
                                                                                ptr += 3;
                                                                                dst3 = (__int64 *)v_40;
                                                                                *dst3 = ptr;
                                                                                v7 += 3;
                                                                                i += 4;
                                                                                result = ptr2->field_0;
                                                                                a2 = ptr2->field_10;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 1) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 2, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xB848;
                                                                                a2 += 2;
                                                                                ptr2->field_10 = a2;
                                                                                result = ptr2->field_0;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 7) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 8, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                a1 = 0x9E3779B97F4A7C15;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 8;
                                                                                ptr2->field_10 = a2;
                                                                                result = ptr2->field_0;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 1) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 2, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xBB48;
                                                                                a2 += 2;
                                                                                ptr2->field_10 = a2;
                                                                                result = ptr2->field_0;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 7) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 8, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                ptr -= 3;
                                                                                result = ptr2->field_8;
                                                                                a1 = 0xA8014F8F497C4A23;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 8;
                                                                                ptr2->field_10 = a2;
                                                                                result = ptr2->field_0;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 2) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 195;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                                                                                a2 += 3;
                                                                                ptr2->field_10 = a2;
                                                                                ptr += 6;
                                                                                *dst3 = ptr;
                                                                                dst += v7;
                                                                                dst3 = 96;
                                                                                result = 0;
                                                                                do {
                                                                                    v7 = (__int64)result;
                                                                                    sub_14002EDF0(0, 8);
                                                                                    a4 = dst3 - 32;
                                                                                    v_28 = 8;
                                                                                    v_30 = (__int64)result;
                                                                                    *result = 0x8B48;
                                                                                    v_38 = 2;
                                                                                    a1 = rsp + 40;
                                                                                    sub_1400D4F50(a1, 0, 4, a4);
                                                                                    i = v_28;
                                                                                    dst2 = (__int64 *)v_30;
                                                                                    dst4 = (__int64 *)v_38;
                                                                                    result = ptr2->field_0;
                                                                                    ptr = ptr2->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)ptr);
                                                                                    if (dst4 > result) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr2, ptr, dst4, 1);
                                                                                        ptr = ptr2->field_10;
                                                                                    }
                                                                                    a1 = ptr2->field_8;
                                                                                    a1 = (size_t *)((__int64)a1 + (__int64)ptr);
                                                                                    sub_1400F27F0(a1, dst2, dst4);
                                                                                    ptr = (struct Struct_1_t *)((__int64)ptr + (__int64)dst4);
                                                                                    ptr2->field_10 = ptr;
                                                                                    if (i == 0) {
                                                                                        result = ptr2->field_0;
                                                                                        result = (__int64 *)((__int64)result - (__int64)ptr);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(ptr2, ptr, 3, 1);
                                                                                            ptr = ptr2->field_10;
                                                                                        }
                                                                                        a1 = (size_t *)v_40;
                                                                                        result = ptr2->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 216;
                                                                                        *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                                                                                        ptr += 3;
                                                                                        ptr2->field_10 = ptr;
                                                                                        result = dst + v7;
                                                                                        result += 5;
                                                                                        *a1 = result;
                                                                                        sub_14002EDF0(0, 8);
                                                                                        v_28 = 8;
                                                                                        v_30 = (__int64)result;
                                                                                        *result = 0x8948;
                                                                                        v_38 = 2;
                                                                                        a1 = rsp + 40;
                                                                                        sub_1400D4F50(a1, 0, 4, dst3);
                                                                                        i = v_28;
                                                                                        ptr = (struct Struct_1_t *)v_30;
                                                                                        dst2 = (__int64 *)v_38;
                                                                                        result = ptr2->field_0;
                                                                                        dst4 = ptr2->field_10;
                                                                                        result = (__int64 *)((__int64)result - (__int64)dst4);
                                                                                        if (dst2 > result) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(ptr2, dst4, dst2, 1);
                                                                                            dst4 = ptr2->field_10;
                                                                                        }
                                                                                        a1 = ptr2->field_8;
                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)dst4);
                                                                                        sub_1400F27F0(a1, ptr, dst2);
                                                                                        dst4 = (__int64 *)((__int64)dst4 + (__int64)dst2);
                                                                                        ptr2->field_10 = dst4;
                                                                                        if (i == 0) {
                                                                                            result = dst + v7;
                                                                                            result += 6;
                                                                                            dst2 = (__int64 *)v_40;
                                                                                            *dst2 = result;
                                                                                            result = v7 + 3;
                                                                                            dst3 += 8;
                                                                                            sub_14002EDF0(0, 8);
                                                                                            ptr = (struct Struct_1_t *)result;
                                                                                            dst += v7;
                                                                                            dst += 2;
                                                                                            *result = 0x249C8948;
                                                                                            result = ptr2->field_0;
                                                                                            a2 = ptr2->field_10;
                                                                                            ptr->field_4 = 128;
                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                            result = dst + 5;
                                                                                            *dst2 = result;
                                                                                            sub_14002EDF0(0, 8);
                                                                                            ptr = (struct Struct_1_t *)result;
                                                                                            *result = 0x249C8948;
                                                                                            result = ptr2->field_0;
                                                                                            a2 = ptr2->field_10;
                                                                                            ptr->field_4 = 136;
                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                            result = dst + 6;
                                                                                            *dst2 = result;
                                                                                            sub_14002EDF0(0, 8);
                                                                                            ptr = (struct Struct_1_t *)result;
                                                                                            *result = 0x249C8948;
                                                                                            result = ptr2->field_0;
                                                                                            a2 = ptr2->field_10;
                                                                                            ptr->field_4 = 144;
                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                            result = dst + 7;
                                                                                            *dst2 = result;
                                                                                            sub_14002EDF0(0, 8);
                                                                                            ptr = (struct Struct_1_t *)result;
                                                                                            *result = 0x249C8948;
                                                                                            result = ptr2->field_0;
                                                                                            a2 = ptr2->field_10;
                                                                                            ptr->field_4 = 152;
                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                            dst += 8;
                                                                                            *dst2 = dst;
                                                                                            a3 = v_e0;
                                                                                            sub_1400D9BD0(ptr2, dst2, a3);
                                                                                            a3 = v_d0;
                                                                                            sub_1400DAC20(ptr2, dst2, a3, 96);
                                                                                            if (v_48 <= 63) {
                                                                                                sub_14002EDF0(0, 3);
                                                                                                ptr = (struct Struct_1_t *)result;
                                                                                                *result = 0x3148;
                                                                                                arg_2 = 192;
                                                                                                result = ptr2->field_0;
                                                                                                i = ptr2->field_10;
                                                                                                result -= i;
                                                                                                if (result <= 2) {
                                                                                                    v_20 = 1;
                                                                                                    sub_1400F2D20(ptr2, i, 3, 1);
                                                                                                    i = ptr2->field_10;
                                                                                                }
                                                                                                dst = ptr2->field_8;
                                                                                                result = ptr->field_2;
                                                                                                *(dst + i + 2) = result;
                                                                                                result = ptr->field_0;
                                                                                                *(dst + i) = result;
                                                                                                i += 3;
                                                                                                ptr2->field_10 = i;
                                                                                                off_140108030();
                                                                                                off_140108038(result, 0, ptr);
                                                                                                dst3 = *dst2;
                                                                                                result = dst3 + 1;
                                                                                                *dst2 = result;
                                                                                                sub_14002EDF0(0, 8);
                                                                                                ptr = (struct Struct_1_t *)result;
                                                                                                *result = 0x24BC8D48;
                                                                                                result = ptr2->field_0;
                                                                                                ptr->field_4 = 160;
                                                                                                result -= i;
                                                                                                if (result <= 7) {
                                                                                                    v_20 = 1;
                                                                                                    sub_1400F2D20(ptr2, i, 8, 1);
                                                                                                    dst = ptr2->field_8;
                                                                                                    i = ptr2->field_10;
                                                                                                }
                                                                                                result = ptr->field_0;
                                                                                                *(dst + i) = result;
                                                                                                i += 8;
                                                                                                ptr2->field_10 = i;
                                                                                                off_140108030();
                                                                                                off_140108038(result, 0, ptr);
                                                                                                sub_14002EDF0(0, 6);
                                                                                                if (result != 0) {
                                                                                                    ptr = (struct Struct_1_t *)result;
                                                                                                    *result = 185;
                                                                                                    arg_1 = 128;
                                                                                                    dst2 = ptr2->field_0;
                                                                                                    result = dst2;
                                                                                                    result -= i;
                                                                                                    if (result <= 4) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr2, i, 5, 1);
                                                                                                        i = ptr2->field_10;
                                                                                                        dst2 = ptr2->field_0;
                                                                                                        dst = ptr2->field_8;
                                                                                                    }
                                                                                                    result = (__int64 *)v_48;
                                                                                                    v7 = (__int64)result;
                                                                                                    v7 &= 63;
                                                                                                    result = ptr->field_4;
                                                                                                    *(dst + i + 4) = result;
                                                                                                    result = ptr->field_0;
                                                                                                    *(dst + i) = result;
                                                                                                    i += 5;
                                                                                                    ptr2->field_10 = i;
                                                                                                    off_140108030();
                                                                                                    off_140108038(result, 0, ptr);
                                                                                                    dst2 -= i;
                                                                                                    if (dst2 <= 2) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr2, i, 3, 1);
                                                                                                        i = ptr2->field_10;
                                                                                                    }
                                                                                                    dst2 = (__int64 *)v_40;
                                                                                                    dst = ptr2->field_8;
                                                                                                    *(dst + i + 2) = 170;
                                                                                                    *(dst + i) = 0xF3FC;
                                                                                                    i += 3;
                                                                                                    ptr2->field_10 = i;
                                                                                                    result = dst3 + 4;
                                                                                                    *dst2 = result;
                                                                                                    sub_14002EDF0(0, 3);
                                                                                                    ptr = (struct Struct_1_t *)result;
                                                                                                    *result = 0x894C;
                                                                                                    arg_2 = 230;
                                                                                                    result = ptr2->field_0;
                                                                                                    result -= i;
                                                                                                }
                                                                                                sub_1400F3326(1, 6);
                                                                                                sub_1400F3326(1, 7);
                                                                                                result = &off_14011B3E0;
                                                                                                v_20 = (__int64)result;
                                                                                                a1 = &off_14011B3C3;
                                                                                                a4 = &off_14011D3F8;
                                                                                                a3 = rsp + 40;
                                                                                                sub_1400F3B80(a1, 23, a3, a4);
                                                                                                result = &off_14011CAD0;
                                                                                                v_20 = (__int64)result;
                                                                                                a1 = &off_14011CAB8;
                                                                                                a4 = &off_14011D3F8;
                                                                                                a3 = rsp + 40;
                                                                                                sub_1400F3B80(a1, 19, a3, a4);
                                                                                                v_44 = a3;
                                                                                                ptr = (struct Struct_1_t *)a1;
                                                                                                v_48 = (__int64)a2;
                                                                                                ptr2 = *a2;
                                                                                                ptr2 += 2;
                                                                                                dst = 0;
                                                                                                return sub_1400D9C1A();
                                                                                            }
                                                                                            sub_14002EDF0(0, 6);
                                                                                            if (result != 0) {
                                                                                                ptr = (struct Struct_1_t *)result;
                                                                                                result = (__int64 *)v_48;
                                                                                                result = (__int64 *)((__int64)(__int64)result >> 6);
                                                                                                *(__int64 *)ptr = (__int64)(0xBD41);
                                                                                                ptr->field_2 = result;
                                                                                                result = ptr2->field_0;
                                                                                                a2 = ptr2->field_10;
                                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                if (result <= 5) {
                                                                                                    v_20 = 1;
                                                                                                    sub_1400F2D20(ptr2, a2, 6, 1);
                                                                                                    a2 = ptr2->field_10;
                                                                                                }
                                                                                                result = ptr2->field_8;
                                                                                                a1 = ptr->field_4;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                                                a1 = ptr->field_0;
                                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                                a2 += 6;
                                                                                                ptr2->field_10 = a2;
                                                                                                off_140108030(a1, a2);
                                                                                                off_140108038(result, 0, ptr);
                                                                                                *dst2 = *dst2 + 1;
                                                                                                dst = ptr2->field_10;
                                                                                                a3 = v_d0;
                                                                                                sub_1400DAEC0(ptr2, dst2, a3);
                                                                                                sub_14002EDF0(0, 7);
                                                                                                if (result != 0) {
                                                                                                    ptr = (struct Struct_1_t *)result;
                                                                                                    *result = 0x40C48349;
                                                                                                    result = ptr2->field_0;
                                                                                                    a2 = ptr2->field_10;
                                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                                    ptr = *dst2;
                                                                                                    a1 = ptr2->field_0;
                                                                                                    result = ptr2->field_10;
                                                                                                    a1 = (size_t *)((__int64)a1 - (__int64)result);
                                                                                                    if (a1 <= 2) {
                                                                                                        v_20 = 1;
                                                                                                        sub_1400F2D20(ptr2, result, 3, 1);
                                                                                                        result = ptr2->field_10;
                                                                                                    }
                                                                                                    a1 = ptr2->field_8;
                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result + 2) = 205;
                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result) = 0xFF49;
                                                                                                    a2 = result + 3;
                                                                                                    ptr2->field_10 = a2;
                                                                                                    a1 = ptr + 2;
                                                                                                    *dst2 = a1;
                                                                                                    result += 9;
                                                                                                    if (!((result < 0))) {
                                                                                                        dst = (__int64 *)((__int64)dst - (__int64)result);
                                                                                                        result = dst;
                                                                                                        if (dst == dst) {
                                                                                                            result = ptr2->field_0;
                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                            if (result <= 1) {
                                                                                                                v_20 = 1;
                                                                                                                sub_1400F2D20(ptr2, a2, 2, 1);
                                                                                                                a2 = ptr2->field_10;
                                                                                                            }
                                                                                                            result = ptr2->field_8;
                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x850F;
                                                                                                            a2 += 2;
                                                                                                            ptr2->field_10 = a2;
                                                                                                            result = ptr2->field_0;
                                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                                            if (result <= 3) {
                                                                                                                v_20 = 1;
                                                                                                                sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                                                a2 = ptr2->field_10;
                                                                                                            }
                                                                                                            result = ptr2->field_8;
                                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = dst;
                                                                                                            a2 += 4;
                                                                                                            ptr2->field_10 = a2;
                                                                                                            ptr += 3;
                                                                                                            *dst2 = ptr;
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
                                                                                        off_140108030();
                                                                                        off_140108038(result, 0, ptr);
                                                                                        return (__int64)ptr;
                                                                                    }
                                                                                    off_140108030();
                                                                                    off_140108038(result, 0, dst2);
                                                                                    ptr = ptr2->field_10;
                                                                                    return (__int64)ptr;
                                                                                } while (result != 12);
                                                                                return (__int64)ptr;
                                                                            }
                                                                            off_140108030();
                                                                            off_140108038(result, 0, ptr);
                                                                            return (__int64)ptr;
                                                                        }
                                                                        sub_1400F3326(1, 3);
                                                                        sub_1400F3326(1, 11);
                                                                        return (__int64)ptr;
                                                                    }
                                                                    off_140108030();
                                                                    off_140108038(result, 0, ptr);
                                                                    return (__int64)ptr;
                                                                } while (v7 != 24);
                                                                return (__int64)ptr;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        return (__int64)ptr;
                                    }
                                    off_140108030();
                                    off_140108038(result, 0, ptr);
                                    return (__int64)ptr;
                                }
                                off_140108030();
                                off_140108038(result, 0, ptr);
                                return (__int64)ptr;
                            } while (dst3 != 96);
                            return (__int64)ptr;
                        }
                        return (__int64)ptr;
                    }
                    off_140108030();
                    off_140108038(result, 0, ptr);
                    return (__int64)ptr;
                }
                off_140108030();
                off_140108038(result, 0, ptr);
                return (__int64)ptr;
            } while (dst3 != 568);
            return (__int64)ptr;
        }
        return (__int64)ptr;
    }
    do {
        sub_1400F3326(1, 8);
        do {
            v_20 = 1;
            sub_1400F2D20(ptr2, i, 3, 1);
            dst = ptr2->field_8;
            i = ptr2->field_10;
            do {
                result = ptr->field_2;
                *(dst + i + 2) = result;
                result = ptr->field_0;
                *(dst + i) = result;
                i += 3;
                ptr2->field_10 = i;
                off_140108030();
                off_140108038(result, 0, ptr);
                result = dst3 + 5;
                *dst2 = result;
                sub_14002EDF0(0, 8);
                ptr = (struct Struct_1_t *)result;
                *result = 0x24BC8D48;
                result = ptr2->field_0;
                ptr->field_4 = 160;
                result -= i;
                if (result <= 7) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, i, 8, 1);
                    dst = ptr2->field_8;
                    i = ptr2->field_10;
                }
                result = ptr->field_0;
                *(dst + i) = result;
                i += 8;
                ptr2->field_10 = i;
                off_140108030();
                off_140108038(result, 0, ptr);
                sub_14002EDF0(0, 6);
                if (result != 0) {
                    ptr = (struct Struct_1_t *)result;
                    *result = 185;
                    arg_1 = v7;
                    dst2 = ptr2->field_0;
                    result = dst2;
                    result -= i;
                    if (result <= 4) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, i, 5, 1);
                        dst2 = ptr2->field_0;
                        i = ptr2->field_10;
                    }
                    dst = ptr2->field_8;
                    result = ptr->field_4;
                    *(dst + i + 4) = result;
                    result = ptr->field_0;
                    *(dst + i) = result;
                    i += 5;
                    ptr2->field_10 = i;
                    off_140108030();
                    off_140108038(result, 0, ptr);
                    dst2 -= i;
                    if (dst2 <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, i, 3, 1);
                        dst = ptr2->field_8;
                        i = ptr2->field_10;
                    }
                    dst2 = (__int64 *)v_40;
                    *(dst + i + 2) = 164;
                    *(dst + i) = 0xF3FC;
                    i += 3;
                    ptr2->field_10 = i;
                    dst3 += 8;
                    *dst2 = dst3;
                    do {
                        ptr = ptr2->field_0;
                        result = (__int64 *)ptr;
                        result -= i;
                        v_20 = 1;
                        sub_1400F2D20(ptr2, i, 3, 1);
                        i = ptr2->field_10;
                        ptr = ptr2->field_0;
                        dst = ptr2->field_8;
                        dst3 = v7 + 160;
                        *(dst + i + 2) = 36;
                        *(dst + i) = 0x84C6;
                        i += 3;
                        ptr2->field_10 = i;
                        result = (__int64 *)ptr;
                        result -= i;
                        if (result <= 3) {
                            v_20 = 1;
                            sub_1400F2D20(ptr2, i, 4, 1);
                            ptr = ptr2->field_0;
                            i = ptr2->field_10;
                        }
                        dst4 = ptr2->field_8;
                        *(dst4 + i) = dst3;
                        i += 4;
                        ptr2->field_10 = i;
                        if (ptr == i) {
                            v_20 = 1;
                            sub_1400F2D20(ptr2, ptr, 1, 1);
                            i = ptr2->field_10;
                            ptr = ptr2->field_0;
                            dst4 = ptr2->field_8;
                        }
                        dst3 = 0;
                        v_58 = v7;
                        dst = (v7 >= 56) ? 1 : 0;
                        *(dst4 + i) = 128;
                        ++i;
                        ptr2->field_10 = i;
                        result = *dst2;
                        v_50 = (__int64)result;
                        ++result;
                        *dst2 = result;
                        sub_14002EDF0(0, 11);
                        if (result != 0) {
                            a1 = (size_t *)v_48;
                            a1 =  + (__int64)(__int64)a1*8 + 512;
                            a1 = __builtin_bswap64(a1);
                            v_48 = (__int64)a1;
                            dst3 = dst;
                            dst3 = (__int64 *)((__int64)(__int64)dst3 << 6);
                            dst3 += 216;
                            v_28 = 11;
                            v_30 = (__int64)result;
                            *result = 199;
                            v_38 = 1;
                            a1 = rsp + 40;
                            sub_1400D4F50(a1, 0, 4, dst3);
                            dst = (__int64 *)v_28;
                            v5 = v_38;
                            result = dst;
                            result -= v5;
                            if (result <= 3) {
                                v_20 = 1;
                                a1 = rsp + 40;
                                sub_1400F2D20(a1, v5, 4, 1);
                                dst = (__int64 *)v_28;
                                v5 = v_38;
                            }
                            dst2 = (__int64 *)v_30;
                            result = (__int64 *)v_48;
                            *(dst2 + v5) = result;
                            v5 += 4;
                            ptr -= i;
                            if (v5 > ptr) {
                                v_20 = 1;
                                sub_1400F2D20(ptr2, i, v5, 1);
                                dst4 = ptr2->field_8;
                                i = ptr2->field_10;
                            }
                            dst4 += i;
                            sub_1400F27F0(dst4, dst2, v5);
                            i += v5;
                            ptr2->field_10 = i;
                            if (dst == 0) {
                                sub_14002EDF0(0, 11);
                                v7 = v_48;
                                if (result != 0) {
                                    v7 >>= 32;
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 | 4);
                                    v_28 = 11;
                                    v_30 = (__int64)result;
                                    *result = 199;
                                    v_38 = 1;
                                    a1 = rsp + 40;
                                    sub_1400D4F50(a1, 0, 4, dst3);
                                    dst = (__int64 *)v_28;
                                    ptr = (struct Struct_1_t *)v_38;
                                    result = dst;
                                    result = (__int64 *)((__int64)result - (__int64)ptr);
                                    dst2 = (__int64 *)v_40;
                                    if (result <= 3) {
                                        v_20 = 1;
                                        a1 = rsp + 40;
                                        sub_1400F2D20(a1, ptr, 4, 1);
                                        dst = (__int64 *)v_28;
                                        ptr = (struct Struct_1_t *)v_38;
                                    }
                                    dst3 = (__int64 *)v_30;
                                    *(__int64 *)((__int64)dst3 + (__int64)ptr) = v7;
                                    ptr += 4;
                                    result = ptr2->field_0;
                                    result -= i;
                                    if (ptr > result) {
                                        v_20 = 1;
                                        sub_1400F2D20(ptr2, i, ptr, 1);
                                        i = ptr2->field_10;
                                    }
                                    a1 = ptr2->field_8;
                                    a1 += i;
                                    sub_1400F27F0(a1, dst3, ptr);
                                    i += (__int64)ptr;
                                    ptr2->field_10 = i;
                                    if (dst == 0) {
                                        result = (__int64 *)v_50;
                                        result += 3;
                                        *dst2 = result;
                                        v7 = 160;
                                        a3 = v_d0;
                                        sub_1400DAC20(ptr2, dst2, a3, 160);
                                        if (v_58 <= 55) {
                                            result = *dst2;
                                            v_48 = (__int64)result;
                                            i = 0;
                                            do {
                                                sub_14002EDF0(0, 8);
                                                a4 = v7 - 128;
                                                v_28 = 8;
                                                v_30 = (__int64)result;
                                                *result = 139;
                                                v_38 = 1;
                                                a1 = rsp + 40;
                                                sub_1400D4F50(a1, 0, 4, a4);
                                                dst = (__int64 *)v_28;
                                                dst2 = (__int64 *)v_30;
                                                dst4 = (__int64 *)v_38;
                                                result = ptr2->field_0;
                                                dst3 = ptr2->field_10;
                                                result = (__int64 *)((__int64)result - (__int64)dst3);
                                                if (dst4 > result) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, dst3, dst4, 1);
                                                    dst3 = ptr2->field_10;
                                                }
                                                ptr = ptr2->field_8;
                                                a1 = (__int64)ptr + (__int64)dst3;
                                                sub_1400F27F0(a1, dst2, dst4);
                                                dst3 = (__int64 *)((__int64)dst3 + (__int64)dst4);
                                                ptr2->field_10 = dst3;
                                                if (dst == 0) {
                                                    result = (__int64 *)v_48;
                                                    result += i;
                                                    ++result;
                                                    a1 = (size_t *)v_40;
                                                    *a1 = result;
                                                    sub_14002EDF0(0, 3);
                                                    if (result != 0) {
                                                        dst2 = result;
                                                        *result = 0xC80F;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)dst3);
                                                        if (result <= 1) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, dst3, 2, 1);
                                                            ptr = ptr2->field_8;
                                                            dst3 = ptr2->field_10;
                                                        }
                                                        result = *dst2;
                                                        *(__int64 *)((__int64)ptr + (__int64)dst3) = result;
                                                        dst3 += 2;
                                                        ptr2->field_10 = dst3;
                                                        off_140108030();
                                                        off_140108038(result, 0, dst2);
                                                        sub_14002EDF0(0, 8);
                                                        v_28 = 8;
                                                        v_30 = (__int64)result;
                                                        *result = 137;
                                                        v_38 = 1;
                                                        a1 = rsp + 40;
                                                        sub_1400D4F50(a1, 0, 4, v7);
                                                        dst = (__int64 *)v_28;
                                                        dst2 = (__int64 *)v_30;
                                                        dst4 = (__int64 *)v_38;
                                                        result = ptr2->field_0;
                                                        result = (__int64 *)((__int64)result - (__int64)dst3);
                                                        if (dst4 > result) {
                                                            v_20 = 1;
                                                            sub_1400F2D20(ptr2, dst3, dst4, 1);
                                                            ptr = ptr2->field_8;
                                                            dst3 = ptr2->field_10;
                                                        }
                                                        ptr = (struct Struct_1_t *)((__int64)ptr + (__int64)dst3);
                                                        sub_1400F27F0(ptr, dst2, dst4);
                                                        dst3 = (__int64 *)((__int64)dst3 + (__int64)dst4);
                                                        ptr2->field_10 = dst3;
                                                        if (dst == 0) {
                                                            result = (__int64 *)v_48;
                                                            ptr = result + i;
                                                            ptr += 3;
                                                            dst = (__int64 *)v_40;
                                                            *dst = ptr;
                                                            i += 3;
                                                            v7 += 4;
                                                            result = ptr2->field_0;
                                                            a2 = ptr2->field_10;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 1) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 2, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            result = ptr2->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xB848;
                                                            a2 += 2;
                                                            ptr2->field_10 = a2;
                                                            result = ptr2->field_0;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 7) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 8, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            result = ptr2->field_8;
                                                            a1 = 0xD1B54A327B53C0E1;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                            a2 += 8;
                                                            ptr2->field_10 = a2;
                                                            result = ptr2->field_0;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 1) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 2, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            result = ptr2->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xBB48;
                                                            a2 += 2;
                                                            ptr2->field_10 = a2;
                                                            result = ptr2->field_0;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 7) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 8, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            ptr -= 3;
                                                            result = ptr2->field_8;
                                                            a1 = 0x8DE9166E270F9CBD;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                            a2 += 8;
                                                            ptr2->field_10 = a2;
                                                            result = ptr2->field_0;
                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                            if (result <= 2) {
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 3, 1);
                                                                a2 = ptr2->field_10;
                                                            }
                                                            result = ptr2->field_8;
                                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 195;
                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                                                            a2 += 3;
                                                            ptr2->field_10 = a2;
                                                            ptr += 6;
                                                            *dst = ptr;
                                                            v_48 += i;
                                                            dst3 = 96;
                                                            v7 = rsp + 40;
                                                            result = 0;
                                                            do {
                                                                dst4 = result;
                                                                sub_14002EDF0(0, 8);
                                                                a4 = dst3 - 32;
                                                                v_28 = 8;
                                                                v_30 = (__int64)result;
                                                                *result = 0x8B48;
                                                                v_38 = 2;
                                                                sub_1400D4F50(v7, 0, 4, a4);
                                                                dst = (__int64 *)v_28;
                                                                dst2 = (__int64 *)v_30;
                                                                i = v_38;
                                                                result = ptr2->field_0;
                                                                ptr = ptr2->field_10;
                                                                result = (__int64 *)((__int64)result - (__int64)ptr);
                                                                if (i > result) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr2, ptr, i, 1);
                                                                    ptr = ptr2->field_10;
                                                                }
                                                                a1 = ptr2->field_8;
                                                                a1 = (size_t *)((__int64)a1 + (__int64)ptr);
                                                                sub_1400F27F0(a1, dst2, i);
                                                                ptr += i;
                                                                ptr2->field_10 = ptr;
                                                                if (dst == 0) {
                                                                    result = ptr2->field_0;
                                                                    result = (__int64 *)((__int64)result - (__int64)ptr);
                                                                    if (result <= 2) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr2, ptr, 3, 1);
                                                                        ptr = ptr2->field_10;
                                                                    }
                                                                    a1 = (size_t *)v_40;
                                                                    result = ptr2->field_8;
                                                                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 216;
                                                                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                                                                    ptr += 3;
                                                                    ptr2->field_10 = ptr;
                                                                    result = (__int64 *)v_48;
                                                                    result = (__int64 *)((__int64)result + (__int64)dst4);
                                                                    result += 5;
                                                                    *a1 = result;
                                                                    sub_14002EDF0(0, 8);
                                                                    v_28 = 8;
                                                                    v_30 = (__int64)result;
                                                                    *result = 0x8948;
                                                                    v_38 = 2;
                                                                    sub_1400D4F50(v7, 0, 4, dst3);
                                                                    dst = (__int64 *)v_28;
                                                                    ptr = (struct Struct_1_t *)v_30;
                                                                    dst2 = (__int64 *)v_38;
                                                                    result = ptr2->field_0;
                                                                    i = ptr2->field_10;
                                                                    result -= i;
                                                                    if (dst2 > result) {
                                                                        v_20 = 1;
                                                                        sub_1400F2D20(ptr2, i, dst2, 1);
                                                                        i = ptr2->field_10;
                                                                    }
                                                                    a1 = ptr2->field_8;
                                                                    a1 += i;
                                                                    sub_1400F27F0(a1, ptr, dst2);
                                                                    i += (__int64)dst2;
                                                                    ptr2->field_10 = i;
                                                                    if (dst == 0) {
                                                                        result = (__int64 *)v_48;
                                                                        result = (__int64 *)((__int64)result + (__int64)dst4);
                                                                        result += 6;
                                                                        dst2 = (__int64 *)v_40;
                                                                        *dst2 = result;
                                                                        result = dst4 + 3;
                                                                        dst3 += 8;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        result = (__int64 *)v_48;
                                                                        dst = (__int64)result + (__int64)dst4;
                                                                        dst += 2;
                                                                        *(__int64 *)ptr = (__int64)(0x249C8948);
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 128;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        result = dst + 5;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x249C8948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 136;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        result = dst + 6;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x249C8948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 144;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        result = dst + 7;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x249C8948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 152;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        result = dst + 8;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 3);
                                                                        if (result == 0) {
                                                                            do {
                                                                                sub_1400F3340(1, 3);
                                                                                return (__int64)result;
                                                                            } while (result == 0);
                                                                            return (__int64)result;
                                                                        }
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x3148;
                                                                        arg_2 = 192;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        result = dst + 9;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x24448948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 64;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x24448948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 72;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        result = dst + 11;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x24448948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 80;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x24448948;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 88;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        dst += 13;
                                                                        *dst2 = dst;
                                                                        a3 = v_e0;
                                                                        sub_1400D9BD0(ptr2, dst2, a3);
                                                                        a3 = v_d0;
                                                                        sub_1400DAC20(ptr2, dst2, a3, 96);
                                                                        sub_14002EDF0(0, 3);
                                                                        if (result == 0) {
                                                                            return a3;
                                                                        }
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x3148;
                                                                        arg_2 = 192;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        dst = *dst2;
                                                                        result = dst + 1;
                                                                        *dst2 = result;
                                                                        sub_14002EDF0(0, 8);
                                                                        ptr = (struct Struct_1_t *)result;
                                                                        *result = 0x24BC8D48;
                                                                        result = ptr2->field_0;
                                                                        a2 = ptr2->field_10;
                                                                        ptr->field_4 = 193;
                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                        sub_14002EDF0(0, 6);
                                                                        if (result != 0) {
                                                                            ptr = (struct Struct_1_t *)result;
                                                                            *result = 185;
                                                                            arg_1 = 23;
                                                                            result = ptr2->field_0;
                                                                            a2 = ptr2->field_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                            result = dst + 3;
                                                                            *dst2 = result;
                                                                            result = ptr2->field_0;
                                                                            a2 = ptr2->field_10;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                            if (result <= 2) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                a2 = ptr2->field_10;
                                                                            }
                                                                            result = ptr2->field_8;
                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 170;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                                                                            a2 += 3;
                                                                            ptr2->field_10 = a2;
                                                                            result = ptr2->field_0;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                            if (result <= 2) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                a2 = ptr2->field_10;
                                                                            }
                                                                            result = ptr2->field_8;
                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 36;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 0x84C6;
                                                                            a2 += 3;
                                                                            ptr2->field_10 = a2;
                                                                            result = ptr2->field_0;
                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                            if (result <= 3) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, a2, 4, 1);
                                                                                a2 = ptr2->field_10;
                                                                            }
                                                                            result = ptr2->field_8;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 192;
                                                                            a2 += 4;
                                                                            ptr2->field_10 = a2;
                                                                            if (ptr2->field_0 == a2) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, a2, 1, 1);
                                                                                a2 = ptr2->field_10;
                                                                            }
                                                                            result = ptr2->field_8;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = 128;
                                                                            ++a2;
                                                                            ptr2->field_10 = a2;
                                                                            result = dst + 5;
                                                                            *dst2 = result;
                                                                            sub_14002EDF0(0, 11);
                                                                            if (result != 0) {
                                                                                ptr = (struct Struct_1_t *)result;
                                                                                *result = 0x84C7;
                                                                                arg_2 = 36;
                                                                                arg_3 = 216;
                                                                                result = ptr2->field_0;
                                                                                a2 = ptr2->field_10;
                                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                if (result <= 10) {
                                                                                    v_20 = 1;
                                                                                    sub_1400F2D20(ptr2, a2, 11, 1);
                                                                                    a2 = ptr2->field_10;
                                                                                }
                                                                                result = ptr2->field_8;
                                                                                a1 = ptr->field_7;
                                                                                *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                                                a1 = ptr->field_0;
                                                                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                a2 += 11;
                                                                                ptr2->field_10 = a2;
                                                                                off_140108030(a1, a2);
                                                                                off_140108038(result, 0, ptr);
                                                                                sub_14002EDF0(0, 11);
                                                                                if (result != 0) {
                                                                                    ptr = (struct Struct_1_t *)result;
                                                                                    *result = 0x84C7;
                                                                                    arg_2 = 36;
                                                                                    result = 0x30000000000DC;
                                                                                    ptr->field_3 = result;
                                                                                    result = ptr2->field_0;
                                                                                    a2 = ptr2->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                    if (result <= 10) {
                                                                                        v_20 = 1;
                                                                                        sub_1400F2D20(ptr2, a2, 11, 1);
                                                                                        a2 = ptr2->field_10;
                                                                                    }
                                                                                    result = ptr2->field_8;
                                                                                    a1 = ptr->field_7;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                                                                                    a1 = ptr->field_0;
                                                                                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                    a2 += 11;
                                                                                    ptr2->field_10 = a2;
                                                                                    off_140108030(a1, a2);
                                                                                    off_140108038(result, 0, ptr);
                                                                                    dst += 7;
                                                                                    *dst2 = dst;
                                                                                    a3 = v_d0;
                                                                                    sub_1400DAC20(ptr2, dst2, a3, 160);
                                                                                    a3 = v_60;
                                                                                    a4 = (int *)v_d8;
                                                                                    sub_1400DA120(ptr2, dst2, a3, a4);
                                                                                    sub_14002EDF0(0, 3);
                                                                                    if (result == 0) {
                                                                                        return (__int64)a4;
                                                                                    }
                                                                                    ptr = (struct Struct_1_t *)result;
                                                                                    *result = 0x3148;
                                                                                    arg_2 = 192;
                                                                                    result = ptr2->field_0;
                                                                                    a2 = ptr2->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                    dst = *dst2;
                                                                                    result = dst + 1;
                                                                                    *dst2 = result;
                                                                                    sub_14002EDF0(0, 3);
                                                                                    if (result == 0) {
                                                                                        return (__int64)result;
                                                                                    }
                                                                                    ptr = (struct Struct_1_t *)result;
                                                                                    *result = 0x8948;
                                                                                    arg_2 = 231;
                                                                                    result = ptr2->field_0;
                                                                                    a2 = ptr2->field_10;
                                                                                    result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                    sub_14002EDF0(0, 6);
                                                                                    if (result == 0) {
                                                                                        return (__int64)a2;
                                                                                    } else {
                                                                                        ptr = (struct Struct_1_t *)result;
                                                                                        *result = 185;
                                                                                        arg_1 = 320;
                                                                                        result = ptr2->field_0;
                                                                                        a2 = ptr2->field_10;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
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
                                                                                        result = dst + 3;
                                                                                        *dst2 = result;
                                                                                        result = ptr2->field_0;
                                                                                        a2 = ptr2->field_10;
                                                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                        if (result <= 2) {
                                                                                            v_20 = 1;
                                                                                            sub_1400F2D20(ptr2, a2, 3, 1);
                                                                                            a2 = ptr2->field_10;
                                                                                        }
                                                                                        result = ptr2->field_8;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 170;
                                                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0xF3FC;
                                                                                        a2 += 3;
                                                                                        ptr2->field_10 = a2;
                                                                                        sub_14002EDF0(0, 7);
                                                                                        if (result != 0) {
                                                                                            ptr = (struct Struct_1_t *)result;
                                                                                            *result = 0x8148;
                                                                                            arg_3 = 320;
                                                                                            arg_2 = 196;
                                                                                            result = ptr2->field_0;
                                                                                            a2 = ptr2->field_10;
                                                                                            result = (__int64 *)((__int64)result - (__int64)a2);
                                                                                            if (result <= 6) {
                                                                                                v_20 = 1;
                                                                                                sub_1400F2D20(ptr2, a2, 7, 1);
                                                                                                a2 = ptr2->field_10;
                                                                                            }
                                                                                            result = ptr2->field_8;
                                                                                            a1 = ptr->field_0;
                                                                                            a3 = ptr->field_3;
                                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 3) = a3;
                                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                                            a2 += 7;
                                                                                            ptr2->field_10 = a2;
                                                                                            off_140108030(a1, a2, a3);
                                                                                            off_140108038(result, 0, ptr);
                                                                                            dst += 5;
                                                                                            *dst2 = dst;
                                                                                            return (__int64)dst;
                                                                                        }
                                                                                    }
                                                                                    return (__int64)dst;
                                                                                }
                                                                            }
                                                                            return (__int64)dst;
                                                                        }
                                                                        return (__int64)dst;
                                                                    }
                                                                    off_140108030();
                                                                    off_140108038(result, 0, ptr);
                                                                    return (__int64)dst;
                                                                }
                                                                off_140108030();
                                                                off_140108038(result, 0, dst2);
                                                                ptr = ptr2->field_10;
                                                                return (__int64)ptr;
                                                            } while (result != 12);
                                                            return (__int64)ptr;
                                                        }
                                                        off_140108030();
                                                        off_140108038(result, 0, dst2);
                                                        return (__int64)ptr;
                                                    }
                                                    return (__int64)ptr;
                                                }
                                                off_140108030();
                                                off_140108038(result, 0, dst2);
                                                return (__int64)ptr;
                                            } while (i != 24);
                                            return (__int64)ptr;
                                        }
                                        a3 = v_d0;
                                        sub_1400DAC20(ptr2, dst2, a3, 224);
                                        return a3;
                                    }
                                    off_140108030();
                                    off_140108038(result, 0, dst3);
                                    return a3;
                                }
                                return a3;
                            }
                            off_140108030();
                            off_140108038(result, 0, dst2);
                            return a3;
                        }
                        return a3;
                    } while (v7 == 0);
                }
                return a3;
            } while (result > 2);
            return (__int64)result;
        } while (result <= 2);
    } while (result == 0);
}