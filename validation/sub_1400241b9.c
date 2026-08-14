// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140013110();
__int64 sub_140023DFC();
__int64 sub_1400247C7();
__int64 sub_1400123E0();
__int64 sub_140024ADD();
__int64 sub_1400126B0();
__int64 sub_1400F3B80();
__int64 sub_140023492();
__int64 sub_14002454F();
extern __int64 off_1401109D2;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;
extern __int64 off_140110C90;
extern __int64 off_14011D418;
extern __int64 off_140110D08;
extern __int64 off_140116F20;

__int64 __fastcall sub_1400241B9(size_t *a1) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_20;
    __int64 arg_8;
    int v_10;
    int v_18;
    __int64 v_20;
    int v_38;
    int v_6;
    __int64 v_8;
    int v_d;
    int v_e;
    __int64 *dst;
    __int64 *dst2;
    __int64 v3;
    __int64 v6;
    __int64 *i;
    struct Struct_2_t *ptr2;
    __int64 *result;
    __int64 v12;
    __int64 v10;
    struct Struct_1_t *ptr;
    __int64 i2;
    __int64 v7;
    __int64 v9;
    __int64 v8;

    dst = rsp + 112;
    dst2 = (__int64 *)a1;
    if (*a1 == 0) {
        a1 = (size_t *)arg_20;
        if (a1 != 0) {
            v3 = &off_1401109D2;
            v6 = 1;
            return sub_140013110();
        }
    } else {
        i = dst - 64;
        sub_140023DFC(i, dst2);
        ptr2 = *i;
        if (ptr2 == 0) {
            ptr2 = (struct Struct_2_t *)v_38;
            a1 = (size_t *)arg_20;
            if (a1 != 0) {
                result = &off_1401109B9;
                v3 = &off_1401109A9;
                if (ptr2 != 0) v3 = result;
                result = (__int64 *)ptr2;
                v6 = result + (__int64)(__int64)result*8;
                v6 += 16;
                sub_140013110(a1, v3, v6);
                i = 1;
                if (result == 0) {
                    *dst2 = 0;
                    arg_8 = (__int64)ptr2;
                    i = 0;
                }
                result = i;
                return (__int64)result;
            }
            return (__int64)result;
        } else {
            v12 = v_38;
            if ((v12 & 1) == 0) {
                v10 = ptr2 + v12;
                *i = ptr2;
                arg_8 = v12;
                arg_10 = v10;
                arg_18 = 0;
                arg_20 = 2;
                do {
                    sub_1400247C7(i);
                } while (result < 0x110000);
                if (result != 0x110001) {
                    a1 = (size_t *)arg_20;
                    if (a1 != 0) {
                        v3 = &off_1401109A9;
                        sub_140013110(a1, v3, 16);
                        i = 1;
                        if (result == 0) {
                            *dst2 = 0;
                            arg_8 = 0;
                            return arg_8;
                        }
                        return arg_8;
                    }
                    return arg_8;
                } else {
                    ptr = (struct Struct_1_t *)arg_20;
                    if (ptr == 0) {
                        return (__int64)ptr;
                    } else {
                        a1 = ptr->field_0;
                        result = ptr->field_8;
                        ((__int64 (*)())(*(result + 32)))();
                        i = 1;
                        if (result == 0) {
                            dst2 = dst - 64;
                            *dst2 = ptr2;
                            arg_8 = v12;
                            arg_10 = v10;
                            arg_18 = 0;
                            arg_20 = 2;
                            sub_1400247C7(dst2, 34);
                            while (result != 0x110001) {
                                v12 = (__int64)result;
                                if (result != 0x110000) {
                                    if (v12 != 39) {
                                        if (v12 > 12) {
                                            if (v12 == 13) {
                                                v_8 = 0x725C;
                                                v_6 = 0;
                                                v12 = 2;
                                                result = 0;
                                                a1 = *dst;
                                                v_10 = (int)a1;
                                                a1 = (size_t *)v_8;
                                                v_18 = (int)a1;
                                                v10 = v_18;
                                                do {
                                                    v3 = v10;
                                                    a1 = ptr->field_0;
                                                    result = ptr->field_8;
                                                    ((__int64 (*)())(*(result + 32)))();
                                                    if (result == 0) {
                                                        ++i2;
                                                    }
                                                    return i2;
                                                } while (true);
                                            }
                                            if (v12 == 34) {
                                                v_8 = 0x225C;
                                                return v_8;
                                            }
                                            if (v12 != 92) {
                                                if (v12 <= 767) {
                                                    sub_1400123E0(v12);
                                                    if (result == 0) {
                                                        a1 = dst - 24;
                                                        sub_140024ADD(a1, v12);
                                                        result = (__int64 *)v_10;
                                                        *dst = result;
                                                        result = (__int64 *)v_18;
                                                        v_8 = (__int64)result;
                                                        result = (__int64 *)v_e;
                                                        v12 = v_d;
                                                        a1 = *dst;
                                                        v_10 = (int)a1;
                                                        a1 = (size_t *)v_8;
                                                        v_18 = (int)a1;
                                                        return v_18;
                                                    }
                                                    v_8 = v12;
                                                    v12 = 129;
                                                    result = 128;
                                                    return (__int64)result;
                                                }
                                                sub_1400126B0(v12, 39);
                                                if (result != 0) {
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            v_8 = 0x5C5C;
                                            return v_8;
                                        }
                                        if (v12 == 0) {
                                            v_8 = 0x305C;
                                            return v_8;
                                        }
                                        if (v12 == 9) {
                                            v_8 = 0x745C;
                                            return v_8;
                                        }
                                        if (v12 != 10) {
                                            return v_8;
                                        }
                                        v_8 = 0x6E5C;
                                        return v_8;
                                    }
                                    a1 = ptr->field_0;
                                    result = ptr->field_8;
                                    ((__int64 (*)())(*(result + 32)))();
                                    return (__int64)result;
                                }
                                result = &off_140110C90;
                                v_20 = (__int64)result;
                                a1 = &off_14011D418;
                                v7 = &off_140110D08;
                                v9 = dst - 24;
                                sub_1400F3B80(a1, 43, v9, v7);
                                dst = rsp + 32;
                                result = *a1;
                                if (result == 0) JUMPOUT(0x14002453b);
                                ptr2 = (struct Struct_2_t *)a1;
                                dst2 = 0;
                                v8 = &off_140116F20;
                                i = 0;
                                do {
                                    a1 = ptr2->field_10;
                                    if (i == 0) {
                                        sub_140023492(ptr2, 1);
                                        if (result != 0) JUMPOUT(0x14002453f);
                                        ++i;
                                        result = ptr2->field_0;
                                        return sub_14002454F();
                                    }
                                    a1 = ptr2->field_20;
                                    if (a1 == 0) {
                                        return (__int64)a1;
                                    }
                                    sub_140013110(a1, v8, 2);
                                    if (result != 0) JUMPOUT(0x14002453f);
                                    return (__int64)a1;
                                } while (result != 0);
                                return (__int64)a1;
                            }
                            a1 = ptr->field_0;
                            result = ptr->field_8;
                            v3 = 34;
                            ((__int64 (*)())(*(result + 32)))();
                            i = result;
                        }
                    }
                    return (__int64)i;
                }
                return (__int64)i;
            }
            return (__int64)i;
        }
    }
    return (__int64)result;
}