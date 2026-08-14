// inferred from 5 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    char _pad_18[8];
    __int64 field_28; // offset 40
    char _pad_28[208];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 6 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[432];
    __int64 field_1B0; // offset 432
    __int64 field_1B8; // offset 440
    __int64 field_1C0; // offset 448
    __int64 field_1C8; // offset 456
    char _pad_1C8[48];
    __int64 field_200; // offset 512
    __int64 field_208; // offset 520
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    int field_0; // offset 0
    char _pad_0[1];
    char field_5; // offset 5
    __int64 field_6; // offset 6
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[512];
    __int64 field_200; // offset 512
    __int64 field_208; // offset 520
};

__int64 sub_14001EF00();
__int64 sub_1400F37D0();
__int64 sub_1400F3869();
__int64 sub_1400F6B50();
__int64 sub_1400F6820();
__int64 sub_1400F3B80();
__int64 sub_14001EDC0();
__int64 sub_14001F160();
__int64 sub_1400F4640();
__int64 sub_140020049();
__int64 off_140108268();
__int64 off_140108258();
extern __int64 off_14012D270;
extern __int64 off_1401103B0;
extern __int64 off_1401103D8;
extern __int64 off_140110498;
extern __int64 off_14012D268;
extern __int64 off_140118E08;
extern __int64 off_14011D418;
extern __int64 off_1401106F0;
extern __int64 off_140110761;
extern __int64 off_140110798;
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_140110408;
extern __int64 off_1401103F0;

__int64 __fastcall sub_14001FA90(int *a1) {
    int arg_118;
    int arg_120;
    int arg_128;
    int arg_130;
    int v_100;
    int v_180;
    int v_190;
    int v_198;
    int v_1b8;
    __int64 v_20;
    int v_70;
    __int64 v_78;
    int v_88;
    __int64 *v_0;
    char *str;
    __int64 *rsp;
    __int64 v4;
    struct Struct_1_t *result;
    __int64 v6;
    __int64 *dst;
    __int64 v5;
    struct Struct_2_t *ptr;
    __int64 *src;
    struct Struct_3_t *ptr2;
    struct Struct_4_t *ptr3;
    __int64 src2;
    __int64 v7;
    __int64 *src3;
    __int64 v8;

    rsp = (__int64 *)((__int64)(__int64)rsp & -128);
    v4 = rsp + 128;
    sub_14001EF00(v4, a1);
    result = off_14012D270;
    a1 = __readgsqword(88);
    result = v_0[(__int64)result];
    if (result->field_18 != 0) {
        a1 = &off_1401103B0;
        v6 = &off_1401103D8;
        sub_1400F37D0(a1, 35, v6);
    } else {
        dst = result + 24;
        *dst = v4;
        v5 = v_180;
        ptr = (struct Struct_2_t *)v_190;
        src = ptr->field_208;
        if (v5 >= src) {
            v6 = &off_140110498;
            sub_1400F3869(v5, src, v6);
        } else {
            ptr2 = ptr->field_200;
            ptr3 = v5 + v5*4;
            src2 = ptr2 + (__int64)(__int64)ptr3*8;
            src2 += 4;
            a1 = 1;
            result = 0;
            /* cmpxchg %(__int64)a1, 4(%(__int64)ptr2,%(__int64)ptr3,8) */;
            if ((src2 != 0)) {
                sub_1400F6B50(src2);
            }
            ptr2 += (__int64)(__int64)ptr3*8;
            result = off_14012D268;
            result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
            if (result != 0) {
                sub_1400F6820();
                ptr3 = (struct Struct_4_t *)result;
                ptr3 = (struct Struct_4_t *)((__int64)(__int64)ptr3 ^ 1);
                result = ptr2->field_5;
                if (result == 0) {
                    ptr2->field_6 = 1;
                    *(__int64 *)ptr2 = (__int64)(ptr2->field_0 + 1);
                    off_140108268(ptr2, src);
                    if (ptr3 == 0) {
                        result = off_14012D268;
                        result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
                        if (result != 0) {
                            sub_1400F6820();
                            ptr2->field_5 = 1;
                        }
                    }
                } else {
                    v_70 = src2;
                    v_78 = (__int64)ptr3;
                    result = &off_140118E08;
                    v_20 = (__int64)result;
                    a1 = &off_14011D418;
                    v7 = &off_1401106F0;
                    v6 = rsp + 112;
                    sub_1400F3B80(a1, 43, v6, v7);
                    off_140108258(src2);
                    a1 = ptr->field_1C0;
                    if (a1 != 0) {
                        result = ptr->field_1C8;
                        ((__int64 (*)())(result->field_28))();
                        if (*dst != v4) {
                            a1 = &off_140110761;
                            v6 = &off_140110798;
                            sub_1400F37D0(a1, 49, v6);
                            return v6;
                        }
                        *dst = 0;
                        result = (struct Struct_1_t *)v_198;
                        *(__int64 *)result = (__int64)(result->field_0 - 1);
                        if (!((result->field_0 != 0))) {
                            a1 = rsp + 408;
                            sub_14001EDC0(a1, v5);
                        }
                        result = (struct Struct_1_t *)v_1b8;
                        *(__int64 *)result = (__int64)(result->field_0 - 1);
                        if (!((result->field_0 != 0))) {
                            a1 = rsp + 440;
                            sub_14001EDC0(a1);
                        }
                        v5 = v_100;
                        src2 = (__int64)str;
                        v4 = v_88;
                        src2 &= -2;
                        v5 &= -2;
                        if (src2 != v5) {
                            ptr2 = off_140108030;
                            ptr3 = off_140108038;
                            do {
                                result = (struct Struct_1_t *)src2;
                                result = (struct Struct_1_t *)(~(__int64)result);
                                src2 += 2;
                            } while (v5 != src2);
                        }
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, v4);
                        result = (struct Struct_1_t *)v_190;
                        *(__int64 *)result = (__int64)(result->field_0 - 1);
                        if (!((result->field_0 != 0))) {
                            a1 = (int *)v_190;
                            sub_14001F160(a1);
                        }
                        rsp = str + 440;
                        return (__int64)rsp;
                    }
                    return (__int64)rsp;
                }
                do {
                    result = 0;
                    result = _InterlockedExchange64(src2, result);
                    off_140108258(src2);
                    a1 = ptr->field_1B0;
                    if (a1 != 0) {
                        result = ptr->field_1B8;
                        src = (__int64 *)v5;
                        ((__int64 (*)())(result->field_28))();
                        src2 = v_180;
                        ptr3 = (struct Struct_4_t *)v_190;
                        src = ptr3->field_208;
                        if (src2 < src) {
                            result = ptr3->field_200;
                            ptr2 = src2 + src2*4;
                            a1 = *(__int64 *)(result + (__int64)(__int64)ptr2*8 + 16);
                            if (a1 != 3) {
                                src = result + (__int64)(__int64)ptr2*8;
                                src += 16;
                                a1 = rsp + 128;
                                sub_1400F4640(a1, src);
                                src = ptr3->field_208;
                                if (src2 < src) {
                                    ptr3 = ptr3->field_200;
                                    src2 = ptr3 + (__int64)(__int64)ptr2*8;
                                    src2 += 12;
                                    a1 = 1;
                                    result = 0;
                                    /* cmpxchg %(__int64)a1, 12(%(__int64)ptr3,%(__int64)ptr2,8) */;
                                    if ((src2 != 0)) {
                                        sub_1400F6B50(src2);
                                    }
                                    ptr2 = ptr3 + (__int64)(__int64)ptr2*8;
                                    ptr2 += 8;
                                    result = off_14012D268;
                                    result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
                                    if (result != 0) {
                                        sub_1400F6820();
                                        ptr3 = (struct Struct_4_t *)result;
                                        ptr3 = (struct Struct_4_t *)((__int64)(__int64)ptr3 ^ 1);
                                        result = ptr2->field_5;
                                        if (result == 0) {
                                            ptr2->field_6 = 1;
                                            *(__int64 *)ptr2 = (__int64)(ptr2->field_0 + 1);
                                            off_140108268(ptr2, src);
                                            if (ptr3 != 0) {
                                                result = 0;
                                                result = _InterlockedExchange64(src2, result);
                                                if (result == 2) {
                                                    return (__int64)result;
                                                }
                                                a1 = ptr->field_1C0;
                                                if (a1 == 0) {
                                                    return (__int64)a1;
                                                }
                                                return (__int64)a1;
                                            }
                                            result = off_14012D268;
                                            result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
                                            if (result != 0) {
                                                sub_1400F6820();
                                                if (result != 0) {
                                                    return (__int64)result;
                                                }
                                                ptr2->field_5 = 1;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    ptr3 = 0;
                                    result = ptr2->field_5;
                                    if (result != 0) {
                                        return (__int64)result;
                                    }
                                    return (__int64)result;
                                }
                                v6 = &off_140110408;
                                sub_1400F3869(src2, src, v6);
                                return v6;
                            }
                            src = ptr3->field_208;
                            if (src2 >= src) {
                                return (__int64)src;
                            }
                            return (__int64)src;
                        }
                        v6 = &off_1401103F0;
                        sub_1400F3869(src2, src, v6);
                        v4 = (__int64)a1;
                        result = a1[35];
                        v7 = result->field_108;
                        src = result->field_100;
                        a1 = (int *)v7;
                        a1 = (int *)((__int64)a1 - (__int64)src);
                        if (a1 <= 0) JUMPOUT(0x140020010);
                        if (arg_130 != 1) JUMPOUT(0x14001ff9f);
                        a1 = v7 - 1;
                        result->field_108 = a1;
                        *(__int64 *)rsp = *(__int64 *)rsp | 0;
                        src3 = (__int64 *)arg_118;
                        v5 = *(src3 + 256);
                        v8 = (__int64)a1;
                        v8 -= v5;
                        if ((v8 < 0)) JUMPOUT(0x14001ffc2);
                        src = (__int64 *)arg_120;
                        v6 = arg_128;
                        src2 = v6 - 1;
                        src2 &= (__int64)a1;
                        src2 <<= 4;
                        result = *(src + src2);
                        src = *(src + src2 + 8);
                        if (a1 != v5) JUMPOUT(0x140020051);
                        v6 = (__int64)result;
                        result = (struct Struct_1_t *)a1;
                        /* cmpxchg %v7, 256(%(__int64)src3) */;
                        result = (struct Struct_1_t *)v6;
                        a1 = (int *)arg_118;
                        a1[33] = v7;
                        if ((0 /* unresolved: flags != */)) JUMPOUT(0x140020010);
                        return sub_140020049();
                    }
                    return (__int64)a1;
                } while (result != 0);
            } else {
                ptr3 = 0;
                result = ptr2->field_5;
                if (result == 0) {
                    return (__int64)result;
                }
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}