// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `i`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3600();
__int64 sub_1400F6770();
__int64 sub_1400F6180();
__int64 sub_1400F5F90();
__int64 sub_1400F6230();
__int64 sub_1400F3510();
extern __int64 off_140111FA0;
extern __int64 off_140111CF2;
extern __int64 off_140111AF2;

__int64 __fastcall sub_1400F62D0(size_t *a1, int *a2, int a3, int *a4) {
    __int64 rsp;
    __int64 arg_1;
    int arg_8;
    int v_20;
    int v_21;
    __int64 v_22;
    int v_28;
    int v_30;
    struct Struct_3_t *ptr2;
    __int64 v2;
    __int64 *result;
    struct Struct_2_t *i;
    __int64 *src;
    __int64 *src2;
    __int64 v9;
    __int64 *src3;
    struct Struct_1_t *ptr;
    __int64 *src4;

    ptr2 = (struct Struct_3_t *)arg_8;
    v2 = a1[2];
    result = (__int64 *)ptr2;
    result -= v2;
    if ((result < 0)) {
        a4 = &off_140111FA0;
        sub_1400F3600(v2, ptr2, ptr2, a4);
    } else {
        i = (struct Struct_2_t *)a1;
        if (result <= 3) {
            i->field_10 = ptr2;
            v_30 = 4;
            a1 = rsp + 32;
            a3 = rsp + 48;
            v2 = (__int64)a2;
            sub_1400F6770(a1, i, a3, 2);
            a2 = (int *)v2;
            v2 = (__int64)ptr2;
        } else {
            result = i->field_0;
            a1 = *(result + v2);
            a3 = *(result + v2 + 1);
            a4 = *(result + v2 + 2);
            result = *(result + v2 + 3);
            v2 += 4;
            i->field_10 = v2;
            src = &off_140111CF2;
            src2 = &off_140111AF2;
            a3 = *(src2 + a3*2);
            a4 = *(src + (__int64)(__int64)a4*2);
            src2 = *(src2 + (__int64)(__int64)result*2);
            a3 |= *(src + (__int64)(__int64)a1*2);
            result = (__int64 *)a3;
            result = (__int64 *)((__int64)(__int64)result << 8);
            result = (__int64 *)((__int64)(__int64)result | (__int64)a4);
            result = (__int64 *)((__int64)(__int64)result | (__int64)src2);
            if ((result < 0)) {
                v_30 = 12;
                a1 = rsp + 32;
                a3 = rsp + 48;
                v9 = (__int64)a2;
                sub_1400F6770(a1, i, a3);
                a2 = (int *)v9;
            } else {
                v_22 = (__int64)result;
                v_20 = 0;
            }
        }
        if (v_20 != 1) {
            v9 = v_22;
            result = (__int64 *)v9;
            result = (__int64 *)((__int64)(__int64)result & 0xFC00);
            if (result != 0xDC00) {
                result = v9 + 0x2400;
                if (result >= 0xFC00) {
                    src3 = i->field_0;
                    if (v2 >= ptr2) {
                        ptr = (struct Struct_1_t *)a2;
                        v_30 = 4;
                        a1 = rsp + 32;
                        a3 = rsp + 48;
                        sub_1400F6180(a1, i, a3);
                        if (v_20 != 1) {
                            a1 = (size_t *)v_21;
                            a2 = (int *)ptr;
                            result = v2 + 1;
                            i->field_10 = result;
                            if (a1 == 92) {
                                if (result >= ptr2) {
                                    ptr = (struct Struct_1_t *)a2;
                                    v_30 = 4;
                                    a1 = rsp + 32;
                                    a3 = rsp + 48;
                                    sub_1400F6180(a1, i, a3);
                                    if (v_20 != 1) {
                                        result = (__int64 *)v_21;
                                        a2 = (int *)ptr;
                                        a1 = v2 + 2;
                                        if (result == 117) {
                                            result = (__int64 *)ptr2;
                                            result = (__int64 *)((__int64)result - (__int64)a1);
                                            if ((result < 0)) {
                                                a4 = &off_140111FA0;
                                                sub_1400F3600(a1, ptr2, ptr2, a4);
                                                ptr2 = (struct Struct_3_t *)a2;
                                                sub_1400F5F90(a2, result, 4);
                                                a2 = (int *)ptr2;
                                                result = ptr2->field_10;
                                                a1 = ptr2->field_8;
                                                a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                if (i < 0x800) {
                                                    a3 = v9;
                                                    a3 >>= 6;
                                                    a3 |= 192;
                                                } else {
                                                    a3 = (int)i;
                                                    a3 >>= 12;
                                                    a3 |= 224;
                                                    i = (struct Struct_2_t *)((__int64)(__int64)i >> 6);
                                                    i = (struct Struct_2_t *)((__int64)(__int64)i & 63);
                                                    i = (struct Struct_2_t *)((__int64)(__int64)i | 128);
                                                    arg_1 = (__int64)i;
                                                    a4 = 3;
                                                }
                                                *a1 = a3;
                                                v9 &= 63;
                                                v9 |= 128;
                                                *(__int64 *)((__int64)a1 + (__int64)a4 - 1) = v9;
                                                result = (__int64 *)((__int64)result + (__int64)a4);
                                                a2[2] = result;
                                                result = 0;
                                            } else {
                                                ptr = (struct Struct_1_t *)a2;
                                                if (result <= 3) {
                                                    i->field_10 = ptr2;
                                                    v_30 = 4;
                                                } else {
                                                    result = *(src3 + v2 + 2);
                                                    a1 = *(src3 + v2 + 3);
                                                    a2 = *(src3 + v2 + 4);
                                                    a3 = *(src3 + v2 + 5);
                                                    v2 += 6;
                                                    i->field_10 = v2;
                                                    a4 = &off_140111CF2;
                                                    src4 = &off_140111AF2;
                                                    a1 = *(src4 + (__int64)(__int64)a1*2);
                                                    a2 = *(a4 + (__int64)(__int64)a2*2);
                                                    a3 = *(src4 + a3*2);
                                                    a1 = (size_t *)((__int64)(__int64)a1 | *(a4 + (__int64)(__int64)result*2));
                                                    result = (__int64 *)a1;
                                                    result = (__int64 *)((__int64)(__int64)result << 8);
                                                    result = (__int64 *)((__int64)(__int64)result | (__int64)a2);
                                                    result = (__int64 *)((__int64)(__int64)result | a3);
                                                    if ((result < 0)) {
                                                        v_30 = 12;
                                                        a1 = rsp + 32;
                                                        a3 = rsp + 48;
                                                        sub_1400F6770(a1, i, a3);
                                                        if (v_20 == 1) {
                                                            result = (__int64 *)v_28;
                                                        } else {
                                                            ptr2 = (struct Struct_3_t *)v_22;
                                                            result = ptr2 + 0x2000;
                                                            if (result < 0xFC00) {
                                                                v_30 = 20;
                                                                a2 = rsp + 48;
                                                                sub_1400F6230(i, a2);
                                                            } else {
                                                                a1 = (size_t *)ptr;
                                                                v9 += 0x2800;
                                                                result = (__int64 *)v9;
                                                                result = (__int64 *)((__int64)(__int64)result << 10);
                                                                a2 = (int *)ptr2;
                                                                a2 += 0x2400;
                                                                v2 = (__int64)result + (__int64)a2;
                                                                v2 += 0x10000;
                                                                i = (struct Struct_2_t *)result;
                                                                i = (struct Struct_2_t *)((__int64)(__int64)i | (__int64)a2);
                                                                result = ptr->field_0;
                                                                a2 = ptr->field_10;
                                                                result = (__int64 *)((__int64)result - (__int64)a2);
                                                                if (result <= 3) JUMPOUT(0x1400f6752);
                                                                result = (__int64 *)arg_8;
                                                                a3 = v2;
                                                                a3 >>= 18;
                                                                a3 |= 240;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = a3;
                                                                v2 >>= 12;
                                                                v2 &= 63;
                                                                v2 |= 128;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 1) = v2;
                                                                i = (struct Struct_2_t *)((__int64)(__int64)i >> 6);
                                                                i = (struct Struct_2_t *)((__int64)(__int64)i & 63);
                                                                i = (struct Struct_2_t *)((__int64)(__int64)i | 128);
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = i;
                                                                ptr2 = (struct Struct_3_t *)((__int64)(__int64)ptr2 & 63);
                                                                ptr2 = (struct Struct_3_t *)((__int64)(__int64)ptr2 | 128);
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 3) = ptr2;
                                                                a2 += 4;
                                                                a1[2] = a2;
                                                                result = 0;
                                                            }
                                                        }
                                                        return (__int64)result;
                                                    } else {
                                                        v_22 = (__int64)result;
                                                        v_20 = 0;
                                                        if (v_20 == 1) {
                                                            return v_20;
                                                        } else {
                                                            return v_20;
                                                        }
                                                        return v_20;
                                                    }
                                                    return v_20;
                                                }
                                                return v_20;
                                            }
                                        } else {
                                            i->field_10 = a1;
                                            v_30 = 23;
                                            return v_30;
                                        }
                                        return v_30;
                                    }
                                } else {
                                    result = *(__int64 *)((__int64)src3 + (__int64)result);
                                    a1 = v2 + 2;
                                    if (result != 117) {
                                        return (__int64)a1;
                                    } else {
                                        return (__int64)a1;
                                    }
                                    return (__int64)a1;
                                }
                                return (__int64)a1;
                            } else {
                                return (__int64)a1;
                            }
                            return (__int64)a1;
                        }
                    } else {
                        a1 = *(src3 + v2);
                        result = v2 + 1;
                        i->field_10 = result;
                        if (a1 == 92) {
                            return (__int64)result;
                        }
                        return (__int64)result;
                    }
                    return (__int64)result;
                } else {
                    i = (struct Struct_2_t *)v9;
                    if (v9 >= 128) {
                        a1 = *a2;
                        result = a2[2];
                        a1 = (size_t *)((__int64)a1 - (__int64)result);
                        if (a1 <= 3) {
                            return (__int64)a1;
                        } else {
                            a1 = (size_t *)arg_8;
                            a1 = (size_t *)((__int64)a1 + (__int64)result);
                            if (i >= 0x800) {
                                return (__int64)a1;
                            } else {
                                return (__int64)a1;
                            }
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    } else {
                        i = a2[2];
                        if (i == *a2) {
                            ptr2 = (struct Struct_3_t *)a2;
                            sub_1400F3510(a2);
                            a2 = (int *)ptr2;
                        }
                        result = (__int64 *)arg_8;
                        *(__int64 *)((__int64)result + (__int64)i) = v9;
                        ++i;
                        a2[2] = i;
                        result = 0;
                    }
                }
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}