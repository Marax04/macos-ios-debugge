// inferred from 2 accesses on `a4`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_1400F6180();
__int64 sub_1400F6230();
__int64 sub_1400F62D0();
__int64 sub_1400F3510();
__int64 sub_1400F3600();
__int64 sub_1400F60D0();
__int64 sub_1400F3869();
__int64 sub_1400F27FC();
__int64 sub_1400276AC();
__int64 sub_1400F6080();
extern __int64 off_140121260;
extern __int64 off_140111F58;
extern __int64 off_140111F40;
extern __int64 off_140111F28;
extern __int64 off_140111F10;
extern __int64 off_140111EF8;

__int64 __fastcall sub_14002707E(size_t *a1, __int64 a2, __int64 *a3,struct Struct_1_t *a4) {
    __int64 rsp;
    __int64 arg_10;
    __int64 arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_58;
    int v_59;
    int v_60;
    __int64 v8;
    struct Struct_2_t *result;
    __int64 i;
    __int64 *src;
    struct Struct_3_t *ptr;
    __int64 v2;
    __int64 v11;
    __int64 i2;
    __int64 *dst;
    __int64 v5;
    __int64 v6;

    *(__int64 *)result = (__int64)(result->field_0 + result);
    v8 = a4->field_8;
    a2 = ((__int64 *)a4)[2];
    while (a2 != v8) {
        if (a2 < v8) {
            result = a4->field_0;
            a1 = *(__int64 *)(result + a2);
            if (a1 == 34) {
                i = a2;
                if (a2 != v8) {
                    if (!((0 /* unresolved: flags >= */))) {
                        src = a4->field_0;
                        result = *(src + i);
                        if (result == 92) {
                            ptr = (struct Struct_3_t *)v2;
                            v2 = v11;
                            v11 = i;
                            v11 -= a2;
                            if (!((v11 < 0))) {
                                result = *a3;
                                i2 = a3[2];
                                result -= i2;
                                if (v11 > result) {
                                    dst = (__int64 *)a2;
                                    sub_1400F5F90(a3, i2, v11, a4);
                                    a3 = (__int64 *)v_28;
                                    a2 = (__int64)dst;
                                    i2 = a3[2];
                                }
                                a2 += (__int64)src;
                                dst = (__int64 *)arg_8;
                                a1 = dst + i2;
                                sub_1400F27F0(a1, a2, v11);
                                a3 = (__int64 *)v_28;
                                i2 += v11;
                                a3[2] = i2;
                                result = i + 1;
                                a4 = (struct Struct_1_t *)v_30;
                                ((__int64 *)a4)[2] = (__int64)(result);
                                if (result >= v8) {
                                    v_40 = 4;
                                    a1 = rsp + 88;
                                    a3 = rsp + 64;
                                    sub_1400F6180(a1, a4, a3, a4);
                                    if (v_58 == 0) {
                                        v11 = v2;
                                        result = (struct Struct_2_t *)v_59;
                                        a3 = (__int64 *)v_28;
                                        a4 = (struct Struct_1_t *)v_30;
                                        result += 0xFFFFFFDE;
                                        if (result <= 83) {
                                            v2 = (__int64)ptr;
                                            a1 = &off_140121260;
                                            switch ((__int64)result) {
                                                case 1:
                                                    v_40 = 12;
                                                    a2 = rsp + 64;
                                                    sub_1400F6230(a4, a2, a3, a4);
                                                    break;
                                                case 83:
                                                    sub_1400F62D0(a4, a3, a3);
                                                    a4 = (struct Struct_1_t *)v_30;
                                                    a3 = (__int64 *)v_28;
                                                    ptr = 0x5C5C5C5C5C5C5C5C;
                                                    i2 = 0xDFDFDFDFDFDFDFE0;
                                                    break;
                                                default:
                                                    if (i2 == *a3) {
                                                        sub_1400F3510(a3, a2, a3, a4);
                                                        a4 = (struct Struct_1_t *)v_30;
                                                        a3 = (__int64 *)v_28;
                                                        dst = (__int64 *)arg_8;
                                                    }
                                                    *(dst + i2) = 9;
                                                    ++i2;
                                                    a3[2] = i2;
                                                    result = 0;
                                                    return (__int64)result;
                                            }
                                            a1 = (size_t *)v_38;
                                            arg_8 = (__int64)result;
                                            *a1 = 2;
                                            return arg_8;
                                        }
                                        return arg_8;
                                    }
                                    result = (struct Struct_2_t *)v_60;
                                    return (__int64)result;
                                }
                                result = *(src + i + 1);
                                i += 2;
                                ((__int64 *)a4)[2] = (__int64)(i);
                                v11 = v2;
                                result += 0xFFFFFFDE;
                                if (result <= 83) {
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            a4 = &off_140111F58;
                            sub_1400F3600(a2, i, v8, a4);
                            a4 = &off_140111F40;
                            sub_1400F3600(a2, i, v8, a4);
                            a4 = &off_140111F28;
                            sub_1400F3600(a2, i, v8, a4);
                            sub_1400F5F90(a3, dst, i2);
                            a3 = (__int64 *)v_28;
                            dst = a3[2];
                            v8 = arg_8;
                            a1 = dst + v8;
                            v2 = (__int64)a3;
                            sub_1400F27F0(a1, src, i2);
                            dst += i2;
                            arg_10 = (__int64)dst;
                            ++i;
                            result = (struct Struct_2_t *)v_30;
                            result->field_10 = i;
                            result = (struct Struct_2_t *)v_38;
                            *(__int64 *)result = (__int64)(1);
                            result->field_8 = v8;
                            result->field_10 = dst;
                            return (__int64)result;
                        }
                        if (result != 34) {
                            ++i;
                            ((__int64 *)a4)[2] = (__int64)(i);
                            v_40 = 16;
                            a3 = rsp + 64;
                            a1 = (size_t *)v_38;
                            sub_1400F60D0(a1, a4, a3);
                        } else {
                            dst = a3[2];
                            if (dst == 0) {
                                result = (struct Struct_2_t *)i;
                                result -= a2;
                                if ((result < 0)) {
                                    return (__int64)result;
                                } else {
                                    src += a2;
                                    ++i;
                                    ((__int64 *)a4)[2] = (__int64)(i);
                                    a1 = (size_t *)v_38;
                                    *a1 = 0;
                                    arg_8 = (__int64)src;
                                    a1[2] = result;
                                }
                                return arg_8;
                            } else {
                                i2 = i;
                                i2 -= a2;
                                if ((i2 < 0)) {
                                    return i2;
                                } else {
                                    src += a2;
                                    result = *a3;
                                    result = (struct Struct_2_t *)((__int64)result - (__int64)dst);
                                    if (i2 > result) {
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
                    a3 = &off_140111F10;
                    sub_1400F3869(i, v8, a3);
                    if (*a3 != 5) JUMPOUT(0x1400276a8);
                    src = (__int64 *)arg_8;
                    if (src == 0) JUMPOUT(0x1400276a8);
                    v8 = a2;
                    v2 = (__int64)a1;
                    dst = a3[2];
                    result = src + 360;
                    a1 = *(src + 626);
                    v_20 = (int)a1;
                    a1 =  + (__int64)(__int64)a1*8;
                    v11 = a1 + (__int64)(__int64)a1*2;
                    i2 = -1;
                    do {
                        if (v11 == 0) JUMPOUT(0x140027690);
                        i = result + 24;
                        a2 = result->field_8;
                        a3 = result->field_10;
                        ptr = (struct Struct_3_t *)v8;
                        ptr = (struct Struct_3_t *)((__int64)ptr - (__int64)a3);
                        if (ptr < 0) a3 = v8;
                        sub_1400F27FC(v2, a2, a3);
                        if (result != 0) ptr = result;
                        result = (ptr < 0) ? 1 : 0;
                        a1 = (ptr > 0) ? 1 : 0;
                        a1 = (size_t *)((__int64)a1 - (__int64)result);
                        v11 -= 24;
                        ++i2;
                        result = (struct Struct_2_t *)i;
                    } while (a1 == 1);
                    result = (struct Struct_2_t *)a1;
                    if (a1 != 0) JUMPOUT(0x140027695);
                    return sub_1400276AC();
                }
                v_40 = 4;
                return v_40;
            }
            if (a1 == 92) {
                return v_40;
            }
            if (a1 >= 32) {
                a3 = a2 + 1;
                a4 = (struct Struct_1_t *)v8;
                a4 = (struct Struct_1_t *)((__int64)a4 - (__int64)a3);
                a4 = (struct Struct_1_t *)((__int64)(__int64)a4 & -8);
                a1 = result + a2;
                a1 -= 7;
                v5 = (__int64)a4;
                v5 = -v5;
                while (v5 != 0) {
                    v6 = arg_8;
                    a1 += 8;
                    i = v6;
                    i = ~i;
                    src = v6 + i2;
                    dst = (__int64 *)v6;
                    dst = (__int64 *)((__int64)(__int64)dst ^ v11);
                    dst += v2;
                    dst = (__int64 *)((__int64)(__int64)dst | (__int64)src);
                    v6 ^= (__int64)ptr;
                    v6 += v2;
                    v6 |= (__int64)dst;
                    v6 &= i;
                    v5 += 8;
                    i = 0x8080808080808080;
                    v6 &= i;
                    a1 = (size_t *)((__int64)a1 - (__int64)result);
                    i = __builtin_ctzll(v6);
                    i >>= 3;
                    i += (__int64)a1;
                    a4 = (struct Struct_1_t *)v_30;
                    ((__int64 *)a4)[2] = (__int64)(i);
                    a3 = (__int64 *)v_28;
                    if (i != v8) {
                        return (__int64)a3;
                    }
                    return (__int64)a3;
                }
                a4 = (struct Struct_1_t *)((__int64)a4 + (__int64)a3);
                ptr = (struct Struct_3_t *)v_30;
                ptr->field_10 = a4;
                i = a2;
                sub_1400F6080(ptr, a2, a3, a4);
                v8 = ptr->field_8;
                i = ptr->field_10;
                a3 = (__int64 *)v_28;
                if (i != v8) {
                    return (__int64)a3;
                }
                return (__int64)a3;
            }
            return (__int64)a3;
        }
        a3 = &off_140111EF8;
        sub_1400F3869(a2, v8, a3);
        return (__int64)a3;
    }
    return (__int64)result;
}