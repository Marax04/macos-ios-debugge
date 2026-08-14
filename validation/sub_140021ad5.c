// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3810();
__int64 sub_140021E62();
extern __int64 off_140114D58;
extern __int64 off_140114200;

__int64 __fastcall sub_140021AD5(__int64 *a1,struct Struct_1_t *a2) {
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_8;
    char *dst;
    __int64 *dst2;
    __int64 i;
    __int64 *result;
    __int64 v5;
    __int64 *dst3;
    __int64 i2;
    __int64 v2;
    __int64 *src;
    __int64 *src2;
    __int64 v10;
    __int64 v9;
    __int64 v12;

    if (a2->field_0 != 1) {
        dst2 = 2;
        if (((__int64 *)a2)[3] == 0) {
            i = ((__int64 *)a2)[3];
            result = (__int64 *)i;
            result = (__int64 *)((__int64)(__int64)result ^ 1);
            ((__int64 *)a2)[3] = (__int64)(result);
            v5 = a2->field_8;
            result = ((__int64 *)a2)[9];
            dst3 = ((__int64 *)a2)[10];
            if (v5 != 0) {
                if (v5 >= dst3) {
                    if ((0 /* unresolved: flags != */)) {
                        a1 = &off_140114D58;
                        v_20 = (int)a1;
                        sub_1400F3810(result, dst3, v5, dst3);
                        a1 = (__int64 *)v_10;
                        dst3 = a1 + 8;
                        dst2 = a1 + 16;
                        if (i != 0) {
                            i2 = i;
                            do {
                                if (!((0 /* unresolved: flags == */))) {
                                    ++i2;
                                    result = 0;
                                }
                                if (i <= result) i = result;
                                ((__int64 *)a2)[5] = (__int64)(i);
                                *dst3 = v5;
                                *dst2 = result;
                                dst2 = 1;
                                *a1 = dst2;
                                return (__int64)dst2;
                            } while ((i2 != 0));
                        }
                        return (__int64)dst2;
                    } else {
                        if (v5 != dst3) {
                            v2 = *(result + v5);
                            dst3 = (__int64 *)v2;
                            if (dst3 < 0) {
                                dst2 = dst3;
                                dst2 = (__int64 *)((__int64)(__int64)dst2 & 31);
                                src = *(result + v5 + 1);
                                src = (__int64 *)((__int64)(__int64)src & 63);
                                if (dst3 <= 223) {
                                    dst2 = (__int64 *)((__int64)(__int64)dst2 << 6);
                                    dst2 = (__int64 *)((__int64)(__int64)dst2 | (__int64)src);
                                    dst3 = dst2;
                                } else {
                                    dst3 = *(result + v5 + 2);
                                    src = (__int64 *)((__int64)(__int64)src << 6);
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 & 63);
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 | (__int64)src);
                                    if (v2 < 240) {
                                        dst2 = (__int64 *)((__int64)(__int64)dst2 << 12);
                                        dst3 = (__int64 *)((__int64)(__int64)dst3 | (__int64)dst2);
                                    } else {
                                        result = *(result + v5 + 3);
                                        dst2 = (__int64 *)((__int64)(__int64)dst2 & 7);
                                        dst2 = (__int64 *)((__int64)(__int64)dst2 << 18);
                                        dst3 = (__int64 *)((__int64)(__int64)dst3 << 6);
                                        result = (__int64 *)((__int64)(__int64)result & 63);
                                        result = (__int64 *)((__int64)(__int64)result | (__int64)dst3);
                                        result = (__int64 *)((__int64)(__int64)result | (__int64)dst2);
                                        dst3 = result;
                                    }
                                }
                            }
                            if (i == 0) {
                                dst2 = 1;
                                result = 1;
                                if (dst3 >= 128) {
                                    result = 2;
                                    if (dst3 >= 0x800) {
                                        /* cmp dst3 , 0x10000 */;
                                        result = 4;
                                        result -= 0;
                                    }
                                }
                                result += v5;
                                a2->field_8 = result;
                                *(a1 + 8) = v5;
                                a1[2] = result;
                            } else {
                                *(a1 + 8) = v5;
                                a1[2] = v5;
                                dst2 = 0;
                            }
                            return (__int64)dst2;
                        } else {
                            if (i != 0) {
                                return (__int64)dst2;
                            } else {
                                ((__int64 *)a2)[3] = (__int64)(1);
                            }
                            return (__int64)dst2;
                        }
                        return (__int64)dst2;
                    }
                    return (__int64)dst2;
                } else {
                    if (*(result + v5) >= 192) {
                        return (__int64)dst2;
                    } else {
                        return (__int64)dst2;
                    }
                    return (__int64)dst2;
                }
                return (__int64)dst2;
            }
            return (__int64)dst2;
        }
    } else {
        v5 = ((__int64 *)a2)[5];
        result = ((__int64 *)a2)[10];
        dst2 = 2;
        if (v5 != result) {
            v_10 = (int)a1;
            src = ((__int64 *)a2)[9];
            dst2 = ((__int64 *)a2)[12];
            dst3 = v5 + dst2;
            --dst3;
            i = (__int64)result;
            if (dst3 < result) {
                a1 = ((__int64 *)a2)[7];
                src2 = ((__int64 *)a2)[11];
                i = dst2 - 1;
                v_30 = i;
                i2 = ((__int64 *)a2)[4];
                v10 = a2->field_8;
                i = ((__int64 *)a2)[3];
                v2 = (__int64)dst2;
                v2 -= i;
                v_18 = v2;
                i += v5;
                v_20 = i;
                i = v5 + dst2;
                *dst = i;
                i = v5;
                i -= v10;
                ++i;
                v_28 = i;
                v9 = src + v5;
                v12 = (__int64)a1;
                i = v5;
                v_8 = i2;
                while (v5 == i) {
                    dst3 = *(__int64 *)((__int64)src + (__int64)dst3);
                    if ((!((i2 >> (__int64)dst3) & 1))) {
                        i = *dst;
                        ((__int64 *)a2)[5] = (__int64)(i);
                        if (a1 == -1) {
                            dst3 = (__int64 *)v_30;
                            dst3 += i;
                            a1 = (__int64 *)v_10;
                            dst3 = a1 + 8;
                            dst2 = a1 + 16;
                            i = (__int64)result;
                            return i;
                        }
                        dst3 = 0;
                        i = *dst;
                        ((__int64 *)a2)[7] = (__int64)(dst3);
                        v12 = (__int64)dst3;
                        return v12;
                    }
                    dst3 = (__int64 *)v10;
                    if (v12 > v10) v10 = v12;
                    if (a1 == -1) v10 = v10;
                    i2 = v10;
                    while (i2 < dst2) {
                        i = i2;
                        i2 += v5;
                        if (i2 < result) {
                            i2 = i + 1;
                            v2 = *(src2 + i);
                            i += v_28;
                            ((__int64 *)a2)[5] = (__int64)(i);
                            if (a1 == -1) {
                                i2 = v_8;
                                return i2;
                            }
                            dst3 = 0;
                            i2 = v_8;
                            return i2;
                        }
                        dst3 += v5;
                        if (result > dst3) dst3 = result;
                        v5 = &off_140114200;
                        a1 = dst3;
                        return sub_140021E62();
                    }
                    i2 = v12;
                    dst3 = 0;
                    if (a1 == -1) v12 = dst3;
                    dst3 = (__int64 *)v10;
                    while (i2 < dst3) {
                        --dst3;
                        if (dst3 >= dst2) JUMPOUT(0x140021e6a);
                        i = dst3 + v5;
                        if (i >= result) JUMPOUT(0x140021e58);
                        v2 = *(__int64 *)((__int64)src2 + (__int64)dst3);
                        i = v_20;
                        ((__int64 *)a2)[5] = (__int64)(i);
                        dst3 = (__int64 *)v_18;
                        i2 = v_8;
                        if (a1 == -1) {
                            return i2;
                        }
                        return i2;
                    }
                    result = *dst;
                    ((__int64 *)a2)[5] = (__int64)(result);
                    if (a1 != -1) {
                        ((__int64 *)a2)[7] = (__int64)(0);
                    }
                    a1 = (__int64 *)v_10;
                    *(a1 + 8) = v5;
                    result = *dst;
                    a1[2] = result;
                    return (__int64)result;
                }
            }
            return (__int64)result;
        }
    }
    return (__int64)result;
}