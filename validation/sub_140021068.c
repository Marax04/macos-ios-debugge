// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char field_0; // offset 0
    char field_1; // offset 1
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 5 accesses on `ptr2`
struct Struct_2_t {
    char field_0; // offset 0
    char field_1; // offset 1
    char field_2; // offset 2
    char field_3; // offset 3
    __int64 field_4; // offset 4
};

__int64 sub_14001A580();
__int64 sub_140021AD5();
__int64 sub_140021E7D();
__int64 sub_1400F3B80();
__int64 sub_1400F3869();
__int64 sub_140021A85();
__int64 sub_1400F3810();
__int64 sub_140021AAE();
extern __int64 off_140110BD0;
extern __int64 off_140110B10;
extern __int64 off_140110A60;
extern __int64 off_140110CA8;
extern __int64 off_140114200;
extern __int64 off_1401141E8;
extern __int64 off_1401141D0;
extern __int64 off_140110AE0;
extern __int64 off_140110B28;
extern __int64 off_140110B88;
extern __int64 off_140110C08;

__int64 __fastcall sub_140021068(size_t *a1, size_t *a2, int *a3) {
    int arg_1;
    int arg_10;
    int arg_18;
    int arg_2;
    __int64 arg_20;
    __int64 arg_28;
    int arg_3;
    __int64 arg_30;
    int arg_38;
    int arg_40;
    __int64 arg_48;
    __int64 arg_50;
    int arg_8;
    int v_10;
    int v_18;
    __int64 v_20;
    int v_28;
    int v_29;
    int v_2b;
    int v_2f;
    int v_30;
    int v_38;
    int v_48;
    int v_50;
    char *src;
    __int64 i;
    struct Struct_2_t *ptr2;
    __int64 v5;
    __int64 *v2;
    __int64 v11;
    __int64 *result;
    __int64 v7;
    __int64 v4;
    __int64 v8;
    __int64 xmm0;
    struct Struct_1_t *ptr;
    __int64 v3;

    i = (__int64)a3;
    ptr2 = (struct Struct_2_t *)a2;
    arg_40 = (int)a1;
    v_20 = 6;
    v5 = &off_140110BD0;
    v2 = src - 56;
    sub_14001A580(v2, a2, a3, v5);
    if (*v2 == 0) {
        v2 = src - 80;
        v11 = src - 56;
        do {
            sub_140021AD5(v2, v11, a3, v5);
            result = (__int64 *)v_50;
        } while (result == 1);
        if (result != 0) {
            arg_50 = (__int64)ptr2;
            ptr2 = (struct Struct_2_t *)arg_50;
        } else {
            v5 = v_48;
            a3 = (int *)v5;
            a3 += 6;
            if (!((a3 == 0))) {
                if (a3 >= i) {
                    if (!((0 /* unresolved: flags != */))) {
                        a3 = (int *)((__int64)a3 + (__int64)ptr2);
                        result = i + ptr2;
                        while (a3 != result) {
                            v7 = *a3;
                            a1 = (size_t *)v7;
                            if (a1 < 0) {
                                a2 = a1;
                                a2 = (size_t *)((__int64)(__int64)a2 & 31);
                                v4 = arg_1;
                                v4 &= 63;
                                if (a1 <= 223) {
                                    a3 += 2;
                                    a2 = (size_t *)((__int64)(__int64)a2 << 6);
                                    a2 = (size_t *)((__int64)(__int64)a2 | v4);
                                    a1 = a2;
                                    a2 = a1 - 58;
                                    a2 = (a2 < 0xFFFFFFF6) ? 1 : 0;
                                    a1 += 0xFFFFFFB9;
                                    a1 = (a1 < 0xFFFFFFF9) ? 1 : 0;
                                    if (i >= 3) {
                                        result = ptr2->field_0;
                                        result = (__int64 *)((__int64)(__int64)result ^ 0x5A5F);
                                        a1 = ptr2->field_2;
                                        a1 = (size_t *)((__int64)(__int64)a1 ^ 78);
                                        a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                        if ((a1 == 0)) {
                                            v11 = -3;
                                            a3 = 3;
                                            if (i != 3) {
                                                if (ptr2->field_3 <= 191) JUMPOUT(0x140021aa7);
                                                v2 = (__int64 *)i;
                                            } else {
                                                v2 = 3;
                                            }
                                            v11 += (__int64)v2;
                                            a3 = (int *)((__int64)a3 + (__int64)ptr2);
                                            v5 = a3 + v11;
                                            result = 0;
                                            while (v11 != result) {
                                                /* cmp *((__int64)a3 + (__int64)result) , 0 */;
                                                ++result;
                                                if (v2 < 3) {
                                                    v2 = 2;
                                                    v8 = 2;
                                                    if (ptr2->field_0 == 82) {
                                                        result = ptr2->field_1;
                                                        if (result > 191) {
                                                            v11 = ptr2 + 1;
                                                            i = -1;
                                                            result += 191;
                                                            v8 = 2;
                                                            if (result <= 25) {
                                                                i += (__int64)v2;
                                                                result = 0;
                                                                while (i != result) {
                                                                    /* cmp *(v11 + result) , 0 */;
                                                                    ++result;
                                                                    result = (__int64 *)arg_40;
                                                                    *result = v8;
                                                                    return (__int64)result;
                                                                }
                                                                a1 = src - 56;
                                                                *a1 = v11;
                                                                arg_8 = i;
                                                                result = 0;
                                                                a1[2] = result;
                                                                a1[3] = result;
                                                                a1[4] = result;
                                                                a1[5] = result;
                                                                sub_140021E7D(a1, 0, 4, v5);
                                                                if (result == 0) {
                                                                    a1 = (size_t *)v_38;
                                                                    if (a1 != 0) {
                                                                        result = (__int64 *)v_30;
                                                                        a2 = (size_t *)v_29;
                                                                        a2 = (size_t *)((__int64)(__int64)a2 << 16);
                                                                        a3 = (int *)v_2b;
                                                                        a3 = (int *)((__int64)(__int64)a3 | (__int64)a2);
                                                                        a3 = (int *)((__int64)(__int64)a3 << 32);
                                                                        v5 = v_2f;
                                                                        v5 |= (__int64)a3;
                                                                        a3 = (int *)v_28;
                                                                        v5 <<= 8;
                                                                        v5 |= (__int64)result;
                                                                        if (a3 < v5) {
                                                                            result = *(__int64 *)((__int64)a1 + (__int64)a3);
                                                                            result += 191;
                                                                            if (result < 26) {
                                                                                result = src - 56;
                                                                                xmm0 = arg_18;
                                                                                *result = a1;
                                                                                arg_8 = v5;
                                                                                arg_10 = (int)a3;
                                                                                /* movlps %xmm0, 24(%(__int64)result) */;
                                                                                arg_20 = 0;
                                                                                arg_28 = 0;
                                                                                sub_140021E7D(result, 0, a3, v5);
                                                                                if (result != 0) {
                                                                                    result = &off_140110B10;
                                                                                    v_20 = (__int64)result;
                                                                                    a1 = &off_140110A60;
                                                                                    v5 = &off_140110CA8;
                                                                                    a3 = src - 80;
                                                                                    sub_1400F3B80(a1, 61, a3, v5);
                                                                                    ptr2 += v5;
                                                                                    if (a2 > ptr2) ptr2 = a2;
                                                                                    a3 = &off_140114200;
                                                                                    sub_1400F3869(ptr2, a2, a3);
                                                                                    a3 = &off_1401141E8;
                                                                                    sub_1400F3869(ptr, a2, a3);
                                                                                    a3 = &off_1401141D0;
                                                                                    sub_1400F3869(a1, result, a3);
                                                                                    v5 += v4;
                                                                                    if (a2 > v5) v5 = a2;
                                                                                    a3 = &off_140114200;
                                                                                    sub_1400F3869(v5, a2, a3, v5);
                                                                                    result = &off_140110AE0;
                                                                                    v_20 = (__int64)result;
                                                                                    a3 = 1;
                                                                                    return sub_140021A85();
                                                                                } else {
                                                                                    a1 = (size_t *)v_38;
                                                                                    if (a1 != 0) {
                                                                                        v5 = v_30;
                                                                                        a3 = (int *)v_28;
                                                                                        if (a3 != 0) {
                                                                                            if (v5 <= a3) {
                                                                                                if ((0 /* unresolved: flags != */)) {
                                                                                                    result = &off_140110B28;
                                                                                                    v_20 = (__int64)result;
                                                                                                    sub_1400F3810(a1, v5, a3, v5);
                                                                                                    i = 0;
                                                                                                    v5 -= (__int64)a1;
                                                                                                } else {
                                                                                                    a1 = (size_t *)((__int64)a1 + (__int64)a3);
                                                                                                    v5 -= (__int64)a3;
                                                                                                    a3 = 0;
                                                                                                }
                                                                                                if (v5 == 0) {
                                                                                                    v5 = 0;
                                                                                                } else {
                                                                                                    v8 = 2;
                                                                                                    if (*a1 == 46) {
                                                                                                        result = a1 + v5;
                                                                                                        v7 = 46;
                                                                                                        ptr = (struct Struct_1_t *)a1;
                                                                                                        do {
                                                                                                            a2 = (size_t *)v7;
                                                                                                            a2 = (size_t *)((__int64)(__int64)a2 & 31);
                                                                                                            v4 = (__int64)a2;
                                                                                                            a2 = ptr->field_1;
                                                                                                            a2 = (size_t *)((__int64)(__int64)a2 & 63);
                                                                                                            if (v7 <= 223) {
                                                                                                                ptr += 2;
                                                                                                                v4 <<= 6;
                                                                                                                v4 |= (__int64)a2;
                                                                                                                v7 = v4;
                                                                                                                a2 = (size_t *)v7;
                                                                                                                a2 = (size_t *)((__int64)(__int64)a2 & 0x1FFFDF);
                                                                                                                a2 += 0xFFFFFFBF;
                                                                                                                a2 = (a2 < 26) ? 1 : 0;
                                                                                                                v3 = v7 - 48;
                                                                                                                v3 = (v3 < 10) ? 1 : 0;
                                                                                                                v4 = v7 - 33;
                                                                                                                v4 = (v4 < 15) ? 1 : 0;
                                                                                                                v4 |= v3;
                                                                                                                v4 |= (__int64)a2;
                                                                                                                if ((v4 != 0)) {
                                                                                                                    if (ptr != result) {
                                                                                                                        v7 = ptr->field_0;
                                                                                                                    }
                                                                                                                    result = (__int64 *)arg_40;
                                                                                                                    arg_8 = (int)a3;
                                                                                                                    arg_10 = v11;
                                                                                                                    arg_18 = i;
                                                                                                                    arg_20 = (__int64)ptr2;
                                                                                                                    arg_28 = (__int64)v2;
                                                                                                                    arg_30 = (__int64)a1;
                                                                                                                    arg_38 = v5;
                                                                                                                    v8 = 1;
                                                                                                                    return v8;
                                                                                                                }
                                                                                                                a2 = v7 - 58;
                                                                                                                if (a2 > 38) {
                                                                                                                    v7 += 0xFFFFFF81;
                                                                                                                    if (v7 >= 0xFFFFFFFC) {
                                                                                                                        return v7;
                                                                                                                    }
                                                                                                                    return v7;
                                                                                                                }
                                                                                                                v3 = 0x7E0000007F;
                                                                                                                if ((!((v3 >> (__int64)a2) & 1))) {
                                                                                                                    return v3;
                                                                                                                }
                                                                                                                return v3;
                                                                                                            }
                                                                                                            v3 = (__int64)ptr2;
                                                                                                            ptr2 = ptr->field_2;
                                                                                                            a2 = (size_t *)((__int64)(__int64)a2 << 6);
                                                                                                            ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 & 63);
                                                                                                            ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 | (__int64)a2);
                                                                                                            if (v7 < 240) {
                                                                                                                ptr += 3;
                                                                                                                v4 <<= 12;
                                                                                                                ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 | v4);
                                                                                                                v7 = (__int64)ptr2;
                                                                                                                ptr2 = (struct Struct_2_t *)v3;
                                                                                                                return (__int64)ptr2;
                                                                                                            }
                                                                                                            v7 = ptr->field_3;
                                                                                                            v4 &= 7;
                                                                                                            v4 <<= 18;
                                                                                                            ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 << 6);
                                                                                                            v7 &= 63;
                                                                                                            v7 |= (__int64)ptr2;
                                                                                                            v7 |= v4;
                                                                                                            if (v7 != 0x110000) {
                                                                                                                ptr += 4;
                                                                                                                return (__int64)ptr;
                                                                                                            }
                                                                                                            ptr2 = (struct Struct_2_t *)v3;
                                                                                                            return (__int64)ptr2;
                                                                                                        } while (true);
                                                                                                    }
                                                                                                    return (__int64)ptr2;
                                                                                                }
                                                                                                return (__int64)ptr2;
                                                                                            } else {
                                                                                                if (*(__int64 *)((__int64)a1 + (__int64)a3) > 191) {
                                                                                                    return (__int64)ptr2;
                                                                                                } else {
                                                                                                    return (__int64)ptr2;
                                                                                                }
                                                                                                return (__int64)ptr2;
                                                                                            }
                                                                                            return (__int64)ptr2;
                                                                                        }
                                                                                        return (__int64)ptr2;
                                                                                    }
                                                                                    return (__int64)ptr2;
                                                                                }
                                                                            }
                                                                        }
                                                                        return (__int64)ptr2;
                                                                    }
                                                                    return (__int64)ptr2;
                                                                }
                                                                return (__int64)ptr2;
                                                            }
                                                            return (__int64)ptr2;
                                                        }
                                                        return (__int64)ptr2;
                                                    }
                                                } else {
                                                    if (ptr2->field_0 == 0x525F) {
                                                        result = ptr2->field_2;
                                                        if (result <= 191) JUMPOUT(0x140021a73);
                                                        v11 = ptr2 + 2;
                                                        i = -2;
                                                    } else {
                                                        if (ptr2->field_0 == 82) {
                                                            return i;
                                                        } else {
                                                            v8 = 2;
                                                            if (v2 != 3) {
                                                                result = ptr2->field_0;
                                                                result = (__int64 *)((__int64)(__int64)result ^ 0x5F5F);
                                                                a1 = ptr2->field_2;
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ 82);
                                                                a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                if (!((a1 != 0))) {
                                                                    result = ptr2->field_3;
                                                                    if (result <= 191) JUMPOUT(0x140021ac1);
                                                                    v11 = ptr2 + 3;
                                                                    i = -3;
                                                                    return i;
                                                                }
                                                            }
                                                            return i;
                                                        }
                                                        return i;
                                                    }
                                                    return i;
                                                }
                                                return i;
                                            }
                                            if (v11 != 0) {
                                                a1 = *a3;
                                                a2 = a1;
                                                if (a2 < 0) {
                                                    result = (__int64 *)a2;
                                                    result = (__int64 *)((__int64)(__int64)result & 31);
                                                    ptr = (struct Struct_1_t *)arg_1;
                                                    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 63);
                                                    if (a2 <= 223) {
                                                        a1 = a3 + 2;
                                                        result = (__int64 *)((__int64)(__int64)result << 6);
                                                        result = (__int64 *)((__int64)(__int64)result | (__int64)ptr);
                                                        a2 = (size_t *)result;
                                                    } else {
                                                        a2 = (size_t *)arg_2;
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 6);
                                                        a2 = (size_t *)((__int64)(__int64)a2 & 63);
                                                        a2 = (size_t *)((__int64)(__int64)a2 | (__int64)ptr);
                                                        if (a1 < 240) {
                                                            a1 = a3 + 3;
                                                            result = (__int64 *)((__int64)(__int64)result << 12);
                                                            a2 = (size_t *)((__int64)(__int64)a2 | (__int64)result);
                                                        } else {
                                                            a1 = a3 + 4;
                                                            ptr = (struct Struct_1_t *)arg_3;
                                                            result = (__int64 *)((__int64)(__int64)result & 7);
                                                            result = (__int64 *)((__int64)(__int64)result << 18);
                                                            a2 = (size_t *)((__int64)(__int64)a2 << 6);
                                                            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 63);
                                                            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | (__int64)a2);
                                                            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | (__int64)result);
                                                            a2 = (size_t *)ptr;
                                                        }
                                                    }
                                                } else {
                                                    a1 = a3 + 1;
                                                }
                                                if (a2 != 69) {
                                                    if (a2 != 0x110000) {
                                                        i = 0;
                                                        ptr = 10;
                                                        result = a2 - 48;
                                                        while (result <= 9) {
                                                            result = 0;
                                                            v7 = a2 - 48;
                                                            while (v7 < 10) {
                                                                result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)ptr); /* unsigned; high half in a2 */;
                                                                a2 = (size_t *)result;
                                                                result = (__int64 *)v7;
                                                                v7 = (0 /* unresolved: flags OF */) ? 1 : 0;
                                                                result = (__int64 *)((__int64)result + (__int64)a2);
                                                                a2 = (result < 0) ? 1 : 0;
                                                                if (v7 == 0) {
                                                                    if (a2 == 0) {
                                                                        if (a1 != v5) {
                                                                            v4 = *a1;
                                                                            a2 = (size_t *)v4;
                                                                            if (a2 < 0) {
                                                                                v7 = (__int64)a2;
                                                                                v7 &= 31;
                                                                                v8 = arg_1;
                                                                                v8 &= 63;
                                                                                if (a2 <= 223) {
                                                                                    a1 += 2;
                                                                                    v7 <<= 6;
                                                                                    v7 |= v8;
                                                                                    a2 = (size_t *)v7;
                                                                                    if (a2 != 0x110000) {
                                                                                    }
                                                                                    return (__int64)a2;
                                                                                }
                                                                                a2 = (size_t *)arg_2;
                                                                                v8 <<= 6;
                                                                                a2 = (size_t *)((__int64)(__int64)a2 & 63);
                                                                                a2 = (size_t *)((__int64)(__int64)a2 | v8);
                                                                                if (v4 < 240) {
                                                                                    a1 += 3;
                                                                                    v7 <<= 12;
                                                                                    a2 = (size_t *)((__int64)(__int64)a2 | v7);
                                                                                    return (__int64)a2;
                                                                                }
                                                                                v3 = arg_3;
                                                                                a1 += 4;
                                                                                v7 &= 7;
                                                                                v7 <<= 18;
                                                                                a2 = (size_t *)((__int64)(__int64)a2 << 6);
                                                                                v3 &= 63;
                                                                                v3 |= (__int64)a2;
                                                                                v3 |= v7;
                                                                                a2 = (size_t *)v3;
                                                                                return (__int64)a2;
                                                                            }
                                                                            ++a1;
                                                                            return (__int64)a1;
                                                                        }
                                                                    }
                                                                }
                                                                return (__int64)a1;
                                                            }
                                                            if (result == 0) {
                                                                ++i;
                                                                return i;
                                                            }
                                                            while (a1 != v5) {
                                                                v8 = *a1;
                                                                a2 = (size_t *)v8;
                                                                if (a2 < 0) {
                                                                    v3 = (__int64)ptr2;
                                                                    v7 = (__int64)a2;
                                                                    v7 &= 31;
                                                                    ptr2 = (struct Struct_2_t *)arg_1;
                                                                    ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 & 63);
                                                                    if (a2 <= 223) {
                                                                        a1 += 2;
                                                                        v7 <<= 6;
                                                                        v7 |= (__int64)ptr2;
                                                                        a2 = (size_t *)v7;
                                                                        ptr2 = (struct Struct_2_t *)v3;
                                                                        --result;
                                                                        return (__int64)result;
                                                                    }
                                                                    v4 = arg_2;
                                                                    ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 << 6);
                                                                    v4 &= 63;
                                                                    v4 |= (__int64)ptr2;
                                                                    if (v8 < 240) {
                                                                        a1 += 3;
                                                                        v7 <<= 12;
                                                                        v4 |= v7;
                                                                        a2 = (size_t *)v4;
                                                                        return (__int64)a2;
                                                                    }
                                                                    a2 = (size_t *)arg_3;
                                                                    v7 &= 7;
                                                                    v7 <<= 18;
                                                                    v4 <<= 6;
                                                                    a2 = (size_t *)((__int64)(__int64)a2 & 63);
                                                                    a2 = (size_t *)((__int64)(__int64)a2 | v4);
                                                                    a2 = (size_t *)((__int64)(__int64)a2 | v7);
                                                                    ptr2 = (struct Struct_2_t *)v3;
                                                                    if (a2 != 0x110000) {
                                                                        a1 += 4;
                                                                        return (__int64)a1;
                                                                    }
                                                                    return (__int64)a1;
                                                                }
                                                                ++a1;
                                                                return (__int64)a1;
                                                            }
                                                        }
                                                    }
                                                    return (__int64)a1;
                                                }
                                                return (__int64)a1;
                                            }
                                            return (__int64)a1;
                                        } else {
                                            if (ptr2->field_0 == 0x4E5A) {
                                                if (ptr2->field_2 <= 191) JUMPOUT(0x140021a93);
                                                a3 = 2;
                                                v11 = -2;
                                            } else {
                                                v2 = 3;
                                                if (i != 3) {
                                                    if (ptr2->field_0 == 0x4E5A5F5F) {
                                                        v11 = -4;
                                                        if (i < 5) {
                                                            v2 = 4;
                                                        } else {
                                                            if (ptr2->field_4 > 191) {
                                                                return (__int64)v2;
                                                            } else {
                                                                result = &off_140110B88;
                                                                return sub_140021AAE();
                                                            }
                                                        }
                                                        return (__int64)result;
                                                    } else {
                                                        v2 = (__int64 *)i;
                                                    }
                                                }
                                                return (__int64)v2;
                                            }
                                        }
                                        return (__int64)v2;
                                    } else {
                                        v8 = 2;
                                        if (i == 2) {
                                            if (ptr2->field_0 == 0x4E5A) {
                                                v11 = -2;
                                                v2 = 2;
                                                a3 = 2;
                                                return (__int64)a3;
                                            }
                                            return (__int64)a3;
                                        }
                                        return (__int64)a3;
                                    }
                                    return (__int64)a3;
                                }
                                ptr = (struct Struct_1_t *)arg_2;
                                v4 <<= 6;
                                ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 63);
                                ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | v4);
                                if (v7 < 240) {
                                    a3 += 3;
                                    a2 = (size_t *)((__int64)(__int64)a2 << 12);
                                    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | (__int64)a2);
                                    a1 = (size_t *)ptr;
                                    return (__int64)a1;
                                }
                                a1 = (size_t *)arg_3;
                                a2 = (size_t *)((__int64)(__int64)a2 & 7);
                                a2 = (size_t *)((__int64)(__int64)a2 << 18);
                                ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 6);
                                a1 = (size_t *)((__int64)(__int64)a1 & 63);
                                a1 = (size_t *)((__int64)(__int64)a1 | (__int64)ptr);
                                a1 = (size_t *)((__int64)(__int64)a1 | (__int64)a2);
                                if (a1 != 0x110000) {
                                    a3 += 4;
                                    return (__int64)a3;
                                }
                                if (v5 == 0) {
                                    v8 = 2;
                                } else {
                                    if (v5 >= i) {
                                        if ((0 /* unresolved: flags != */)) JUMPOUT(0x140021a59);
                                    } else {
                                        if (*(__int64 *)(ptr2 + v5) <= 191) JUMPOUT(0x140021a59);
                                        i = v5;
                                    }
                                    return i;
                                }
                                return i;
                            }
                            ++a3;
                            return (__int64)a3;
                        }
                        return (__int64)a3;
                    }
                } else {
                    if (*(__int64 *)((__int64)ptr2 + (__int64)a3) > 191) {
                        return (__int64)a3;
                    }
                }
                result = &off_140110C08;
                return sub_140021AAE();
            }
            return (__int64)result;
        }
        return (__int64)result;
    } else {
        arg_50 = (__int64)ptr2;
        v11 = *src;
        a3 = (int *)arg_10;
        result = (__int64 *)arg_28;
        a1 = result - 1;
        a2 = (size_t *)arg_18;
        v2 = (__int64 *)arg_20;
        if (v11 == -1) {
            v5 = v_10;
            v7 = (__int64)a1;
            a1 += v5;
            if (a1 < a2) {
                v11 = v_18;
                v4 = v_30;
                ptr = (struct Struct_1_t *)v_20;
                arg_48 = (__int64)ptr;
                ptr2 = v4 - 1;
                do {
                    a1 = *(__int64 *)((__int64)a3 + (__int64)a1);
                    v5 += (__int64)result;
                    a1 = v5 + v7;
                } while (a1 < a2);
            }
        } else {
            v5 = v_10;
            arg_48 = (__int64)a1;
            a1 += v5;
            if (a1 < a2) {
                v7 = v_18;
                v3 = v_30;
                ptr = (struct Struct_1_t *)v_20;
                v4 = (__int64)result;
                arg_30 = (__int64)ptr;
                v4 -= (__int64)ptr;
                arg_38 = v4;
                do {
                    a1 = *(__int64 *)((__int64)a3 + (__int64)a1);
                    v5 += (__int64)result;
                    v11 = 0;
                    a1 = (size_t *)arg_48;
                    a1 += v5;
                } while (a1 < a2);
            }
        }
    }
    return (__int64)result;
}