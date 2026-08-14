// inferred from 3 accesses on `i`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

__int64 sub_140012190();
__int64 sub_140012B4C();
__int64 sub_140012B25();

__int64 __fastcall sub_1400127C0(int a1, size_t a2, int a3, size_t *a4) {
    int v_10;
    __int64 v_18;
    int v_20;
    int v_23;
    int v_24;
    int v_30;
    __int64 v_8;
    char *dst;
    __int64 *v7;
    struct Struct_1_t *i;
    __int64 v2;
    __int64 *v3;
    __int64 v9;
    __int64 v10;
    __int64 *result;
    __int64 v5;
    __int64 v8;
    __int64 v6;

    v7 = (__int64 *)a4;
    i = (struct Struct_1_t *)a3;
    v2 = a2;
    v3 = (__int64 *)a1;
    v9 = a4[4];
    ((__int64 (*)())v9)(a3, 34);
    v10 = 1;
    if (result == 0) {
        if (v2 == 0) {
            v2 = 0;
            result = 0;
        } else {
            v_18 = (__int64)v7;
            v_10 = v9;
            v_8 = (__int64)i;
            a3 = 0;
            v7 = 0;
            result = (__int64 *)v2;
            *dst = v3;
            i = (struct Struct_1_t *)v3;
            do {
                v5 = (__int64)i + (__int64)result;
                a1 = 0;
                a2 = *(__int64 *)(i + a1);
                a4 = a2 - 127;
                while (a4 >= 161) {
                    if (a2 == 34) {
                        v_20 = v5;
                        v7 += a1;
                        a2 = *(__int64 *)(i + a1);
                        v9 = a2;
                        if (v9 < 0) {
                            i += a1;
                            result = (__int64 *)v9;
                            result = (__int64 *)((__int64)(__int64)result & 31);
                            a4 = i->field_1;
                            a4 = (size_t *)((__int64)(__int64)a4 & 63);
                            if (v9 <= 223) {
                                i += 2;
                                result = (__int64 *)((__int64)(__int64)result << 6);
                                result = (__int64 *)((__int64)(__int64)result | (__int64)a4);
                                v9 = (__int64)result;
                                v8 = a3;
                                a1 = dst - 48;
                                sub_140012190(a1, v9, 0x10001, a4);
                                v3 = (__int64 *)v_23;
                                v10 = v_24;
                                result = v3;
                                result -= v10;
                                if (result != 1) {
                                    a3 = (int)v7;
                                    a2 = v8;
                                    a3 -= v8;
                                    if ((a3 < 0)) JUMPOUT(0x140012b25);
                                    if (a2 == 0) {
                                        if (v7 == 0) {
                                            v6 = v2;
                                            a2 += *dst;
                                            result = (__int64 *)v_18;
                                            v2 = *(result + 24);
                                            a1 = v_8;
                                            ((__int64 (*)())v2)(a1, a2, a3);
                                            if (result != 0) JUMPOUT(0x140012b20);
                                            if (v3 < 129) {
                                                a3 = (int)v3;
                                                a3 -= v10;
                                                a2 = v10 + dst;
                                                a2 -= 48;
                                                a1 = v_8;
                                                ((__int64 (*)())v2)(a1, a2, a3);
                                                if (result != 0) JUMPOUT(0x140012b20);
                                                a3 = 1;
                                                if (v9 < 128) {
                                                    a3 += (__int64)v7;
                                                    v2 = v6;
                                                    a1 = v_20;
                                                    result = 1;
                                                    if (v9 < 128) {
                                                        v7 = (__int64 *)((__int64)v7 + (__int64)result);
                                                        a1 -= (__int64)i;
                                                        result = (__int64 *)a1;
                                                        if (a3 > v7) JUMPOUT(0x140012b43);
                                                        v3 = *dst;
                                                        if (a3 == 0) {
                                                            result = 0;
                                                            if (v7 != 0) {
                                                                if (v7 >= v2) {
                                                                    if ((0 /* unresolved: flags != */)) JUMPOUT(0x140012b49);
                                                                } else {
                                                                    if (*(__int64 *)((__int64)v3 + (__int64)v7) <= 191) JUMPOUT(0x140012b49);
                                                                    v2 = (__int64)v7;
                                                                }
                                                            } else {
                                                                v2 = 0;
                                                            }
                                                            i = (struct Struct_1_t *)v_8;
                                                            v9 = v_10;
                                                            v10 = 1;
                                                            v7 = (__int64 *)v_18;
                                                            v2 -= (__int64)result;
                                                            v3 = (__int64 *)((__int64)v3 + (__int64)result);
                                                            a1 = (int)i;
                                                            a2 = (size_t)v3;
                                                            ((__int64 (*)())(*(v7 + 24)))();
                                                            if (result == 0) {
                                                                ((__int64 (*)())v9)(i, 34, v2);
                                                                v10 = (__int64)result;
                                                            }
                                                            result = (__int64 *)v10;
                                                            return (__int64)result;
                                                        } else {
                                                            if (a3 >= v2) {
                                                                result = (__int64 *)v2;
                                                                if ((0 /* unresolved: flags != */)) JUMPOUT(0x140012b4c);
                                                            } else {
                                                                result = (__int64 *)a3;
                                                                if (*(v3 + a3) <= 191) {
                                                                    return sub_140012B4C();
                                                                }
                                                            }
                                                            if (v7 == 0) {
                                                                return (__int64)result;
                                                            } else {
                                                                return (__int64)result;
                                                            }
                                                            return (__int64)result;
                                                        }
                                                        return (__int64)result;
                                                    }
                                                    result = 2;
                                                    if (v9 < 0x800) {
                                                        return (__int64)result;
                                                    }
                                                    /* cmp v9 , 0x10000 */;
                                                    result = 4;
                                                    result -= 0;
                                                    return (__int64)result;
                                                }
                                                a3 = 2;
                                                if (v9 < 0x800) {
                                                    return a3;
                                                }
                                                /* cmp v9 , 0x10000 */;
                                                a3 = 4;
                                                a3 -= 0;
                                                return a3;
                                            }
                                            a2 = v_30;
                                            a1 = v_8;
                                            ((__int64 (*)())(v_10))();
                                            return a1;
                                        }
                                        if (v7 >= v2) {
                                            if ((0 /* unresolved: flags != */)) JUMPOUT(0x140012b25);
                                            return a1;
                                        }
                                        result = *dst;
                                        if (*(__int64 *)((__int64)result + (__int64)v7) > 191) {
                                            return (__int64)result;
                                        }
                                        return sub_140012B25();
                                    }
                                    if (a2 >= v2) {
                                        if ((0 /* unresolved: flags != */)) JUMPOUT(0x140012b25);
                                        return (__int64)result;
                                    }
                                    result = *dst;
                                    if (*(result + a2) > 191) {
                                        return (__int64)result;
                                    }
                                    return sub_140012B25();
                                }
                                a3 = v8;
                                a1 = v_20;
                                result = 1;
                                if (v9 >= 128) {
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            a1 = i->field_2;
                            a4 = (size_t *)((__int64)(__int64)a4 << 6);
                            a1 &= 63;
                            a1 |= (__int64)a4;
                            if (a2 < 240) {
                                i += 3;
                                result = (__int64 *)((__int64)(__int64)result << 12);
                                a1 |= (__int64)result;
                                v9 = a1;
                                return v9;
                            }
                            v9 = i->field_3;
                            i += 4;
                            result = (__int64 *)((__int64)(__int64)result & 7);
                            result = (__int64 *)((__int64)(__int64)result << 18);
                            a1 <<= 6;
                            v9 &= 63;
                            v9 |= a1;
                            v9 |= (__int64)result;
                            if (v9 != 0x110000) {
                                return v9;
                            }
                            a1 = v_20;
                            a1 -= (__int64)i;
                            result = (__int64 *)a1;
                            return (__int64)result;
                        }
                        i += a1;
                        ++i;
                        return (__int64)i;
                    }
                    if (a2 == 92) {
                        return (__int64)i;
                    }
                    ++a1;
                    v7 = (__int64 *)((__int64)v7 + (__int64)result);
                    return (__int64)v7;
                }
                return (__int64)v7;
            } while ((a1 != 0));
            return (__int64)v7;
        }
        return (__int64)v7;
    }
    return (__int64)result;
}