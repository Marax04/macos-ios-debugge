// inferred from 2 accesses on `i`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_1400F37D0();
__int64 sub_1400F27F0();
__int64 sub_1400F3360();
__int64 sub_140011760();
__int64 sub_1400F35E0();
__int64 sub_1400F3810();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14005820F();
__int64 sub_140056CD0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401168C8;
extern __int64 off_140116950;
extern __int64 off_140121F04;
extern __int64 off_140115B90;
extern __int64 off_14000E2E0;
extern __int64 off_1401175D8;
extern __int64 off_140115C88;
extern __int64 off_140121F84;
extern __int64 off_140121F18;
extern __int64 off_140115BA4;
extern __int64 off_140115C38;
extern __int64 off_140116968;
extern __int64 off_140115C08;
extern __int64 off_140115C20;
extern __int64 off_140018760;
extern __int64 off_140115C60;
extern __int64 off_140119C98;
extern __int64 off_140115C70;

__int64 __fastcall sub_1400578F0(size_t a1, size_t *a2, size_t *a3, size_t a4) {
    __int64 rsp;
    __int64 arg_10;
    int arg_18;
    int arg_20;
    int arg_28;
    int arg_8;
    __int64 v_128;
    int v_130;
    __int64 v_138;
    int v_140;
    __int64 v_148;
    int v_150;
    __int64 v_20;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    __int64 v_50;
    __int64 v_5c;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    __int64 v_98;
    int v_a0;
    __int64 v_a8;
    int v_b0;
    __int64 v_b8;
    int v_c0;
    int *v_0;
    __int64 v2;
    __int64 *result;
    struct Struct_1_t *i;
    __int64 v4;
    __int64 v9;
    __int64 v7;
    __int64 v5;
    int v6;
    __int64 v3;
    __int64 v8;
    __int64 v11;

    if (a4 >= a3) {
        a1 = &off_1401168C8;
        a3 = &off_140116950;
        sub_1400F37D0(a1, 32, a3);
    } else {
        v2 = a4;
        v_88 = a1;
        a1 = a4 + a4*8;
        a1 <<= 4;
        result = a2 + a1;
        v_90 = (int)a2;
        a1 = *(a2 + a1 + 24);
        if (a1 != a2) {
            i = 0x8000000000000000;
            i = (struct Struct_1_t *)((__int64)(__int64)i ^ a1);
            v4 = 1;
            if (a1 >= 0) i = v4;
            if (i == 0) {
                sub_1400F27F0(v4, 1, i, a4);
            } else {
                if (i == 1) {
                    i = (struct Struct_1_t *)arg_28;
                    if (i < 0) {
                        sub_1400F3360(a1, 0x8000000000000003);
                        i = (struct Struct_1_t *)arg_8;
                        v9 = arg_10;
                        result = (v9 != 0) ? 1 : 0;
                        if (v9 == 0) {
                            a3 = 1;
                        } else {
                            v7 = v2;
                            result = 1;
                            a3 = 0;
                            v5 = 1;
                            a1 = 0;
                            v6 = 0;
                            a4 = 0;
                            a2 = 0;
                            do {
                                v3 = *(__int64 *)((__int64)i + (__int64)a3);
                                v4 = v3;
                                v2 = v3 - 48;
                                if (v4 > 38) {
                                    if (v4 == 39) {
                                        a1 = 1;
                                        ++a3;
                                        a2 = (size_t *)((__int64)(__int64)a2 | a4);
                                        a2 = (size_t *)((__int64)(__int64)a2 | v6);
                                        if ((a4 & 1) != 0) {
                                            a1 = 1;
                                        }
                                        a3 = 1;
                                        v2 = v7;
                                        if (((__int64)a2 & 1) != 0) {
                                            a3 = (size_t *)a1;
                                        }
                                        a1 = (size_t)a3;
                                        /* test result , 1 */;
                                        if (a1 == 4) result = a1;
                                        v_60 = 0;
                                        v_68 = 1;
                                        v_70 = 0;
                                        v_128 = (__int64)i;
                                        v_130 = v9;
                                        a1 = 1;
                                        a2 = (size_t *)result;
                                        a3 = &off_140121F04;
                                        a2 = v_0[(__int64)a2];
                                        a2 = (size_t *)((__int64)a2 + (__int64)a3);
                                        JUMPOUT(a2);
                                        a2 = &off_140115B90;
                                        v3 = 0;
                                        v_78 = (int)a2;
                                        v_80 = a1;
                                        result = (result >= 2) ? 1 : 0;
                                        v_30 = (__int64)result;
                                        result = rsp + 120;
                                        v_38 = (__int64)result;
                                        result = &off_14000E2E0;
                                        v_40 = (__int64)result;
                                        result = &off_1401175D8;
                                        v_98 = (__int64)result;
                                        v_a0 = 1;
                                        v_b8 = 0;
                                        result = rsp + 56;
                                        v_a8 = (__int64)result;
                                        v_b0 = 1;
                                        a2 = &off_140115C88;
                                        a1 = rsp + 96;
                                        a3 = rsp + 152;
                                        sub_140011760(a1, a2, a3);
                                        if (result == 0) {
                                            if (v3 != 0) {
                                                if (v9 != 0) {
                                                    v8 = v_30;
                                                    v8 += v8;
                                                    v11 = &off_140121F84;
                                                    v4 = &off_140121F18;
                                                    do {
                                                        v3 = 0;
                                                        a4 = 0;
                                                        do {
                                                            result = *(__int64 *)(i + a4);
                                                            a1 = (size_t)result;
                                                            a2 = a1 - 8;
                                                            if (a1 == 92) {
                                                                v3 = 1;
                                                                result = &off_140115BA4;
                                                                if (a4 != 0) {
                                                                    if (a4 >= v9) {
                                                                        if (!((0 /* unresolved: flags != */))) {
                                                                            v_138 = (__int64)i;
                                                                            v_140 = a4;
                                                                            a1 = 1;
                                                                            if (v3 == 0) result = a1;
                                                                            v7 = v3;
                                                                            a1 = v7 + v7;
                                                                            v_148 = (__int64)result;
                                                                            v_150 = a1;
                                                                            v7 += a4;
                                                                            if ((v7 == 0)) {
                                                                                result = rsp + 312;
                                                                                v_38 = (__int64)result;
                                                                                result = &off_14000E2E0;
                                                                                v_40 = (__int64)result;
                                                                                a1 = rsp + 328;
                                                                                v_48 = a1;
                                                                                v_50 = (__int64)result;
                                                                                result = &off_140115C38;
                                                                                v_98 = (__int64)result;
                                                                                v_a0 = 2;
                                                                                v_b8 = 0;
                                                                                result = rsp + 56;
                                                                                v_a8 = (__int64)result;
                                                                                v_b0 = 2;
                                                                                a1 = rsp + 96;
                                                                                a2 = &off_140115C88;
                                                                                a3 = rsp + 152;
                                                                                sub_140011760(a1, a2, a3, v9);
                                                                                if (result == 0) {
                                                                                    v9 -= v7;
                                                                                    i += v7;
                                                                                    if (v3 != 0) {
                                                                                        result = rsp + 120;
                                                                                        v_38 = (__int64)result;
                                                                                        result = &off_14000E2E0;
                                                                                        v_40 = (__int64)result;
                                                                                        result = &off_1401175D8;
                                                                                        v_98 = (__int64)result;
                                                                                        v_a0 = 1;
                                                                                        v_b8 = 0;
                                                                                        result = rsp + 56;
                                                                                        v_a8 = (__int64)result;
                                                                                        v_b0 = 1;
                                                                                        a2 = &off_140115C88;
                                                                                        a1 = rsp + 96;
                                                                                        a3 = rsp + 152;
                                                                                        sub_140011760(a1, a2, a3);
                                                                                        v3 = v_60;
                                                                                        v7 = v_68;
                                                                                        v8 = v_70;
                                                                                        if (v8 == 0) {
                                                                                            v4 = 1;
                                                                                            if (v3 == 0) {
                                                                                                i = 0;
                                                                                            } else {
                                                                                                off_140108030();
                                                                                                i = 0;
                                                                                                off_140108038(result, 0, v7);
                                                                                            }
                                                                                        } else {
                                                                                            if (v3 < 0) {
                                                                                                i = 0x7FFFFFFFFFFFFFFF;
                                                                                                i = (struct Struct_1_t *)((__int64)(__int64)i & v3);
                                                                                                if (i != 1) {
                                                                                                    v4 = 1;
                                                                                                    if (i != 0) {
                                                                                                        a1 = &off_140116968;
                                                                                                        sub_1400F35E0(a1);
                                                                                                        result = &off_140115C08;
                                                                                                        v_20 = (__int64)result;
                                                                                                        sub_1400F3810(i, v9, 0);
                                                                                                        result = &off_140115C20;
                                                                                                        v_20 = (__int64)result;
                                                                                                        sub_1400F3810(i, v9, v7, v9);
                                                                                                    } else {
                                                                                                        if (v2 == 0) {
                                                                                                            v7 = 8;
                                                                                                        } else {
                                                                                                            v_30 = v4;
                                                                                                            result = (__int64 *)v2;
                                                                                                            result = (__int64 *)((__int64)(__int64)result << 4);
                                                                                                            v8 = result + (__int64)(__int64)result*8;
                                                                                                            sub_14002EDF0(0, v8);
                                                                                                            if (result == 0) {
                                                                                                                sub_1400F3326(8, v8);
                                                                                                                sub_1400F3326(1, v8);
                                                                                                                v3 = arg_20;
                                                                                                                if ((0 /* unresolved: flags == */)) JUMPOUT(0x14005820c);
                                                                                                                sub_14002EDF0(0, i);
                                                                                                                if (result == 0) JUMPOUT(0x140058217);
                                                                                                                v4 = (__int64)result;
                                                                                                                return sub_14005820F();
                                                                                                            } else {
                                                                                                                v7 = (__int64)result;
                                                                                                                v3 = 0;
                                                                                                                v11 = rsp + 152;
                                                                                                                v5 = v2;
                                                                                                                while (v8 != v3) {
                                                                                                                    result = (__int64 *)v_90;
                                                                                                                    a2 = result + v3;
                                                                                                                    v4 = v7 + v3;
                                                                                                                    sub_140056CD0(v11, a2);
                                                                                                                    sub_1400F27F0(v4, v11, 144);
                                                                                                                    v3 += 144;
                                                                                                                    --v2;
                                                                                                                }
                                                                                                                v2 = v5;
                                                                                                                v4 = v_30;
                                                                                                            }
                                                                                                        }
                                                                                                        result = (__int64 *)v_88;
                                                                                                        *result = i;
                                                                                                        arg_8 = v4;
                                                                                                        arg_10 = (__int64)i;
                                                                                                        arg_18 = v2;
                                                                                                        arg_20 = v7;
                                                                                                        arg_28 = v2;
                                                                                                        return arg_28;
                                                                                                    }
                                                                                                    return arg_28;
                                                                                                } else {
                                                                                                    sub_14002EDF0(0, v8);
                                                                                                    if (result != 0) {
                                                                                                        v4 = (__int64)result;
                                                                                                        sub_1400F27F0(result, v7, v8);
                                                                                                        if (v3 <= 0) {
                                                                                                            i = (struct Struct_1_t *)v8;
                                                                                                        } else {
                                                                                                            off_140108030();
                                                                                                            off_140108038(result, 0, v7);
                                                                                                            i = (struct Struct_1_t *)v8;
                                                                                                        }
                                                                                                        return (__int64)i;
                                                                                                    }
                                                                                                    return (__int64)i;
                                                                                                }
                                                                                                return (__int64)i;
                                                                                            }
                                                                                            return (__int64)i;
                                                                                        }
                                                                                        return (__int64)i;
                                                                                    }
                                                                                    if (v9 != 0) {
                                                                                        result = i->field_0;
                                                                                        v_5c = (__int64)result;
                                                                                        result = rsp + 92;
                                                                                        v_38 = (__int64)result;
                                                                                        result = &off_140018760;
                                                                                        v_40 = (__int64)result;
                                                                                        result = &off_140115C60;
                                                                                        v_98 = (__int64)result;
                                                                                        v_a0 = 1;
                                                                                        result = &off_140119C98;
                                                                                        v_b8 = (__int64)result;
                                                                                        v_c0 = 1;
                                                                                        result = rsp + 56;
                                                                                        v_a8 = (__int64)result;
                                                                                        v_b0 = 1;
                                                                                        a1 = rsp + 96;
                                                                                        a2 = &off_140115C88;
                                                                                        a3 = rsp + 152;
                                                                                        sub_140011760(a1, a2, a3);
                                                                                        if (result == 0) {
                                                                                            if (v9 == 1) {
                                                                                                --v9;
                                                                                                ++i;
                                                                                                return (__int64)i;
                                                                                            }
                                                                                            if (i->field_1 >= 192) {
                                                                                                return (__int64)i;
                                                                                            }
                                                                                            result = &off_140115C70;
                                                                                            v_20 = (__int64)result;
                                                                                            sub_1400F3810(i, v9, 1, v9);
                                                                                            result = rsp + 296;
                                                                                            v_38 = (__int64)result;
                                                                                            result = &off_14000E2E0;
                                                                                            v_40 = (__int64)result;
                                                                                            result = &off_1401175D8;
                                                                                            v_98 = (__int64)result;
                                                                                            v_a0 = 1;
                                                                                            v_b8 = 0;
                                                                                            result = rsp + 56;
                                                                                            v_a8 = (__int64)result;
                                                                                            v_b0 = 1;
                                                                                            a2 = &off_140115C88;
                                                                                            a1 = rsp + 96;
                                                                                            a3 = rsp + 152;
                                                                                            sub_140011760(a1, a2, a3);
                                                                                            if (result == 0) {
                                                                                                return (__int64)a3;
                                                                                            }
                                                                                        }
                                                                                        return (__int64)a3;
                                                                                    }
                                                                                    return (__int64)a3;
                                                                                }
                                                                                return (__int64)a3;
                                                                            }
                                                                            if (v9 <= v7) {
                                                                                if (!((0 /* unresolved: flags != */))) {
                                                                                    return (__int64)a3;
                                                                                }
                                                                                return (__int64)a3;
                                                                            }
                                                                            if (*(__int64 *)(i + v7) >= 192) {
                                                                                return (__int64)a3;
                                                                            }
                                                                            return (__int64)a3;
                                                                        }
                                                                        return (__int64)a3;
                                                                    }
                                                                    if (*(__int64 *)(i + a4) > 191) {
                                                                        return (__int64)a3;
                                                                    }
                                                                    return (__int64)a3;
                                                                }
                                                                return (__int64)a3;
                                                            }
                                                            v3 = 0;
                                                            if (result < 32) {
                                                                result = 0;
                                                                if (a4 != 0) {
                                                                    return (__int64)result;
                                                                }
                                                                return (__int64)result;
                                                            }
                                                            if (result != 127) {
                                                                ++a4;
                                                                v3 = 0;
                                                                result = 0;
                                                                if (v9 != 0) {
                                                                    return (__int64)result;
                                                                }
                                                                return (__int64)result;
                                                            }
                                                            return (__int64)result;
                                                        } while (v9 != a4);
                                                        return (__int64)result;
                                                    } while (v9 != 0);
                                                }
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    if (v4 != 92) {
                                        if (v3 == 127) a4 = v5;
                                        if (v3 < 32) a4 = v5;
                                        return (__int64)result;
                                    }
                                    a2 = 1;
                                    return (__int64)a2;
                                }
                                if (v4 == 9) {
                                    return (__int64)a2;
                                }
                                if (v4 != 34) {
                                    return (__int64)a2;
                                }
                                v6 = 1;
                                return v6;
                            } while (v9 != a3);
                            return v6;
                        }
                        return v6;
                    }
                    return v6;
                }
                return v6;
            }
            return v6;
        }
        return v6;
    }
    return (__int64)result;
}