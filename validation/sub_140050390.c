// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
};

__int64 sub_140018820();
__int64 sub_140011760();
__int64 sub_1400127C0();
__int64 sub_1400509AE();
__int64 sub_1400509B9();
__int64 sub_1400502A0();
extern __int64 off_140115F40;
extern __int64 off_14010B438;
extern __int64 off_140115F4C;
extern __int64 off_140117BCE;
extern __int64 off_140116220;
extern __int64 off_140053B90;
extern __int64 off_140050370;
extern __int64 off_1401175D8;
extern __int64 off_14010B408;
extern __int64 off_14010B400;
extern __int64 off_140110A3A;
extern __int64 off_140115F52;
extern __int64 off_140115F45;
extern __int64 off_140116F20;

__int64 __fastcall sub_140050390(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_27;
    __int64 v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_78;
    int v_80;
    char *str;
    __int64 *v4;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 *src;
    __int64 v8;
    __int64 v12;
    int v11;
    __int64 v9;
    __int64 result;
    __int64 v7;
    __int64 v5;
    __int64 v6;

    v4 = (__int64 *)a2;
    ptr = (struct Struct_2_t *)a1;
    v3 = a2->field_0;
    src = a2->field_8;
    v8 = *(src + 24);
    a2 = &off_140115F40;
    ((__int64 (*)())v8)(v3, a2, 5);
    v12 = ptr->field_0;
    a1 = 0x8000000000000003;
    v11 = 1;
    if (v12 != a1) {
        if (result == 0) {
            v9 = (__int64)a1;
            if ((*(v4 + 18) & 128) != 0) {
                a2 = &off_14010B438;
                ((__int64 (*)())v8)(v3, a2, 3);
                if (result == 0) {
                    v_27 = 1;
                    v_30 = v3;
                    v_38 = (__int64)src;
                    result = rsp + 39;
                    v_40 = result;
                    a2 = &off_140115F4C;
                    a1 = rsp + 48;
                    sub_140018820(a1, a2, 6);
                    if (result == 0) {
                        a2 = &off_140117BCE;
                        a1 = rsp + 48;
                        sub_140018820(a1, a2, 2);
                        if (result == 0) {
                            a1 = 0x8000000000000000;
                            a1 = (__int64 *)((__int64)(__int64)a1 ^ v12);
                            result = 1;
                            if (v12 < 0) result = a1;
                            if (result == 0) {
                                a2 = &off_140116220;
                                a1 = rsp + 48;
                                sub_140018820(a1, a2, 5);
                            } else {
                                if (result != 1) {
                                    result = ptr + 8;
                                    v_28 = result;
                                    result = rsp + 40;
                                    v_78 = result;
                                    result = &off_140053B90;
                                } else {
                                    v_28 = (__int64)ptr;
                                    result = rsp + 40;
                                    v_78 = result;
                                    result = &off_140050370;
                                }
                                v_80 = result;
                                result = &off_1401175D8;
                                str = (char *)result;
                                v_50 = 1;
                                v_68 = 0;
                                result = rsp + 120;
                                v_58 = result;
                                v_60 = 1;
                                a2 = &off_14010B408;
                                a1 = rsp + 48;
                                sub_140011760(a1, a2, str);
                            }
                            if (result == 0) {
                                a2 = &off_14010B400;
                                a1 = rsp + 48;
                                sub_140018820(a1, a2, 2);
                                v11 = result;
                            }
                        }
                    }
                }
            } else {
                a2 = &off_140110A3A;
                ((__int64 (*)())v8)(v3, a2, 3);
                if (result == 0) {
                    a2 = &off_140115F4C;
                    ((__int64 (*)())v8)(v3, a2, 6);
                    if (result != 0) {
                        a1 = (__int64 *)v9;
                        v7 = ptr->field_18;
                        v12 = 1;
                        if (v7 == a1) {
                            if (v11 == 0) {
                                if ((*(v4 + 18) & 128) != 0) {
                                    v_30 = 1;
                                    str = (char *)v3;
                                    v_50 = (__int64)src;
                                    result = rsp + 48;
                                    v_58 = result;
                                    a2 = &off_140115F52;
                                    a1 = rsp + 72;
                                    sub_140018820(a1, a2, 6);
                                    if (result == 0) {
                                        a2 = &off_140117BCE;
                                        a1 = rsp + 72;
                                        sub_140018820(a1, a2, 2);
                                        if (result == 0) {
                                            a1 = &off_140115F45;
                                            v5 = &off_14010B408;
                                            sub_1400127C0(a1, 7, str, v5);
                                            if (result == 0) {
                                                a2 = &off_14010B400;
                                                a1 = rsp + 72;
                                                return sub_1400509AE();
                                            }
                                        }
                                    }
                                } else {
                                    a2 = &off_140116F20;
                                    ((__int64 (*)())v8)(v3, a2, 2);
                                    if (result == 0) {
                                        a2 = &off_140115F52;
                                        ((__int64 (*)())v8)(v3, a2, 6);
                                        if (result == 0) {
                                            a2 = &off_140117BCE;
                                            ((__int64 (*)())v8)(v3, a2, 2);
                                            if (result == 0) {
                                                a1 = &off_140115F45;
                                                sub_1400127C0(a1, 7, v3, src);
                                                return sub_1400509B9();
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if (v11 == 0) JUMPOUT(0x140050823);
                        }
                        result = v12;
                        return result;
                    } else {
                        a2 = &off_140117BCE;
                        ((__int64 (*)())v8)(v3, a2, 2);
                        a1 = (__int64 *)v9;
                        if (result == 0) {
                            sub_1400502A0(ptr, v3, src);
                            a1 = (__int64 *)v9;
                            v11 = result;
                        }
                        v6 = ptr->field_18;
                        v12 = 1;
                        if (v6 != a1) {
                            return v12;
                        } else {
                            return v12;
                        }
                        return v12;
                    }
                    return v12;
                }
            }
            return v12;
        }
    } else {
        if (result == 0) {
            v9 = (__int64)a1;
            if ((*(v4 + 18) & 128) != 0) {
                a2 = &off_14010B438;
                ((__int64 (*)())v8)(v3, a2, 3);
                if (result == 0) {
                    v_30 = 1;
                    str = (char *)v3;
                    v_50 = (__int64)src;
                    result = rsp + 48;
                    v_58 = result;
                    a2 = &off_140115F4C;
                    a1 = rsp + 72;
                    sub_140018820(a1, a2, 6);
                    if (result == 0) {
                        a2 = &off_140117BCE;
                        a1 = rsp + 72;
                        sub_140018820(a1, a2, 2);
                        if (result == 0) {
                            a1 = &off_140115F45;
                            v5 = &off_14010B408;
                            sub_1400127C0(a1, 7, str, v5);
                            if (result == 0) {
                                a2 = &off_14010B400;
                                a1 = rsp + 72;
                                return (__int64)a1;
                            }
                        }
                    }
                }
            } else {
                a2 = &off_140110A3A;
                ((__int64 (*)())v8)(v3, a2, 3);
                if (result == 0) {
                    a2 = &off_140115F4C;
                    ((__int64 (*)())v8)(v3, a2, 6);
                    if (result != 0) {
                        return (__int64)a2;
                    } else {
                        a2 = &off_140117BCE;
                        ((__int64 (*)())v8)(v3, a2, 2);
                        a1 = (__int64 *)v9;
                        if (result == 0) {
                            a1 = &off_140115F45;
                            sub_1400127C0(a1, 7, v3, src);
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
            }
            return (__int64)a1;
        }
    }
    return result;
}