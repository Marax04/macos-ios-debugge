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

__int64 sub_1400502A0();
__int64 sub_1400545CE();
__int64 sub_140018820();
__int64 sub_1400127C0();
__int64 sub_1400545C3();
__int64 sub_1400544F6();
extern __int64 off_140115F40;
extern __int64 off_140110A3A;
extern __int64 off_140115F4C;
extern __int64 off_140117BCE;
extern __int64 off_14010B438;
extern __int64 off_140115F45;
extern __int64 off_14010B408;
extern __int64 off_14010B400;
extern __int64 off_140116F20;
extern __int64 off_140115F52;

__int64 __fastcall sub_140053F90(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    __int64 v_50;
    __int64 v_58;
    char *str;
    char *str2;
    __int64 *v4;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 *src;
    __int64 v6;
    __int64 v7;
    __int64 v9;
    __int64 v5;
    int v10;
    __int64 result;

    v4 = (__int64 *)a2;
    ptr = *a1;
    v3 = a2->field_0;
    src = a2->field_8;
    v6 = *(src + 24);
    a2 = &off_140115F40;
    ((__int64 (*)())v6)(v3, a2, 5);
    v7 = 0x8000000000000003;
    if (ptr->field_0 != v7) {
        v9 = 1;
        if (result == 0) {
            if ((*(v4 + 18) & 128) != 0) JUMPOUT(0x140054303);
            a2 = &off_140110A3A;
            ((__int64 (*)())v6)(v3, a2, 3);
            if (result == 0) {
                a2 = &off_140115F4C;
                ((__int64 (*)())v6)(v3, a2, 6);
                if (result == 0) {
                    a2 = &off_140117BCE;
                    ((__int64 (*)())v6)(v3, a2, 2);
                    if (result == 0) {
                        sub_1400502A0(ptr, v3, src);
                        return sub_1400545CE();
                    }
                }
            }
        }
    } else {
        v9 = 1;
        if (result == 0) {
            if ((*(v4 + 18) & 128) != 0) {
                a2 = &off_14010B438;
                ((__int64 (*)())v6)(v3, a2, 3);
                if (result == 0) {
                    str = 1;
                    str2 = (char *)v3;
                    v_50 = (__int64)src;
                    v_58 = (__int64)str;
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
                            sub_1400127C0(a1, 7, str2, v5);
                            if (result == 0) {
                                a2 = &off_14010B400;
                                a1 = rsp + 72;
                                return sub_1400545C3();
                            }
                        }
                    }
                }
            } else {
                a2 = &off_140110A3A;
                ((__int64 (*)())v6)(v3, a2, 3);
                if (result == 0) {
                    a2 = &off_140115F4C;
                    ((__int64 (*)())v6)(v3, a2, 6);
                    if (result == 0) {
                        a2 = &off_140117BCE;
                        ((__int64 (*)())v6)(v3, a2, 2);
                        if (result == 0) {
                            a1 = &off_140115F45;
                            sub_1400127C0(a1, 7, v3, src);
                            return sub_1400545CE();
                        }
                    }
                }
            }
        }
    }
    if (ptr->field_18 != v7) {
        v10 = 1;
        if (v9 == 0) {
            v9 = ptr + 24;
            if ((*(v4 + 18) & 128) != 0) JUMPOUT(0x1400543bf);
            a2 = &off_140116F20;
            ((__int64 (*)())v6)(v3, a2, 2);
            if (result == 0) {
                a2 = &off_140115F52;
                ((__int64 (*)())v6)(v3, a2, 6);
                if (result == 0) {
                    a2 = &off_140117BCE;
                    ((__int64 (*)())v6)(v3, a2, 2);
                    if (result == 0) {
                        sub_1400502A0(v9, v3, src);
                        return sub_1400544F6();
                    }
                }
            }
        }
    } else {
        v10 = 1;
        if (v9 == 0) {
            if ((*(v4 + 18) & 128) != 0) JUMPOUT(0x140054276);
            a2 = &off_140116F20;
            ((__int64 (*)())v6)(v3, a2, 2);
            if (result == 0) {
                a2 = &off_140115F52;
                ((__int64 (*)())v6)(v3, a2, 6);
                if (result == 0) {
                    a2 = &off_140117BCE;
                    ((__int64 (*)())v6)(v3, a2, 2);
                    if (result == 0) {
                        a1 = &off_140115F45;
                        sub_1400127C0(a1, 7, v3, src);
                        return sub_1400544F6();
                    }
                }
            }
        }
    }
    result = v10;
    return result;
}