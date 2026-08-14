// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140055430(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    int arg_8;
    int v_20;
    __int64 v4;
    __int64 v6;
    __int64 v11;
    __int64 v7;
    __int64 v5;
    __int64 *src;
    struct Struct_3_t *ptr;
    __int64 v9;
    __int64 *src2;
    struct Struct_4_t *ptr2;
    __int64 v3;

    v4 = a2->field_0;
    v6 = a2->field_8;
    v11 = a3->field_0;
    v7 = a3->field_8;
    v5 = ((__int64 *)a3)[2];
    src = ((__int64 *)a3)[4];
    ptr = ((__int64 *)a3)[5];
    if (v4 == 0) {
        arg_8 = v6;
        *a1 = 0;
    } else {
        v9 = ((__int64 *)a2)[2];
        src2 = ((__int64 *)a2)[4];
        ptr2 = ((__int64 *)a2)[5];
        if (v4 != 1) {
            if (v11 == 0) {
                arg_8 = v7;
                *a1 = 0;
                if (v6 != 0) {
                    off_140108030(v6, 0, src);
                    ((__int64 (*)())off_140108038)(v6, 0, v9);
                }
                if (src2 != 0) {
                    v6 = ptr2->field_0;
                    if (v6 != 0) {
                        ((__int64 (*)())v6)(src2);
                    }
                    if (ptr2->field_8 != 0) {
                        if (ptr2->field_10 >= 17) {
                            src2 = *(src2 - 8);
                        }
                        off_140108030();
                        a2 = 0;
                        JUMPOUT(off_140108038);
                    }
                }
            } else {
                a2 = ((__int64 *)a2)[3];
                arg_8 = v6;
                a1[2] = v9;
                a1[3] = a2;
                a1[4] = src2;
                a1[5] = ptr2;
                *a1 = 2;
                v3 = 1;
                if (v11 != 0) {
                    if (v11 != 1) {
                        if (v3 != 0) {
                            if (v7 != 0) {
                                v3 = v5;
                                off_140108030(v11, a2);
                                ((__int64 (*)())off_140108038)(v6, 0, v5);
                            }
                            if (src != 0) {
                                v6 = ptr->field_0;
                                if (v6 != 0) {
                                    ((__int64 (*)())v6)(src);
                                }
                                if (ptr->field_8 != 0) {
                                    if (ptr->field_10 >= 17) {
                                        src = *(src - 8);
                                    }
                                    off_140108030();
                                    return (__int64)src;
                                }
                            }
                        }
                        return (__int64)src;
                    }
                    return (__int64)src;
                }
            }
        } else {
            v_20 = v5;
            if (v11 == 0) {
                arg_8 = v7;
                v3 = 1;
                *a1 = a2;
                if (v6 != 0) {
                    off_140108030(v6, 0, src2);
                    ((__int64 (*)())off_140108038)(v6, 0, v9);
                    v5 = v_20;
                }
            } else {
                v3 = ((__int64 *)a3)[3];
                if (v11 != 1) {
                    arg_8 = v7;
                    a1[2] = v5;
                    a1[3] = v3;
                    a1[4] = src;
                    a1[5] = ptr;
                    a2 = 2;
                    v3 = 0;
                    *a1 = a2;
                    if (v6 != 0) {
                        return v3;
                    } else {
                    }
                    if (src2 != 0) {
                        v6 = ptr2->field_0;
                        if (v6 != 0) {
                            ((__int64 (*)())v6)(src2);
                            v5 = v_20;
                        }
                        if (ptr2->field_8 != 0) {
                            if (ptr2->field_10 >= 17) {
                                src2 = *(src2 - 8);
                            }
                            off_140108030();
                            ((__int64 (*)())off_140108038)(v6, 0, src2);
                            v5 = v_20;
                        }
                    }
                    return v5;
                } else {
                    v11 = (__int64)a1;
                    if (v6 != 0) {
                        off_140108030(a1, a2, a3, v4);
                        ((__int64 (*)())off_140108038)(v6, 0, v9);
                        v5 = v_20;
                        a1 = (__int64 *)v11;
                    }
                    if (src2 != 0) {
                        v6 = ptr2->field_0;
                        if (v6 != 0) {
                            ((__int64 (*)())v6)(src2);
                            v5 = v_20;
                        }
                        if (ptr2->field_8 != 0) {
                            if (ptr2->field_10 >= 17) {
                                src2 = *(src2 - 8);
                            }
                            off_140108030(v11);
                            ((__int64 (*)())off_140108038)(v6, 0, src2);
                            v5 = v_20;
                        }
                    }
                    arg_8 = v7;
                    a1[2] = v5;
                    a1[3] = v3;
                    a1[4] = src;
                    a1[5] = ptr;
                    *a1 = 1;
                }
                return arg_8;
            }
            return arg_8;
        }
        return arg_8;
    }
    return arg_8;
}