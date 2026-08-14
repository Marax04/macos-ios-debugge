// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[312];
    __int64 field_140; // offset 320
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    char _pad_0[308];
    __int16 field_13C; // offset 316
    __int16 field_13E; // offset 318
    __int64 field_140; // offset 320
};

__int64 sub_14000ECF0();
__int64 sub_1400F35E0();
__int64 sub_1400F1D90();
__int64 sub_14009A360();
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14011D9A0;
extern __int64 off_140119DD8;

__int64 __fastcall sub_140099E40(size_t *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_20;
    struct Struct_3_t *ptr;
    struct Struct_2_t *result;
    struct Struct_4_t *ptr2;
    __int64 i;
    __int64 *i2;
    __int64 v8;
    __int64 v12;
    __int64 v11;
    __int64 v6;
    __int64 i3;
    __int64 v9;
    __int64 v10;
    __int64 v13;

    ptr = (struct Struct_3_t *)a1;
    result = ((__int64 *)a2)[8];
    if (result == 0) {
        ptr2 = a2->field_8;
        result = ((__int64 *)a2)[2];
        a1 = ((__int64 *)a2)[3];
        *(__int64 *)a2 = (__int64)(0);
        if (!(((*a2 & 1) == 0))) {
            if (ptr2 == 0) {
                if (a1 == 0) {
                    ptr2 = (struct Struct_4_t *)result;
                } else {
                    a2 = (struct Struct_1_t *)a1;
                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 & 7);
                    if ((a2 == 0)) {
                        a2 = (struct Struct_1_t *)a1;
                    } else {
                        i = 0;
                        do {
                            result = result->field_140;
                            ++i;
                        } while (a2 != i);
                        a2 = (struct Struct_1_t *)a1;
                        a2 -= i;
                    }
                    ptr2 = (struct Struct_4_t *)result;
                    if (a1 >= 8) {
                        ptr2 = (struct Struct_4_t *)result;
                        do {
                            result = ptr2->field_140;
                            result = result->field_140;
                            result = result->field_140;
                            result = result->field_140;
                            result = result->field_140;
                            result = result->field_140;
                            result = result->field_140;
                            ptr2 = result->field_140;
                            a2 -= 8;
                        } while ((a2 != 0));
                    }
                }
            }
            result = ptr2->field_0;
            if (result == 0) {
                i2 = (__int64 *)ptr2;
            } else {
                v8 = off_140108030;
                v12 = off_140108038;
                do {
                    i2 = (__int64 *)result;
                    ((__int64 (*)())v8)(a1, a2, 0, v6);
                    ((__int64 (*)())v12)(result, 0, ptr2);
                    result = *i2;
                    ptr2 = (struct Struct_4_t *)i2;
                } while (result != 0);
            }
            ((__int64 (*)())off_140108030)(a1, a2, i, v6);
            ((__int64 (*)())off_140108038)(result, 0, i2);
        }
        *(__int64 *)ptr = (__int64)(0);
    } else {
        --result;
        ((__int64 *)a2)[8] = (__int64)(result);
        if (a2->field_0 == 1) {
            ptr2 = a2->field_8;
            if (ptr2 == 0) {
                ptr2 = ((__int64 *)a2)[2];
                result = ((__int64 *)a2)[3];
                if (result != 0) {
                    a1 = (size_t *)result;
                    a1 = (size_t *)((__int64)(__int64)a1 & 7);
                    if ((a1 == 0)) {
                        a1 = (size_t *)result;
                        if (result >= 8) {
                            do {
                                result = ptr2->field_140;
                                result = result->field_140;
                                result = result->field_140;
                                result = result->field_140;
                                result = result->field_140;
                                result = result->field_140;
                                result = result->field_140;
                                ptr2 = result->field_140;
                                a1 -= 8;
                            } while ((a1 != 0));
                        } else {
                        }
                        *(__int64 *)a2 = (__int64)(1);
                        v11 = 0;
                        i2 = 0;
                        result = ptr2->field_13E;
                        if (v11 < result) {
                            v12 = (__int64)ptr2;
                            i = v11 + 1;
                            if (i2 == 0) {
                                a1 = (size_t *)v12;
                            } else {
                                result = v12 + i*8;
                                result += 320;
                                i = (__int64)i2;
                                i &= 7;
                                if ((i == 0)) {
                                    v6 = (__int64)i2;
                                    i = 0;
                                    if (i2 >= 8) {
                                        do {
                                            result = result->field_0;
                                            result = result->field_140;
                                            result = result->field_140;
                                            result = result->field_140;
                                            result = result->field_140;
                                            result = result->field_140;
                                            result = result->field_140;
                                            a1 = result->field_140;
                                            result = a1 + 320;
                                            v6 -= 8;
                                        } while ((v6 != 0));
                                    }
                                } else {
                                    for (i3 = 0; i != i3; ++i3) {
                                        a1 = result->field_0;
                                        result = a1 + 320;
                                    }
                                    v6 = (__int64)i2;
                                    v6 -= i3;
                                    if (i2 >= 8) {
                                        return v6;
                                    } else {
                                    }
                                }
                            }
                            a2->field_8 = a1;
                            ((__int64 *)a2)[2] = (__int64)(0);
                            ((__int64 *)a2)[3] = (__int64)(i);
                            *(__int64 *)ptr = (__int64)(v12);
                            ptr->field_8 = i2;
                            ptr->field_10 = v11;
                            return v6;
                        } else {
                            v9 = (__int64)a2;
                            v10 = off_140108030;
                            v13 = off_140108038;
                            v12 = ptr2->field_0;
                            while (v12 != 0) {
                                ++i2;
                                v11 = ptr2->field_13C;
                                ((__int64 (*)())v10)(a1, a2, i);
                                ((__int64 (*)())v13)(result, 0, ptr2);
                                ptr2 = (struct Struct_4_t *)v12;
                                a2 = (struct Struct_1_t *)v9;
                                i = v11 + 1;
                                if (i2 != 0) {
                                    return i;
                                } else {
                                    return i;
                                }
                                return i;
                            }
                            sub_14000ECF0(ptr2, 8);
                            a1 = &off_14011D9A0;
                            sub_1400F35E0(a1);
                            a1 = &off_140119DD8;
                            sub_1400F35E0(a1);
                            sub_1400F1D90(0x1030);
                            i = (__int64)a2;
                            i >>= 1;
                            result = (struct Struct_2_t *)a2;
                            result -= i;
                            i = 0x1E8480;
                            if (a2 < 0x1E8480) i = a2;
                            if (i <= result) i = result;
                            ptr = 48;
                            if (i >= 49) ptr = i;
                            if (i >= 0x401) JUMPOUT(0x14009a237);
                            v_20 = (a2 < 65) ? 1 : 0;
                            i = rsp + 48;
                            return sub_14009A360(a1, a2, i, 0x400);
                        }
                        return i;
                    } else {
                        i = 0;
                        do {
                            ptr2 = ptr2->field_140;
                            ++i;
                        } while (a1 != i);
                        a1 = (size_t *)result;
                        a1 -= i;
                        if (result >= 8) {
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                return (__int64)a1;
            } else {
                i2 = ((__int64 *)a2)[2];
                v11 = ((__int64 *)a2)[3];
                result = ptr2->field_13E;
                if (v11 >= result) {
                    return (__int64)result;
                } else {
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