// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[608];
    __int64 field_278; // offset 632
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[616];
    __int64 field_278; // offset 632
};

// inferred from 3 accesses on `ptr`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_5_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[264];
    __int16 field_270; // offset 624
    int field_272; // offset 626
    char _pad_272[2];
    __int64 field_278; // offset 632
};

__int64 sub_14000ECF0();
__int64 sub_1400F35E0();
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14011D9A0;
extern __int64 off_140119DD8;

__int64 __fastcall sub_14000C1E0(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    struct Struct_4_t *ptr;
    struct Struct_3_t *result;
    struct Struct_5_t *ptr2;
    __int64 *i;
    __int64 v7;
    __int64 v8;
    __int64 v11;
    __int64 v12;
    __int64 v5;
    __int64 v6;
    __int64 v9;
    __int64 v10;
    __int64 v13;

    ptr = (struct Struct_4_t *)a1;
    result = ((__int64 *)a2)[8];
    if (result == 0) {
        ptr2 = a2->field_8;
        result = ((__int64 *)a2)[2];
        a1 = ((__int64 *)a2)[3];
        *(__int64 *)a2 = (__int64)(0);
        if (!(((*a2 & 1) == 0))) {
            if (ptr2 == 0) {
                if (a1 == 0) {
                    ptr2 = (struct Struct_5_t *)result;
                } else {
                    a2 = (struct Struct_2_t *)a1;
                    a2 = (struct Struct_2_t *)((__int64)(__int64)a2 & 7);
                    if ((a2 == 0)) {
                        a2 = (struct Struct_2_t *)a1;
                    } else {
                        do {
                            result = result->field_278;
                            --a2;
                        } while ((a2 != 0));
                        a2 = (struct Struct_2_t *)a1;
                        a2 = (struct Struct_2_t *)((__int64)(__int64)a2 & -8);
                    }
                    ptr2 = (struct Struct_5_t *)result;
                    if (a1 >= 8) {
                        ptr2 = (struct Struct_5_t *)result;
                        do {
                            result = ptr2->field_278;
                            result = result->field_278;
                            result = result->field_278;
                            result = result->field_278;
                            result = result->field_278;
                            result = result->field_278;
                            result = result->field_278;
                            ptr2 = result->field_278;
                            a2 -= 8;
                        } while ((a2 != 0));
                    }
                }
            }
            result = ptr2->field_160;
            if (result == 0) {
                i = (__int64 *)ptr2;
            } else {
                v7 = off_140108030;
                v8 = off_140108038;
                do {
                    i = (__int64 *)result;
                    ((__int64 (*)())v7)(a1, a2, 0, v6);
                    ((__int64 (*)())v8)(result, 0, ptr2);
                    result = *(i + 352);
                    ptr2 = (struct Struct_5_t *)i;
                } while (result != 0);
            }
            ((__int64 (*)())off_140108030)(a1, a2, 0, v6);
            ((__int64 (*)())off_140108038)(result, 0, i);
        }
        *(__int64 *)ptr = (__int64)(0);
    } else {
        --result;
        ((__int64 *)a2)[8] = (__int64)(result);
        if (a2->field_0 == 1) {
            ptr2 = a2->field_8;
            if (ptr2 == 0) {
                ptr2 = ((__int64 *)a2)[2];
                a1 = ((__int64 *)a2)[3];
                if (a1 != 0) {
                    result = (struct Struct_3_t *)a1;
                    result = (struct Struct_3_t *)((__int64)(__int64)result & 7);
                    if ((result == 0)) {
                        result = (struct Struct_3_t *)a1;
                        if (a1 >= 8) {
                            do {
                                a1 = ptr2->field_278;
                                a1 = a1->field_278;
                                a1 = a1->field_278;
                                a1 = a1->field_278;
                                a1 = a1->field_278;
                                a1 = a1->field_278;
                                a1 = a1->field_278;
                                ptr2 = a1->field_278;
                                result -= 8;
                            } while ((result != 0));
                        } else {
                        }
                        *(__int64 *)a2 = (__int64)(1);
                        v11 = 0;
                        i = 0;
                        result = ptr2->field_272;
                        if (v11 < result) {
                            v12 = (__int64)ptr2;
                            v5 = v11 + 1;
                            if (i == 0) {
                                a1 = (struct Struct_1_t *)v12;
                            } else {
                                result = v12 + v5*8;
                                result += 632;
                                v5 = (__int64)i;
                                v5 &= 7;
                                if ((v5 == 0)) {
                                    v6 = (__int64)i;
                                    if (i >= 8) {
                                        do {
                                            result = result->field_0;
                                            result = result->field_278;
                                            result = result->field_278;
                                            result = result->field_278;
                                            result = result->field_278;
                                            result = result->field_278;
                                            result = result->field_278;
                                            a1 = result->field_278;
                                            result = a1 + 632;
                                            v6 -= 8;
                                        } while ((v6 != 0));
                                    }
                                } else {
                                    do {
                                        a1 = result->field_0;
                                        result = a1 + 632;
                                        --v5;
                                    } while ((v5 != 0));
                                    v6 = (__int64)i;
                                    v6 &= -8;
                                    if (i >= 8) {
                                        return v6;
                                    } else {
                                    }
                                }
                            }
                            a2->field_8 = a1;
                            ((__int64 *)a2)[2] = (__int64)(0);
                            ((__int64 *)a2)[3] = (__int64)(v5);
                            *(__int64 *)ptr = (__int64)(v12);
                            ptr->field_8 = i;
                            ptr->field_10 = v11;
                            return v6;
                        } else {
                            v9 = (__int64)a2;
                            v10 = off_140108030;
                            v13 = off_140108038;
                            v12 = ptr2->field_160;
                            while (v12 != 0) {
                                ++i;
                                v11 = ptr2->field_270;
                                ((__int64 (*)())v10)(a1);
                                ((__int64 (*)())v13)(result, 0, ptr2);
                                ptr2 = (struct Struct_5_t *)v12;
                                a2 = (struct Struct_2_t *)v9;
                                v5 = v11 + 1;
                                if (i != 0) {
                                    return v5;
                                } else {
                                    return v5;
                                }
                                return v5;
                            }
                            sub_14000ECF0(ptr2, 8);
                            a1 = &off_14011D9A0;
                            sub_1400F35E0(a1);
                            a1 = &off_140119DD8;
                            sub_1400F35E0(a1);
                            result = a1->field_0;
                            ptr = a1->field_10;
                            a1 = ptr + (__int64)(__int64)ptr*2;
                            ptr = (struct Struct_4_t *)((__int64)(__int64)ptr << 5);
                            ptr = (struct Struct_4_t *)((__int64)ptr + (__int64)result);
                            if (*(__int64 *)(result + (__int64)(__int64)a1*8 + 360) != 0) {
                                result += (__int64)(__int64)a1*8;
                                result += 360;
                                ptr2 = result->field_8;
                                ((__int64 (*)())off_140108030)(a1);
                                ((__int64 (*)())off_140108038)(result, 0, ptr2);
                            }
                            result = ptr->field_0;
                            if (result >= 3) JUMPOUT(0x14000c5b6);
                            return (__int64)result;
                        }
                        return (__int64)result;
                    } else {
                        do {
                            ptr2 = ptr2->field_278;
                            --result;
                        } while ((result != 0));
                        result = (struct Struct_3_t *)a1;
                        result = (struct Struct_3_t *)((__int64)(__int64)result & -8);
                        if (a1 >= 8) {
                            return (__int64)result;
                        }
                        return (__int64)result;
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            } else {
                i = ((__int64 *)a2)[2];
                v11 = ((__int64 *)a2)[3];
                result = ptr2->field_272;
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