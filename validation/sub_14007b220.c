// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a2`
struct Struct_2_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[96];
    __int64 field_68; // offset 104
};

// inferred from 2 accesses on `ptr`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_5_t {
    __int64 field_0; // offset 0
    char _pad_0[88];
    __int16 field_60; // offset 96
    int field_62; // offset 98
    char _pad_62[2];
    __int64 field_68; // offset 104
};

__int64 sub_14000ECF0();
__int64 sub_1400F35E0();
__int64 sub_14007B5CF();
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14011D9A0;
extern __int64 off_140119DD8;

__int64 __fastcall sub_14007B220(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    struct Struct_4_t *ptr;
    struct Struct_3_t *result;
    struct Struct_5_t *ptr2;
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
                        i = 0;
                        do {
                            result = result->field_68;
                            ++i;
                        } while (a2 != i);
                        a2 = (struct Struct_2_t *)a1;
                        a2 -= i;
                    }
                    ptr2 = (struct Struct_5_t *)result;
                    if (a1 >= 8) {
                        ptr2 = (struct Struct_5_t *)result;
                        do {
                            result = ptr2->field_68;
                            result = result->field_68;
                            result = result->field_68;
                            result = result->field_68;
                            result = result->field_68;
                            result = result->field_68;
                            result = result->field_68;
                            ptr2 = result->field_68;
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
                    ptr2 = (struct Struct_5_t *)i2;
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
                    a1 = (struct Struct_1_t *)result;
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 7);
                    if ((a1 == 0)) {
                        a1 = (struct Struct_1_t *)result;
                        if (result >= 8) {
                            do {
                                result = ptr2->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                ptr2 = result->field_68;
                                a1 -= 8;
                            } while ((a1 != 0));
                        } else {
                        }
                        *(__int64 *)a2 = (__int64)(1);
                        v11 = 0;
                        i2 = 0;
                        result = ptr2->field_62;
                        if (v11 < result) {
                            v12 = (__int64)ptr2;
                            i = v11 + 1;
                            if (i2 == 0) {
                                a1 = (struct Struct_1_t *)v12;
                            } else {
                                result = v12 + i*8;
                                result += 104;
                                i = (__int64)i2;
                                i &= 7;
                                if ((i == 0)) {
                                    v6 = (__int64)i2;
                                    i = 0;
                                    if (i2 >= 8) {
                                        do {
                                            result = result->field_0;
                                            result = result->field_68;
                                            result = result->field_68;
                                            result = result->field_68;
                                            result = result->field_68;
                                            result = result->field_68;
                                            result = result->field_68;
                                            a1 = result->field_68;
                                            result = a1 + 104;
                                            v6 -= 8;
                                        } while ((v6 != 0));
                                    }
                                } else {
                                    for (i3 = 0; i != i3; ++i3) {
                                        a1 = result->field_0;
                                        result = a1 + 104;
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
                                v11 = ptr2->field_60;
                                ((__int64 (*)())v10)(a1, a2, i);
                                ((__int64 (*)())v13)(result, 0, ptr2);
                                ptr2 = (struct Struct_5_t *)v12;
                                a2 = (struct Struct_2_t *)v9;
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
                            if (a2->field_4 != 6) JUMPOUT(0x14007b58a);
                            ptr2 = ((__int64 *)a1)[2];
                            if (ptr2 == a1->field_0) JUMPOUT(0x14007b698);
                            result = a1->field_8;
                            i = ptr2 + (__int64)(__int64)ptr2*2;
                            i <<= 4;
                            v6 = 0x8000000000000000;
                            *(__int64 *)(result + i) = (__int64)(v6);
                            *(__int64 *)(result + i + 8) = (__int64)(1);
                            *(__int64 *)(result + i + 16) = (__int64)(0);
                            return sub_14007B5CF();
                        }
                        return v6;
                    } else {
                        i = 0;
                        do {
                            ptr2 = ptr2->field_68;
                            ++i;
                        } while (a1 != i);
                        a1 = (struct Struct_1_t *)result;
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
                result = ptr2->field_62;
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