// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[976];
    __int64 field_3D8; // offset 984
};

// inferred from 7 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[304];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int16 field_3D0; // offset 976
    int field_3D2; // offset 978
    char _pad_3D2[2];
    __int64 field_3D8; // offset 984
};

// inferred from 3 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F35E0();
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_1401147E8;
extern __int64 off_140114818;

__int64 __fastcall sub_14003FAB0(size_t *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_10;
    __int64 v_8;
    __int64 *dst;
    struct Struct_4_t *ptr2;
    struct Struct_2_t *result;
    struct Struct_3_t *ptr;
    __int64 i;
    __int64 *i2;
    __int64 v3;
    __int64 v10;
    __int64 v11;
    __int64 v6;
    __int64 i3;
    __int64 v9;

    dst = rsp + 48;
    *dst = -2;
    ptr2 = (struct Struct_4_t *)a1;
    result = ((__int64 *)a2)[8];
    if (result == 0) {
        ptr = a2->field_8;
        result = ((__int64 *)a2)[2];
        a1 = ((__int64 *)a2)[3];
        *(__int64 *)a2 = (__int64)(0);
        if (!(((*a2 & 1) == 0))) {
            if (ptr == 0) {
                if (a1 == 0) {
                    ptr = (struct Struct_3_t *)result;
                } else {
                    a2 = (struct Struct_1_t *)a1;
                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 & 7);
                    if ((a2 == 0)) {
                        a2 = (struct Struct_1_t *)a1;
                    } else {
                        i = 0;
                        do {
                            result = result->field_3D8;
                            ++i;
                        } while (a2 != i);
                        a2 = (struct Struct_1_t *)a1;
                        a2 -= i;
                    }
                    ptr = (struct Struct_3_t *)result;
                    if (a1 >= 8) {
                        ptr = (struct Struct_3_t *)result;
                        do {
                            result = ptr->field_3D8;
                            result = result->field_3D8;
                            result = result->field_3D8;
                            result = result->field_3D8;
                            result = result->field_3D8;
                            result = result->field_3D8;
                            result = result->field_3D8;
                            ptr = result->field_3D8;
                            a2 -= 8;
                        } while ((a2 != 0));
                    }
                }
            }
            result = ptr->field_160;
            if (result == 0) {
                i2 = (__int64 *)ptr;
            } else {
                v3 = off_140108030;
                v10 = off_140108038;
                do {
                    i2 = (__int64 *)result;
                    ((__int64 (*)())v3)(a1, a2, 0, v6);
                    ((__int64 (*)())v10)(result, 0, ptr);
                    result = *(i2 + 352);
                    ptr = (struct Struct_3_t *)i2;
                } while (result != 0);
            }
            ((__int64 (*)())off_140108030)(a1, a2, i, v6);
            ((__int64 (*)())off_140108038)(result, 0, i2);
        }
        *(__int64 *)ptr2 = (__int64)(0);
    } else {
        --result;
        ((__int64 *)a2)[8] = (__int64)(result);
        if (a2->field_0 == 1) {
            ptr = a2->field_8;
            if (ptr == 0) {
                ptr = ((__int64 *)a2)[2];
                result = ((__int64 *)a2)[3];
                if (result != 0) {
                    a1 = (size_t *)result;
                    a1 = (size_t *)((__int64)(__int64)a1 & 7);
                    if ((a1 == 0)) {
                        if (result >= 8) {
                            do {
                                result = ptr->field_3D8;
                                result = result->field_3D8;
                                result = result->field_3D8;
                                result = result->field_3D8;
                                result = result->field_3D8;
                                result = result->field_3D8;
                                result = result->field_3D8;
                                ptr = result->field_3D8;
                                a1 -= 8;
                            } while ((a1 != 0));
                        } else {
                        }
                        *(__int64 *)a2 = (__int64)(1);
                        v10 = 0;
                        i2 = 0;
                        result = ptr->field_3D2;
                        if (v10 < result) {
                            v11 = (__int64)ptr;
                            i = v10 + 1;
                            if (i2 == 0) {
                                a1 = (size_t *)v11;
                            } else {
                                result = v11 + i*8;
                                result += 984;
                                i = (__int64)i2;
                                i &= 7;
                                if ((i == 0)) {
                                    v6 = (__int64)i2;
                                    i = 0;
                                    if (i2 >= 8) {
                                        do {
                                            result = result->field_0;
                                            result = result->field_3D8;
                                            result = result->field_3D8;
                                            result = result->field_3D8;
                                            result = result->field_3D8;
                                            result = result->field_3D8;
                                            result = result->field_3D8;
                                            a1 = result->field_3D8;
                                            result = a1 + 984;
                                            v6 -= 8;
                                        } while ((v6 != 0));
                                    }
                                } else {
                                    for (i3 = 0; i != i3; ++i3) {
                                        a1 = result->field_0;
                                        result = a1 + 984;
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
                            *(__int64 *)ptr2 = (__int64)(v11);
                            ptr2->field_8 = i2;
                            ptr2->field_10 = v10;
                            return v6;
                        } else {
                            v_8 = (__int64)ptr2;
                            ptr2 = (struct Struct_4_t *)a2;
                            v9 = off_140108030;
                            v3 = off_140108038;
                            v11 = ptr->field_160;
                            while (v11 != 0) {
                                ++i2;
                                v10 = ptr->field_3D0;
                                ((__int64 (*)())v9)(a1, a2, i);
                                ((__int64 (*)())v3)(result, 0, ptr);
                                ptr = (struct Struct_3_t *)v11;
                                a2 = (struct Struct_1_t *)ptr2;
                                ptr2 = (struct Struct_4_t *)v_8;
                                i = v10 + 1;
                                if (i2 != 0) {
                                    return i;
                                } else {
                                    return i;
                                }
                                return i;
                            }
                            ((__int64 (*)())off_140108030)(result, a2);
                            ((__int64 (*)())off_140108038)(result, 0, ptr);
                            a1 = &off_1401147E8;
                            sub_1400F35E0(a1);
                            a1 = &off_140114818;
                            sub_1400F35E0(a1);
                            v_10 = (int)a2;
                            dst = a2 + 48;
                            dst = rsp + 48;
                            v3 = (__int64)a1;
                            v10 = off_140108030;
                            v11 = off_140108038;
                            do {
                                a1 = dst - 16;
                                sub_14003FAB0(a1, v3);
                                ptr2 = (struct Struct_4_t *)v_10;
                                if (ptr2 == 0) JUMPOUT(0x14003ff44);
                                v9 = *dst;
                                result = v9 * 56;
                                ptr = (__int64)ptr2 + (__int64)result;
                                ptr += 360;
                                if (*(__int64 *)((__int64)ptr2 + (__int64)result + 360) == 0) {
                                    if (ptr->field_20 == 0) {
                                        v9 <<= 5;
                                        ptr2 += v9;
                                        i2 = ptr2->field_8;
                                        ((__int64 (*)())v10)();
                                        ((__int64 (*)())v11)(result, 0, i2);
                                    }
                                    i2 = ptr->field_28;
                                    ((__int64 (*)())v10)();
                                    ((__int64 (*)())v11)(result, 0, i2);
                                    return (__int64)i2;
                                }
                                i2 = ptr->field_8;
                                ((__int64 (*)())v10)();
                                ((__int64 (*)())v11)(result, 0, i2);
                                return (__int64)i2;
                            } while (ptr2->field_0 == 0);
                        }
                        return (__int64)i2;
                    } else {
                        for (i = 0; a1 != i; ++i) {
                            ptr = ptr->field_3D8;
                        }
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
                v10 = ((__int64 *)a2)[3];
                result = ptr->field_3D2;
                if (v10 >= result) {
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