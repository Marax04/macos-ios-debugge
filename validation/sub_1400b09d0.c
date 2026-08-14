// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[96];
    __int64 field_68; // offset 104
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[90];
    int field_62; // offset 98
    char _pad_62[2];
    __int64 field_68; // offset 104
};

// inferred from 4 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    char _pad_0[88];
    __int16 field_60; // offset 96
    int field_62; // offset 98
    char _pad_62[2];
    __int64 field_68; // offset 104
};

__int64 sub_1400B0C40();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400B09D0(struct Struct_1_t *a1, __int64 a2) {
    struct Struct_3_t *ptr;
    __int64 i;
    __int64 v2;
    struct Struct_2_t *result;
    struct Struct_4_t *ptr2;
    __int64 v8;
    __int64 v9;
    __int64 i2;
    __int64 v5;

    ptr = a1->field_0;
    if (ptr == 0) {
        return (__int64)ptr;
    } else {
        i = a1->field_8;
        v2 = ((__int64 *)a1)[2];
        if (v2 == 0) {
            if (i != 0) {
                result = (struct Struct_2_t *)i;
                result = (struct Struct_2_t *)((__int64)(__int64)result & 7);
                if ((result == 0)) JUMPOUT(0x1400b0c64);
                a1 = 0;
                do {
                    ptr = ptr->field_68;
                    ++a1;
                } while (result != a1);
                result = (struct Struct_2_t *)i;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a1);
                if (i >= 8) {
                    do {
                        a1 = ptr->field_68;
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        ptr = ((__int64 *)a1)[13];
                        result -= 8;
                    } while ((result != 0));
                }
            }
        } else {
            ptr2 = 0;
            v8 = off_140108030;
            v9 = off_140108038;
            i2 = (__int64)ptr;
            do {
                if (i == 0) {
                    ptr2 = (struct Struct_4_t *)i2;
                    i = 0;
                    i2 = 0;
                    result = ptr2->field_62;
                    if (i < result) {
                        ptr = (struct Struct_3_t *)ptr2;
                        ++i;
                        if (i2 == 0) {
                            i2 = 0;
                            ptr2 = (struct Struct_4_t *)ptr;
                            --v2;
                            result = ptr->field_0;
                            if (result == 0) JUMPOUT(0x1400b0c3d);
                            v2 = off_140108030;
                            v5 = off_140108038;
                            do {
                                ptr2 = (struct Struct_4_t *)result;
                                ((__int64 (*)())v2)(a1, a2);
                                ((__int64 (*)())v5)(result, 0, ptr);
                                result = ptr2->field_0;
                                ptr = (struct Struct_3_t *)ptr2;
                            } while (result != 0);
                            return sub_1400B0C40();
                        }
                        result = ptr + i*8;
                        result += 104;
                        a1 = (struct Struct_1_t *)i2;
                        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 7);
                        if ((a1 == 0)) {
                            a1 = (struct Struct_1_t *)i2;
                            if (i2 < 8) {
                                i = 0;
                                return i;
                            }
                            do {
                                result = result->field_0;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                result = result->field_68;
                                ptr = result->field_68;
                                result = ptr + 104;
                                a1 -= 8;
                            } while ((a1 != 0));
                            return (__int64)a1;
                        }
                        a2 = 0;
                        do {
                            ptr = result->field_0;
                            result = ptr + 104;
                            ++a2;
                        } while (a1 != a2);
                        a1 = (struct Struct_1_t *)i2;
                        a1 -= a2;
                        if (i2 >= 8) {
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    do {
                        ptr = ptr2->field_0;
                        if (ptr == 0) JUMPOUT(0x1400b0c73);
                        ++i2;
                        i = ptr2->field_60;
                        ((__int64 (*)())v8)(a1);
                        ((__int64 (*)())v9)(result, 0, ptr2);
                        ptr2 = (struct Struct_4_t *)ptr;
                    } while (i >= ptr->field_62);
                    return (__int64)ptr2;
                }
                result = (struct Struct_2_t *)i;
                ptr2 = (struct Struct_4_t *)i2;
                result = (struct Struct_2_t *)((__int64)(__int64)result & 7);
                if ((result == 0)) {
                    result = (struct Struct_2_t *)i;
                    if (i < 8) {
                        return (__int64)result;
                    }
                    do {
                        a1 = ptr2->field_68;
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        a1 = ((__int64 *)a1)[13];
                        ptr2 = ((__int64 *)a1)[13];
                        result -= 8;
                    } while ((result != 0));
                    return (__int64)result;
                }
                for (a1 = 0; result != a1; ++a1) {
                    ptr2 = ptr2->field_68;
                }
                result = (struct Struct_2_t *)i;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a1);
                if (i >= 8) {
                    return (__int64)result;
                }
                return (__int64)result;
            } while (!((v2 == 0)));
        }
        return (__int64)result;
    }
}