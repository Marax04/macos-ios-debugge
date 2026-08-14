// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[304];
    __int64 field_140; // offset 320
};

// inferred from 6 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[520];
    __int64 field_238; // offset 568
    __int64 field_240; // offset 576
    __int64 field_248; // offset 584
};

__int64 sub_1400BCF59();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400BCBC0(__int64 *a1, __int64 a2) {
    int arg_13c;
    int arg_13e;
    int arg_140;
    __int64 v_20;
    __int64 *arg_8;
    struct Struct_2_t *ptr;
    __int64 *src;
    __int64 v3;
    __int64 v9;
    struct Struct_1_t *result;
    __int64 v7;
    __int64 *i;
    __int64 v8;
    __int64 v11;
    __int64 v6;
    __int64 v5;

    ptr = (struct Struct_2_t *)a1;
    if (*a1 != 0) {
        src = ptr->field_8;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(result, 0, src);
    }
    src = ptr->field_238;
    if (src != 0) {
        v3 = ptr->field_240;
        v9 = ptr->field_248;
        v_20 = (__int64)ptr;
        if (v9 == 0) {
            if (v3 != 0) {
                result = (struct Struct_1_t *)v3;
                result = (struct Struct_1_t *)((__int64)(__int64)result & 7);
                if ((result == 0)) JUMPOUT(0x1400bd0a8);
                a1 = 0;
                do {
                    src = (__int64 *)arg_140;
                    ++a1;
                } while (result != a1);
                result = (struct Struct_1_t *)v3;
                result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                if (v3 >= 8) {
                    do {
                        a1 = (__int64 *)arg_140;
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        src = a1[40];
                        result -= 8;
                    } while ((result != 0));
                }
            }
        } else {
            ptr = off_140108030;
            v7 = off_140108038;
            i = src;
            src = 0;
            do {
                if (v3 == 0) {
                    src = i;
                    v3 = 0;
                    i = 0;
                    result = (struct Struct_1_t *)arg_13e;
                    if (v3 < result) {
                        v8 = v3;
                        v11 = (__int64)src;
                        v3 = v8 + 1;
                        if (i == 0) {
                            src = (__int64 *)v11;
                            result =  + v8*2;
                            result += v8;
                            if (arg_8[(__int64)result] == 0) {
                                i = 0;
                                --v9;
                                result = *src;
                                if (result == 0) {
                                    i = src;
                                    ptr = (struct Struct_2_t *)v_20;
                                } else {
                                    v3 = off_140108030;
                                    v9 = off_140108038;
                                    ptr = (struct Struct_2_t *)v_20;
                                    do {
                                        i = (__int64 *)result;
                                        ((__int64 (*)())v3)(a1);
                                        ((__int64 (*)())v9)(result, 0, src);
                                        result = *i;
                                        src = i;
                                    } while (result != 0);
                                }
                                ((__int64 (*)())off_140108030)();
                                ((__int64 (*)())off_140108038)(result, 0, i);
                                src = ptr->field_20;
                                v6 = (__int64)ptr;
                                v3 = ptr->field_28;
                                if (v3 == 0) JUMPOUT(0x1400bcf8c);
                                v9 = src + 32;
                                ptr = off_140108030;
                                v5 = off_140108038;
                                return sub_1400BCF59();
                            }
                            result =  + (__int64)(__int64)result*8 + 8;
                            result += v11;
                            i = result->field_8;
                            ((__int64 (*)())ptr)(a1, a2);
                            ((__int64 (*)())v7)(result, 0, i);
                            return (__int64)i;
                        }
                        result =  + v3*8 + 320;
                        result += v11;
                        a1 = i;
                        a1 = (__int64 *)((__int64)(__int64)a1 & 7);
                        if ((a1 == 0)) {
                            a1 = i;
                            if (i >= 8) {
                                do {
                                    result = result->field_0;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    src = result->field_140;
                                    result = src + 320;
                                    a1 -= 8;
                                } while ((a1 != 0));
                                v3 = 0;
                                result =  + v8*2;
                                result += v8;
                                if (arg_8[(__int64)result] != 0) {
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            return (__int64)result;
                        }
                        a2 = 0;
                        do {
                            src = result->field_0;
                            result = src + 320;
                            ++a2;
                        } while (a1 != a2);
                        a1 = i;
                        a1 -= a2;
                        if (i < 8) {
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    do {
                        v11 = *src;
                        if (v11 == 0) JUMPOUT(0x1400bd0ba);
                        ++i;
                        v8 = arg_13c;
                        ((__int64 (*)())ptr)(a1);
                        ((__int64 (*)())v7)(result, 0, src);
                        src = (__int64 *)v11;
                    } while (v8 >= arg_13e);
                    return (__int64)src;
                }
                result = (struct Struct_1_t *)v3;
                src = i;
                result = (struct Struct_1_t *)((__int64)(__int64)result & 7);
                if ((result == 0)) {
                    result = (struct Struct_1_t *)v3;
                    if (v3 < 8) {
                        return (__int64)result;
                    }
                    do {
                        a1 = (__int64 *)arg_140;
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        a1 = a1[40];
                        src = a1[40];
                        result -= 8;
                    } while ((result != 0));
                    return (__int64)result;
                }
                for (a1 = 0; result != a1; ++a1) {
                    src = (__int64 *)arg_140;
                }
                result = (struct Struct_1_t *)v3;
                result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                if (v3 >= 8) {
                    return (__int64)result;
                }
                return (__int64)result;
            } while (!((v9 == 0)));
        }
        return (__int64)result;
    }
    return (__int64)result;
}