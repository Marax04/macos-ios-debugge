// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[304];
    __int64 field_140; // offset 320
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[308];
    __int16 field_13C; // offset 316
    __int16 field_13E; // offset 318
    __int64 field_140; // offset 320
};

__int64 sub_1400E9FF0();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400E9CC0(struct Struct_1_t *a1, __int64 a2) {
    struct Struct_3_t *ptr;
    __int64 v6;
    __int64 v2;
    struct Struct_2_t *result;
    __int64 v8;
    __int64 v9;
    __int64 *i;
    __int64 v10;
    __int64 *src;
    __int64 v5;

    ptr = a1->field_0;
    if (ptr == 0) {
        return (__int64)ptr;
    } else {
        v6 = a1->field_8;
        v2 = ((__int64 *)a1)[2];
        if (v2 == 0) {
            if (v6 != 0) {
                result = (struct Struct_2_t *)v6;
                result = (struct Struct_2_t *)((__int64)(__int64)result & 7);
                if ((result == 0)) JUMPOUT(0x1400ea015);
                a1 = 0;
                do {
                    ptr = ptr->field_140;
                    ++a1;
                } while (result != a1);
                result = (struct Struct_2_t *)v6;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a1);
                if (v6 >= 8) {
                    do {
                        a1 = ptr->field_140;
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        ptr = ((__int64 *)a1)[40];
                        result -= 8;
                    } while ((result != 0));
                }
            }
        } else {
            v8 = off_140108030;
            v9 = off_140108038;
            i = (__int64 *)ptr;
            ptr = 0;
            do {
                if (v6 == 0) {
                    ptr = (struct Struct_3_t *)i;
                    v6 = 0;
                    i = 0;
                    result = ptr->field_13E;
                    if (v6 < result) {
                        v10 = v6;
                        src = (__int64 *)ptr;
                        v6 = v10 + 1;
                        if (i == 0) {
                            ptr = (struct Struct_3_t *)src;
                            result =  + v10*2;
                            result += v10;
                            if (*(src + (__int64)(__int64)result*8 + 8) == 0) {
                                i = 0;
                                --v2;
                                result = ptr->field_0;
                                if (result == 0) JUMPOUT(0x1400e9fed);
                                v2 = off_140108030;
                                v5 = off_140108038;
                                do {
                                    i = (__int64 *)result;
                                    ((__int64 (*)())v2)(a1);
                                    ((__int64 (*)())v5)(result, 0, ptr);
                                    result = *i;
                                    ptr = (struct Struct_3_t *)i;
                                } while (result != 0);
                                return sub_1400E9FF0();
                            }
                            result =  + (__int64)(__int64)result*8 + 8;
                            result = (struct Struct_2_t *)((__int64)result + (__int64)src);
                            i = result->field_8;
                            ((__int64 (*)())v8)(a1, a2);
                            ((__int64 (*)())v9)(result, 0, i);
                            return (__int64)i;
                        }
                        result =  + v6*8 + 320;
                        result = (struct Struct_2_t *)((__int64)result + (__int64)src);
                        a1 = (struct Struct_1_t *)i;
                        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 7);
                        if ((a1 == 0)) {
                            a1 = (struct Struct_1_t *)i;
                            if (i >= 8) {
                                do {
                                    result = result->field_0;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    result = result->field_140;
                                    ptr = result->field_140;
                                    result = ptr + 320;
                                    a1 -= 8;
                                } while ((a1 != 0));
                                v6 = 0;
                                result =  + v10*2;
                                result += v10;
                                if (*(src + (__int64)(__int64)result*8 + 8) != 0) {
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            return (__int64)result;
                        }
                        a2 = 0;
                        do {
                            ptr = result->field_0;
                            result = ptr + 320;
                            ++a2;
                        } while (a1 != a2);
                        a1 = (struct Struct_1_t *)i;
                        a1 -= a2;
                        if (i < 8) {
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    do {
                        src = ptr->field_0;
                        if (src == 0) JUMPOUT(0x1400ea024);
                        ++i;
                        v10 = ptr->field_13C;
                        ((__int64 (*)())v8)(a1);
                        ((__int64 (*)())v9)(result, 0, ptr);
                        ptr = (struct Struct_3_t *)src;
                    } while (v10 >= *(src + 318));
                    return (__int64)ptr;
                }
                result = (struct Struct_2_t *)v6;
                ptr = (struct Struct_3_t *)i;
                result = (struct Struct_2_t *)((__int64)(__int64)result & 7);
                if ((result == 0)) {
                    result = (struct Struct_2_t *)v6;
                    if (v6 < 8) {
                        return (__int64)result;
                    }
                    do {
                        a1 = ptr->field_140;
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        a1 = ((__int64 *)a1)[40];
                        ptr = ((__int64 *)a1)[40];
                        result -= 8;
                    } while ((result != 0));
                    return (__int64)result;
                }
                for (a1 = 0; result != a1; ++a1) {
                    ptr = ptr->field_140;
                }
                result = (struct Struct_2_t *)v6;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a1);
                if (v6 >= 8) {
                    return (__int64)result;
                }
                return (__int64)result;
            } while (!((v2 == 0)));
        }
        return (__int64)result;
    }
}