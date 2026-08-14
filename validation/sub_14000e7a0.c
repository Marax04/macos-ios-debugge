// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[616];
    __int64 field_278; // offset 632
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[264];
    __int16 field_270; // offset 624
    int field_272; // offset 626
    char _pad_272[2];
    __int64 field_278; // offset 632
};

// inferred from 6 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[320];
    __int64 field_160; // offset 352
    char _pad_160[266];
    __int64 field_272; // offset 626
};

__int64 sub_14000EB54();
__int64 sub_140009FD0();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14000E7A0(struct Struct_1_t *a1, __int64 a2) {
    struct Struct_3_t *ptr;
    __int64 v7;
    struct Struct_2_t *result;
    __int64 v8;
    __int64 i;
    __int64 v9;
    __int64 v6;
    __int64 v10;
    struct Struct_4_t *ptr2;
    __int64 v5;

    ptr = a1->field_0;
    v7 = a1->field_8;
    result = (ptr != 0) ? 1 : 0;
    v8 = ((__int64 *)a1)[2];
    a1 = (v8 != 0) ? 1 : 0;
    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & (__int64)result);
    if (a1 != 1) {
        if (ptr == 0) JUMPOUT(0x14000eb79);
        if (v7 != 0) {
            result = v7 - 1;
            a1 = (struct Struct_1_t *)v7;
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 7);
            if (!((a1 == 0))) {
                do {
                    ptr = ptr->field_278;
                    --a1;
                } while ((a1 != 0));
                v7 &= -8;
            }
            if (result >= 7) {
                do {
                    result = ptr->field_278;
                    result = result->field_278;
                    result = result->field_278;
                    result = result->field_278;
                    result = result->field_278;
                    result = result->field_278;
                    result = result->field_278;
                    ptr = result->field_278;
                    v7 -= 8;
                } while ((v7 != 0));
            }
        }
    } else {
        i = (__int64)ptr;
        ptr = 0;
        v9 = off_140108030;
        v6 = off_140108038;
        do {
            if (v7 == 0) {
                ptr = (struct Struct_3_t *)i;
                v7 = 0;
                i = 0;
                result = ptr->field_272;
                if (v7 < result) {
                    v10 = v7;
                    ptr2 = (struct Struct_4_t *)ptr;
                    v7 = v10 + 1;
                    if (i == 0) {
                        ptr = (struct Struct_3_t *)ptr2;
                        result =  + v10*2;
                        result += v10;
                        if (*(__int64 *)(ptr2 + (__int64)(__int64)result*8 + 360) != 0) {
                            result = ptr2 + (__int64)(__int64)result*8;
                            result += 360;
                            i = result->field_8;
                            ((__int64 (*)())v9)(a1);
                            ((__int64 (*)())v6)(result, 0, i);
                            v10 <<= 5;
                            ptr2 += v10;
                            result = ptr2->field_0;
                            a1 = result - 1;
                            if (a1 < 4) {
                                i = 0;
                                --v8;
                                result = ptr->field_160;
                                if (result == 0) JUMPOUT(0x14000eb51);
                                i = off_140108030;
                                v5 = off_140108038;
                                do {
                                    ptr2 = (struct Struct_4_t *)result;
                                    ((__int64 (*)())i)(a1);
                                    ((__int64 (*)())v5)(result, 0, ptr);
                                    result = ptr2->field_160;
                                    ptr = (struct Struct_3_t *)ptr2;
                                } while (result != 0);
                                return sub_14000EB54();
                            }
                            if (result == 0) {
                                if (ptr2->field_8 == 0) {
                                    return (__int64)ptr;
                                }
                                ptr2 = ptr2->field_10;
                                ((__int64 (*)())v9)();
                                ((__int64 (*)())v6)(result, 0, ptr2);
                                return (__int64)ptr2;
                            }
                            if (result != 5) {
                                ptr2 += 8;
                                sub_14000E7A0(ptr2, a2);
                                return (__int64)ptr2;
                            }
                            v10 = ptr2->field_18;
                            if (v10 == 0) {
                                return v10;
                            }
                            i = ptr2->field_10;
                            do {
                                sub_140009FD0(i);
                                i += 32;
                                --v10;
                            } while ((v10 != 0));
                            return v10;
                        }
                        return v10;
                    }
                    result = ptr2 + v7*8;
                    result += 632;
                    a1 = (struct Struct_1_t *)i;
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 7);
                    if ((a1 == 0)) {
                        a1 = (struct Struct_1_t *)i;
                        if (i >= 8) {
                            do {
                                result = result->field_0;
                                result = result->field_278;
                                result = result->field_278;
                                result = result->field_278;
                                result = result->field_278;
                                result = result->field_278;
                                result = result->field_278;
                                ptr = result->field_278;
                                result = ptr + 632;
                                a1 -= 8;
                            } while ((a1 != 0));
                            v7 = 0;
                            result =  + v10*2;
                            result += v10;
                            if (*(__int64 *)(ptr2 + (__int64)(__int64)result*8 + 360) == 0) {
                                return (__int64)result;
                            }
                            return (__int64)result;
                        }
                        return (__int64)result;
                    }
                    do {
                        ptr = result->field_0;
                        result = ptr + 632;
                        --a1;
                    } while ((a1 != 0));
                    a1 = (struct Struct_1_t *)i;
                    a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & -8);
                    if (i < 8) {
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                do {
                    ptr2 = ptr->field_160;
                    if (ptr2 == 0) JUMPOUT(0x14000eb8b);
                    ++i;
                    v10 = ptr->field_270;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr);
                    ptr = (struct Struct_3_t *)ptr2;
                } while (v10 >= ptr2->field_272);
                return (__int64)ptr;
            }
            result = (struct Struct_2_t *)v7;
            ptr = (struct Struct_3_t *)i;
            result = (struct Struct_2_t *)((__int64)(__int64)result & 7);
            if ((result == 0)) {
                result = (struct Struct_2_t *)v7;
                if (v7 < 8) {
                    return (__int64)result;
                }
                do {
                    a1 = ptr->field_278;
                    a1 = ((__int64 *)a1)[79];
                    a1 = ((__int64 *)a1)[79];
                    a1 = ((__int64 *)a1)[79];
                    a1 = ((__int64 *)a1)[79];
                    a1 = ((__int64 *)a1)[79];
                    a1 = ((__int64 *)a1)[79];
                    ptr = ((__int64 *)a1)[79];
                    result -= 8;
                } while ((result != 0));
                return (__int64)result;
            }
            do {
                ptr = ptr->field_278;
                --result;
            } while ((result != 0));
            result = (struct Struct_2_t *)v7;
            result = (struct Struct_2_t *)((__int64)(__int64)result & -8);
            if (v7 >= 8) {
                return (__int64)result;
            }
            return (__int64)result;
        } while (!((v8 == 0)));
    }
    return (__int64)result;
}