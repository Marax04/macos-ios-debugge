// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[98];
    __int64 field_62; // offset 98
    char _pad_62[262];
    __int64 field_170; // offset 368
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[352];
    __int16 field_168; // offset 360
    int field_16A; // offset 362
    char _pad_16A[2];
    __int64 field_170; // offset 368
};

__int64 sub_1400A543D();
__int64 sub_1400A23E0();
__int64 sub_1400FB290();

__int64 __fastcall sub_1400A5040(size_t *a1,struct Struct_1_t *a2, int *a3, int a4) {
    __int64 rsp;
    __int64 arg_8;
    int v_28;
    int v_34;
    int v_38;
    int v_40;
    int v_48;
    __int64 v_50;
    int v_68;
    int v_70;
    int v_e0;
    int v_e8;
    __int64 v10;
    struct Struct_2_t *result;
    __int64 v7;
    __int64 v8;
    struct Struct_3_t *ptr;
    __int64 v9;
    __int64 i;
    __int64 v2;
    int v11;
    __int64 i2;
    __int64 v6;

    v10 = (__int64)a3;
    v_68 = (int)a1;
    v_38 = 0;
    v_40 = 4;
    v_48 = 0;
    result = a2->field_0;
    v7 = ((__int64 *)a2)[2];
    a1 = (result != 0) ? 1 : 0;
    a3 = (v7 != 0) ? 1 : 0;
    a3 = (int *)((__int64)(__int64)a3 & (__int64)a1);
    if (a3 == 1) {
        v8 = a2->field_8;
        if (v10 == 0) {
            ptr = 0;
            return sub_1400A543D();
        } else {
            v9 = a4;
            i = v_e8;
            a1 = 4;
            v_50 = (__int64)a1;
            v_28 = 0;
            ptr = 0;
            v_70 = v10;
            do {
                if (v8 == 0) {
                    ptr = (struct Struct_3_t *)result;
                    result = 0;
                    v8 = 0;
                    a1 = ptr->field_16A;
                    if (v8 < a1) {
                        a1 = (size_t *)v8;
                        a2 = (struct Struct_1_t *)ptr;
                        v8 = a1 + 1;
                        if (result == 0) {
                            ptr = (struct Struct_3_t *)a2;
                            result = a1 + (__int64)(__int64)a1*2;
                            v2 = *(__int64 *)(a2 + (__int64)(__int64)a1*8 + 272);
                            v11 = *(__int64 *)(a2 + (__int64)(__int64)a1*8 + 276);
                            a1 = *(__int64 *)(a2 + (__int64)(__int64)result*8 + 16);
                            a2 = *(__int64 *)(a2 + (__int64)(__int64)result*8 + 24);
                            sub_1400A23E0(a1, a2, a3, a4);
                            if (((__int64)result & 1) == 0) {
                                result = 0;
                                --v7;
                                a2 = (struct Struct_1_t *)v_28;
                                if (a2 >= 2) JUMPOUT(0x1400a55db);
                                result = (struct Struct_2_t *)v_48;
                                a1 = (size_t *)v_68;
                                a1[2] = result;
                                result = (struct Struct_2_t *)v_38;
                                *a1 = result;
                                result = (struct Struct_2_t *)v_40;
                                arg_8 = (__int64)result;
                                return arg_8;
                            }
                            a1 = (size_t *)v9;
                            result = (struct Struct_2_t *)v10;
                            do {
                                a4 = result->field_62;
                                i2 = a4;
                                i2 <<= 2;
                                a3 = -1;
                                while (i2 != 0) {
                                    v6 = (a2 > *(__int64 *)(result + (__int64)(__int64)a3*4 + 12)) ? 1 : 0;
                                    v6 -= 0;
                                    ++a3;
                                    i2 -= 4;
                                    if (v6 == 0) {
                                        if (i <= v2) {
                                            return i2;
                                        }
                                        v6 = v9;
                                        v9 = *(__int64 *)(result + (__int64)(__int64)a3*4 + 52);
                                        result = (struct Struct_2_t *)v_e0;
                                        v2 = *(__int64 *)(result + v2*4);
                                        i = v_28;
                                        if (i != v_38) {
                                            result = (struct Struct_2_t *)i;
                                            result = (struct Struct_2_t *)((__int64)(__int64)result << 4);
                                            a1 = (size_t *)v_50;
                                            *(__int64 *)((__int64)a1 + (__int64)result) = a2;
                                            *(__int64 *)((__int64)a1 + (__int64)result + 4) = v9;
                                            *(__int64 *)((__int64)a1 + (__int64)result + 8) = v2;
                                            *(__int64 *)((__int64)a1 + (__int64)result + 12) = v11;
                                            ++i;
                                            v_28 = i;
                                            v_48 = i;
                                            v9 = v6;
                                            v10 = v_70;
                                            i = v_e8;
                                            return i;
                                        }
                                        a1 = rsp + 56;
                                        v_34 = (int)a2;
                                        sub_1400FB290(a1, a2, a4, v6);
                                        a2 = (struct Struct_1_t *)v_34;
                                        result = (struct Struct_2_t *)v_40;
                                        v_50 = (__int64)result;
                                        return v_50;
                                    }
                                    --a1;
                                    if ((a1 >= 0)) {
                                        result = *(__int64 *)(result + (__int64)(__int64)a3*8 + 104);
                                    }
                                    return (__int64)result;
                                }
                                --a1;
                                if ((a1 < 0)) {
                                    return (__int64)a1;
                                }
                                return (__int64)a1;
                            } while (true);
                        }
                        a3 = a2 + v8*8;
                        a3 += 368;
                        a4 = (int)result;
                        a4 &= 7;
                        if ((a4 == 0)) {
                            a4 = (int)result;
                            if (result >= 8) {
                                do {
                                    result = *a3;
                                    result = result->field_170;
                                    result = result->field_170;
                                    result = result->field_170;
                                    result = result->field_170;
                                    result = result->field_170;
                                    result = result->field_170;
                                    ptr = result->field_170;
                                    a3 = ptr + 368;
                                    a4 -= 8;
                                } while ((a4 != 0));
                                v8 = 0;
                                return v8;
                            }
                            return v8;
                        }
                        i2 = 0;
                        do {
                            ptr = *a3;
                            a3 = ptr + 368;
                            ++i2;
                        } while (a4 != i2);
                        a4 = (int)result;
                        a4 -= i2;
                        if (result < 8) {
                            return a4;
                        }
                        return a4;
                    }
                    do {
                        a2 = ptr->field_0;
                        if (a2 == 0) JUMPOUT(0x1400a5670);
                        ++result;
                        a1 = ptr->field_168;
                        ptr = (struct Struct_3_t *)a2;
                    } while (a1 >= ((__int64 *)a2)[45]);
                    return (__int64)ptr;
                }
                a1 = (size_t *)v8;
                ptr = (struct Struct_3_t *)result;
                a1 = (size_t *)((__int64)(__int64)a1 & 7);
                if ((a1 == 0)) {
                    result = (struct Struct_2_t *)v8;
                    if (v8 < 8) {
                        return (__int64)result;
                    }
                    do {
                        a1 = ptr->field_170;
                        a1 = a1[46];
                        a1 = a1[46];
                        a1 = a1[46];
                        a1 = a1[46];
                        a1 = a1[46];
                        a1 = a1[46];
                        ptr = a1[46];
                        result -= 8;
                    } while ((result != 0));
                    return (__int64)result;
                }
                for (a2 = 0; a1 != a2; ++a2) {
                    ptr = ptr->field_170;
                }
                result = (struct Struct_2_t *)v8;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (v8 >= 8) {
                    return (__int64)result;
                }
                return (__int64)result;
            } while (!((v7 == 0)));
            return (__int64)result;
        }
    }
    return (__int64)result;
}