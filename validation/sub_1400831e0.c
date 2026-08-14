// inferred from 3 accesses on `a1`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a3`
struct Struct_3_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

__int64 sub_1400834E0();
__int64 sub_1400834D8();

__int64 __fastcall sub_1400831E0(struct Struct_1_t *a1,struct Struct_2_t *a2,struct Struct_3_t *a3, size_t a4) {
    int v_10;
    int v_7;
    __int64 v_8;
    int v_80;
    __int64 v6;
    __int64 v8;
    __int64 *result;
    __int64 *src;
    __int64 v10;
    __int64 v9;
    __int64 v11;
    __int64 v2;
    __int64 v3;
    __int64 *src2;
    __int64 *src3;

    v6 = a2->field_8;
    v8 = ((__int64 *)a2)[2];
    if (v8 < v6) {
        v_7 = a4;
        result = a2->field_0;
        v_8 = (__int64)result;
        src = *(result + v8);
        a4 = v8 + 1;
        ((__int64 *)a2)[2] = (__int64)(a4);
        v10 = (__int64)src;
        v10 >>= 6;
        v9 = (__int64)src;
        v9 >>= 3;
        v9 &= 7;
        v11 = (__int64)src;
        v11 &= 7;
        v2 = a3->field_2;
        v3 = a3->field_3;
        result = (__int64 *)v3;
        result = (__int64 *)((__int64)(__int64)result >> 1);
        a3 = a3->field_0;
        src2 = (__int64 *)a3;
        src2 = (__int64 *)((__int64)(__int64)src2 >> 2);
        src3 = result;
        result = src2;
        if (v2 != 0) result = src3;
        result = (__int64 *)((__int64)(__int64)result << 3);
        result = (__int64 *)((__int64)(__int64)result & 8);
        result = (__int64 *)((__int64)(__int64)result | v9);
        if (v10 != 3) {
            if (((__int64)a3 & 64) != 0) {
                *(__int64 *)a1 = (__int64)(0x404);
            } else {
                src2 = (__int64 *)v3;
                src2 = (__int64 *)((__int64)(__int64)src2 >> 2);
                v3 >>= 3;
                src3 = (__int64 *)a3;
                src3 = (__int64 *)((__int64)(__int64)src3 >> 3);
                a3 = (struct Struct_3_t *)((__int64)(__int64)a3 >> 4);
                v9 = (__int64)a3;
                if (v2 != 0) v9 = v3;
                a3 = (struct Struct_3_t *)src2;
                v3 = (__int64)src3;
                if (v2 != 0) src3 = src2;
                if (v11 != 4) {
                    src = (__int64 *)((__int64)(__int64)src & 199);
                    src3 = 1;
                    v3 = 6;
                    if (src != 5) {
                        v9 <<= 3;
                        v9 &= 8;
                        v9 |= v11;
                        src = 3;
                        a3 = 0;
                        v2 = v9;
                        if (v10 == 0) {
                            v9 = 0;
                            if (v11 == 4) JUMPOUT(0x14008349f);
                            if (v11 != 5) JUMPOUT(0x1400834dd);
                            src2 = (v3 != 6) ? 1 : 0;
                            a3 = (struct Struct_3_t *)((__int64)(__int64)a3 ^ 1);
                            v9 = 0;
                            a3 = (struct Struct_3_t *)((__int64)(__int64)a3 | (__int64)src2);
                            a3 = 0;
                            if ((a3 != 0)) JUMPOUT(0x1400834e0);
                            v2 = a4 + 4;
                            src2 = (a4 >= -4) ? 1 : 0;
                            v6 = (v2 > v6) ? 1 : 0;
                            v6 |= (__int64)src2;
                            if ((v6 != 0)) JUMPOUT(0x1400834bc);
                            ((__int64 *)a2)[2] = (__int64)(v2);
                            src = (__int64 *)v_8;
                            a3 = *(src + a4);
                            v9 = 1;
                            src = 6;
                            return sub_1400834E0();
                        }
                    } else {
                        a3 = 1;
                        src = 6;
                        if (v10 == 0) {
                            return (__int64)src;
                        }
                    }
                } else {
                    if (a4 < v6) {
                        v_10 = (int)a1;
                        src2 = (__int64 *)v_8;
                        v2 = *(src2 + v8 + 1);
                        v8 += 2;
                        ((__int64 *)a2)[2] = (__int64)(v8);
                        a1 = (struct Struct_1_t *)v2;
                        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 >> 6);
                        a4 = v2;
                        a4 >>= 3;
                        a4 &= 7;
                        v2 &= 7;
                        a3 = 1;
                        src3 = 1;
                        src3 = (__int64 *)((__int64)(__int64)src3 << (__int64)a1);
                        src2 =  + v3*8;
                        src2 = (__int64 *)((__int64)(__int64)src2 & 8);
                        src2 = (__int64 *)((__int64)(__int64)src2 | a4);
                        a1 = 0;
                        a1 = ((v3 & 1) == 0) ? 1 : 0;
                        a1 = src2 + (__int64)(__int64)src2*2 + 3;
                        v3 = 3;
                        if (a4 == 4) v3 = a1;
                        a1 = (src < 64) ? 1 : 0;
                        a4 = (v2 == 5) ? 1 : 0;
                        if (((__int64)a1 & a4) == 0) {
                            v9 <<= 3;
                            v9 &= 8;
                            v2 |= v9;
                            src = 3;
                            a3 = 0;
                            a4 = v8;
                        } else {
                            src = 6;
                            a4 = v8;
                        }
                        a1 = (struct Struct_1_t *)v_10;
                        if (v10 == 0) {
                            return (__int64)a1;
                        } else {
                            if (v10 != 1) JUMPOUT(0x1400834a4);
                            if (a4 < v6) {
                                src3 = (__int64 *)v_8;
                                a3 = *(src3 + a4);
                                ++a4;
                                ((__int64 *)a2)[2] = (__int64)(a4);
                                return sub_1400834D8();
                            }
                        }
                    }
                    a1->field_3 = 0;
                    *(__int64 *)a1 = (__int64)(516);
                    return a4;
                }
                return a4;
            }
        } else {
            v3 >>= 3;
            a3 = (struct Struct_3_t *)((__int64)(__int64)a3 >> 4);
            a4 = v3;
            a2 = (struct Struct_2_t *)a3;
            if (v2 != 0) a2 = v3;
            a2 = (struct Struct_2_t *)((__int64)(__int64)a2 << 3);
            a2 = (struct Struct_2_t *)((__int64)(__int64)a2 & 8);
            a2 = (struct Struct_2_t *)((__int64)(__int64)a2 | v11);
            if (v_80 == 0) {
                a3 = (struct Struct_3_t *)v_7;
            } else {
                if (v_7 != 5) {
                    a2 = (struct Struct_2_t *)((__int64)(__int64)a2 | 16);
                    a3 = 4;
                } else {
                    a2 = (struct Struct_2_t *)((__int64)(__int64)a2 | 32);
                    a3 = 5;
                }
            }
            *(__int64 *)a1 = (__int64)(0);
            a1->field_1 = a3;
            a1->field_2 = a2;
            ((__int64 *)a1)[2] = (__int64)(result);
        }
        return (__int64)a3;
    }
    return (__int64)result;
}