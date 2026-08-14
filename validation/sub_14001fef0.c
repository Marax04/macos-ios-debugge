// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[264];
    __int64 field_108; // offset 264
    char _pad_108[8];
    __int64 field_118; // offset 280
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[280];
    __int64 field_118; // offset 280
    __int64 field_120; // offset 288
    __int64 field_128; // offset 296
    __int64 field_130; // offset 304
};

// inferred from 2 accesses on `ptr2`
struct Struct_4_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

__int64 sub_1400200C0();
__int64 sub_1400F5320();

__int64 __fastcall sub_14001FEF0(struct Struct_1_t *a1) {
    __int64 rsp;
    int v_28;
    int v_30;
    int v_38;
    struct Struct_3_t *ptr;
    struct Struct_2_t *result;
    __int64 v7;
    __int64 *src;
    __int64 *src2;
    __int64 v6;
    __int64 v10;
    __int64 v5;
    struct Struct_4_t *ptr2;
    __int64 v8;
    __int64 v11;
    __int64 v2;

    ptr = (struct Struct_3_t *)a1;
    result = a1->field_118;
    v7 = result->field_108;
    src = result->field_100;
    a1 = (struct Struct_1_t *)v7;
    a1 = (struct Struct_1_t *)((__int64)a1 - (__int64)src);
    if (a1 > 0) {
        if (ptr->field_130 != 1) {
            src = 1;
            /* xadd %(__int64)src, 256(%(__int64)result) */;
            if ((src - v7) < 0) {
                src2 = ptr->field_120;
                v6 = ptr->field_128;
                v10 = v6 - 1;
                v10 &= (__int64)src;
                v10 <<= 4;
                result = *(src2 + v10);
                src = *(src2 + v10 + 8);
                v7 = v6 + 3;
                if (v6 >= 0) v7 = v6;
                if (v6 >= 65) {
                    v7 >>= 2;
                    if (a1 <= v7) JUMPOUT(0x14002008e);
                }
                if (result == 0) {
                    ptr += 312;
                    v5 = rsp + 40;
                    do {
                        sub_1400200C0(v5, ptr, v6, v7);
                        result = (struct Struct_2_t *)v_28;
                    } while (result == 2);
                    if (result != 0) {
                        result = (struct Struct_2_t *)v_30;
                        src = (__int64 *)v_38;
                    } else {
                        result = 0;
                    }
                }
            } else {
                result = ptr->field_118;
                result->field_100 = src;
                return (__int64)result;
            }
            return (__int64)result;
        } else {
            a1 = v7 - 1;
            result->field_108 = a1;
            *(__int64 *)rsp = *(__int64 *)rsp | 0;
            ptr2 = ptr->field_118;
            v5 = ptr2->field_100;
            v8 = (__int64)a1;
            v8 -= v5;
            if ((v8 < 0)) {
                ptr2->field_108 = v7;
            } else {
                src = ptr->field_120;
                v11 = ptr->field_128;
                v2 = v11 - 1;
                v2 &= (__int64)a1;
                v2 <<= 4;
                result = *(src + v2);
                src = *(src + v2 + 8);
                if (a1 != v5) {
                    a1 = v11 + 3;
                    if (v11 >= 0) a1 = v11;
                    if (v11 >= 65) {
                        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 >> 2);
                        if (v8 < a1) {
                            v11 >>= 1;
                            ptr += 280;
                            ptr = (struct Struct_3_t *)src;
                            v5 = (__int64)result;
                            sub_1400F5320(ptr, v11, v11);
                            src = (__int64 *)ptr;
                            result = (struct Struct_2_t *)v5;
                        }
                    }
                } else {
                    v6 = (__int64)result;
                    result = (struct Struct_2_t *)a1;
                    /* cmpxchg %v7, 256(%(__int64)ptr2) */;
                    result = (struct Struct_2_t *)v6;
                    a1 = ptr->field_118;
                    a1->field_108 = v7;
                    if ((0 /* unresolved: flags != */)) {
                        return (__int64)a1;
                    } else {
                    }
                }
                return (__int64)a1;
            }
        }
    }
    return (__int64)result;
}