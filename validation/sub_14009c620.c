// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 9 accesses on `ptr2`
struct Struct_2_t {
    int field_0; // offset 0
    int field_4; // offset 4
    int field_8; // offset 8
    int field_C; // offset 12
    int field_10; // offset 16
    int field_14; // offset 20
    int field_18; // offset 24
    int field_1C; // offset 28
    __int64 field_20; // offset 32
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_14009D080();
__int64 sub_1400F27F0();
__int64 sub_14009CFE0();

__int64 __fastcall sub_14009C620(int *a1, size_t *a2) {
    __int64 rsp;
    __int64 v_38;
    int v_4;
    int v_40;
    __int64 v_48;
    __int64 v_50;
    int v_58;
    __int64 v_60;
    int *v_0;
    __int64 v9;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 *v11;
    struct Struct_3_t *ptr3;
    __int64 *result;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 *src;
    __int64 v3;
    __int64 v4;
    __int64 *src2;
    __int64 v13;

    v9 = (__int64)a2;
    ptr = (struct Struct_1_t *)a1;
    if (a2 >= 33) {
        v2 = (__int64)ptr3;
        v11 = (__int64 *)ptr2;
        --v2;
        while (!((v2 < 0))) {
            ptr3 = (struct Struct_3_t *)v9;
            ptr3 = (struct Struct_3_t *)((__int64)(__int64)ptr3 >> 3);
            result = (__int64 *)ptr3;
            result = (__int64 *)((__int64)(__int64)result << 4);
            result = (__int64 *)((__int64)result + (__int64)ptr);
            a1 = ptr3 + (__int64)(__int64)ptr3*8;
            ptr2 = a1 + (__int64)(__int64)a1*2;
            ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)ptr);
            ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)ptr3);
            if (v9 >= 64) {
                sub_14009D080(ptr, result, ptr2, ptr3);
                result = (__int64 *)((__int64)result - (__int64)ptr);
                if (v11 != 0) {
                    a2 = *(__int64 *)((__int64)ptr + (__int64)result);
                    a1 = ptr->field_0;
                    if (*v11 < a2) {
                        *(__int64 *)ptr = (__int64)(a2);
                        *(__int64 *)((__int64)ptr + (__int64)result) = a1;
                        result = ptr + 4;
                        ptr2 = ptr->field_0;
                        a1 = ptr->field_4;
                        dst =  + v9*4 - 4;
                        dst = (__int64 *)((__int64)dst + (__int64)ptr);
                        ptr3 = ptr + 8;
                        if (ptr3 >= dst) {
                            dst = result;
                            a2 = 0;
                            src =  + v9*4;
                            src = (__int64 *)((__int64)src + (__int64)ptr);
                            if (ptr3 == src) {
                                /* cmp a1 , ptr2 */;
                                ptr2 = v_0[(__int64)a2];
                                *dst = ptr2;
                                v_0[(__int64)a2] = a1;
                                a2 += 0;
                                if (a2 >= v9) JUMPOUT(0x14009cfdb);
                                v3 =  + (__int64)(__int64)a2*4;
                                v3 += (__int64)ptr;
                                result = ptr->field_0;
                                a1 = *(__int64 *)(ptr + (__int64)(__int64)a2*4);
                                *(__int64 *)ptr = (__int64)(a1);
                                *(__int64 *)(ptr + (__int64)(__int64)a2*4) = (__int64)(result);
                                v4 =  + (__int64)(__int64)a2*4 + 4;
                                v4 += (__int64)ptr;
                                result = (__int64 *)a2;
                                result = (__int64 *)(~(__int64)result);
                                v9 += (__int64)result;
                                sub_14009C620(ptr, a2);
                                v11 = (__int64 *)v3;
                                ptr = (struct Struct_1_t *)v4;
                                if (v9 >= 2) {
                                    v3 = v9;
                                    v3 >>= 1;
                                    a2 = (size_t *)v3;
                                    if (v9 < 18) v3 = v9;
                                    src2 =  + v3*4;
                                    src2 = (__int64 *)((__int64)src2 + (__int64)ptr);
                                    result = (__int64 *)v9;
                                    result -= v3;
                                    v_60 = (__int64)result;
                                    ptr2 = (struct Struct_2_t *)ptr;
                                    v_48 = (__int64)src2;
                                    v_40 = v3;
                                    v_58 = v9;
                                    v_50 = (__int64)ptr;
                                    do {
                                        a1 = 1;
                                        if (a2 <= 8) {
                                            if (a1 > a2) JUMPOUT(0x14009cfdb);
                                            if (a1 != a2) {
                                                a2 = ptr2 + (__int64)(__int64)a2*4;
                                                a1 = (int *)((__int64)(__int64)a1 << 2);
                                                result = (__int64)ptr2 + (__int64)a1;
                                                do {
                                                    src = (__int64 *)v_4;
                                                    ptr3 = *result;
                                                    result += 4;
                                                    a1 += 4;
                                                } while (result != a2);
                                            }
                                            if (v9 >= 18) {
                                                a2 = (size_t *)v_60;
                                                /* cmp ptr2 , ptr */;
                                                ptr2 = (struct Struct_2_t *)src2;
                                                result = rsp + v9*4;
                                                result += 100;
                                                v_38 = (__int64)result;
                                                a2 =  + v9*4 - 4;
                                                a2 = (size_t *)((__int64)a2 + (__int64)ptr);
                                                ptr2 = src2 - 4;
                                                v3 = -v3;
                                                a1 = rsp + 104;
                                                src = 0;
                                                ptr3 = (struct Struct_3_t *)ptr;
                                                do {
                                                    result = *src2;
                                                    dst = (__int64 *)v3;
                                                    v3 = ptr3->field_0;
                                                    v4 = 0;
                                                    v2 = 0;
                                                    v4 = (result >= v3) ? 1 : 0;
                                                    v2 = (result < v3) ? 1 : 0;
                                                    if (result < v3) v3 = result;
                                                    result = *a2;
                                                    v13 = ptr2->field_0;
                                                    /* cmp result , v13 */;
                                                    v11 = 0;
                                                    v11 -= 1;
                                                    *a1 = v3;
                                                    v3 = (__int64)dst;
                                                    /* cmp result , v13 */;
                                                    src2 += v2*4;
                                                    ptr3 += v4*4;
                                                    if (ptr3 > 0) v13 = result;
                                                    result = 0;
                                                    result = 0;
                                                    a1 += 4;
                                                    dst = (__int64 *)v_38;
                                                    *(dst + (__int64)(__int64)src*4) = v13;
                                                    a2 += (__int64)(__int64)v11*4;
                                                    ptr2 += (__int64)(__int64)result*4;
                                                    --src;
                                                } while (v3 != src);
                                                ptr2 += 4;
                                                if ((v9 & 1) != 0) {
                                                    result = 0;
                                                    dst = 0;
                                                    result = (ptr3 >= ptr2) ? 1 : 0;
                                                    dst = (ptr3 < ptr2) ? 1 : 0;
                                                    src = src2;
                                                    if (ptr3 < ptr2) src = ptr3;
                                                    src = *src;
                                                    *a1 = src;
                                                    ptr3 += (__int64)(__int64)dst*4;
                                                    src2 += (__int64)(__int64)result*4;
                                                }
                                                if (ptr3 != ptr2) JUMPOUT(0x14009cfd6);
                                                a2 += 4;
                                                if (src2 != a2) JUMPOUT(0x14009cfd6);
                                                v9 <<= 2;
                                                a2 = rsp + 104;
                                                sub_1400F27F0(ptr, a2, v9, ptr3);
                                            }
                                            return (__int64)a2;
                                        }
                                        result = ptr2->field_C;
                                        src = ptr2->field_0;
                                        a1 = ptr2->field_4;
                                        ptr3 = (struct Struct_3_t *)src;
                                        if (result > src) ptr3 = result;
                                        if (result < src) src = result;
                                        result = ptr2->field_1C;
                                        v3 = (__int64)a1;
                                        if (result > a1) v3 = result;
                                        if (result < a1) a1 = result;
                                        result = ptr2->field_14;
                                        v2 = ptr2->field_8;
                                        dst = (__int64 *)v2;
                                        if (result > v2) dst = result;
                                        if (result < v2) v2 = result;
                                        v4 = ptr2->field_20;
                                        v_38 = (__int64)a2;
                                        a2 = ptr2->field_10;
                                        result = (__int64 *)a2;
                                        if (v4 > a2) result = v4;
                                        if (v4 < a2) a2 = v4;
                                        v4 = (__int64)src;
                                        if (v3 > src) v4 = v3;
                                        if (v3 >= src) v3 = src;
                                        v13 = v2;
                                        if (a2 > v2) v13 = a2;
                                        if (a2 >= v2) a2 = v2;
                                        src = (__int64 *)ptr3;
                                        if (result > ptr3) src = result;
                                        if (result >= ptr3) result = ptr3;
                                        ptr3 = ptr2->field_18;
                                        v2 = (__int64)dst;
                                        if (ptr3 > dst) v2 = ptr3;
                                        if (ptr3 < dst) dst = ptr3;
                                        ptr3 = (struct Struct_3_t *)v3;
                                        if (a2 > v3) ptr3 = a2;
                                        if (a2 >= v3) a2 = v3;
                                        v3 = (__int64)a1;
                                        if (result > a1) v3 = result;
                                        if (result >= a1) result = a1;
                                        src2 = (__int64 *)v13;
                                        if (dst > v13) src2 = dst;
                                        if (dst >= v13) dst = v13;
                                        v11 = (__int64 *)v4;
                                        if (src > v4) v11 = src;
                                        if (src >= v4) src = v4;
                                        v4 = (__int64)result;
                                        if (dst > result) v4 = dst;
                                        if (dst >= result) dst = result;
                                        a1 = (int *)v3;
                                        if (v2 > v3) a1 = v2;
                                        if (v2 < v3) v3 = v2;
                                        v13 = (__int64)src2;
                                        if (src > src2) v13 = src;
                                        if (src >= src2) src = src2;
                                        v2 = (__int64)a2;
                                        if (dst > a2) v2 = dst;
                                        if (dst >= a2) dst = a2;
                                        src2 = (__int64 *)ptr3;
                                        if (v4 > ptr3) src2 = v4;
                                        if (v4 >= ptr3) v4 = ptr3;
                                        result = (__int64 *)v3;
                                        if (src > v3) result = src;
                                        if (src >= v3) src = v3;
                                        ptr3 = (struct Struct_3_t *)a1;
                                        if (v11 > a1) ptr3 = v11;
                                        if (v11 < a1) a1 = v11;
                                        v3 = v4;
                                        if (src > v4) v3 = src;
                                        if (src >= v4) src = v4;
                                        a2 = (size_t *)src2;
                                        if (result > src2) a2 = result;
                                        *(__int64 *)ptr2 = (__int64)(dst);
                                        if (result >= src2) result = src2;
                                        src2 = (__int64 *)v_48;
                                        dst = (__int64 *)a1;
                                        if (v13 > a1) dst = v13;
                                        ptr2->field_20 = ptr3;
                                        if (v13 < a1) a1 = v13;
                                        ptr3 = (struct Struct_3_t *)v2;
                                        if (src > v2) v2 = src;
                                        ptr2->field_1C = dst;
                                        if (src >= v2) src = v2;
                                        dst = (__int64 *)v3;
                                        if (result > v3) dst = result;
                                        ptr2->field_4 = src;
                                        if (result >= v3) result = v3;
                                        v3 = v_40;
                                        src = (__int64 *)a2;
                                        if (a1 > a2) src = a1;
                                        ptr2->field_8 = v2;
                                        ptr2->field_C = result;
                                        if (a1 >= a2) a1 = a2;
                                        a2 = (size_t *)v_38;
                                        ptr2->field_10 = dst;
                                        ptr2->field_14 = a1;
                                        ptr2->field_18 = src;
                                        a1 = 9;
                                        return (__int64)a1;
                                    } while ((0 /* unresolved: flags == */));
                                    return (__int64)a1;
                                }
                                return (__int64)a1;
                            }
                            for (; ptr3 != src; ptr3 += 4) {
                                v3 = ptr3->field_0;
                                /* cmp v3 , ptr2 */;
                                v4 = v_0[(__int64)a2];
                                *dst = v4;
                                v_0[(__int64)a2] = v3;
                                a2 += 0;
                                dst = (__int64 *)ptr3;
                            }
                            ptr3 -= 4;
                            dst = (__int64 *)ptr3;
                            return (__int64)dst;
                        }
                        a2 = 0;
                        do {
                            src = ptr3->field_0;
                            v3 = 0;
                            v3 = (src < ptr2) ? 1 : 0;
                            v4 = v_0[(__int64)a2];
                            *(__int64 *)(ptr3 - 4) = (__int64)(v4);
                            v_0[(__int64)a2] = src;
                            src = a2 + v3;
                            v4 = ptr3->field_4;
                            /* cmp v4 , ptr2 */;
                            v13 = v_0[(__int64)src];
                            *(__int64 *)ptr3 = (__int64)(v13);
                            v_0[(__int64)src] = v4;
                            a2 += v3;
                            ptr3 += 8;
                        } while (ptr3 < dst);
                        dst = ptr3 - 4;
                        src =  + v9*4;
                        src = (__int64 *)((__int64)src + (__int64)ptr);
                        if (ptr3 != src) {
                            return (__int64)src;
                        }
                        return (__int64)src;
                    }
                    *(__int64 *)ptr = (__int64)(a2);
                    *(__int64 *)((__int64)ptr + (__int64)result) = a1;
                    a1 = ptr + 4;
                    ptr2 = ptr->field_0;
                    a2 = ptr->field_4;
                    dst =  + v9*4 - 4;
                    dst = (__int64 *)((__int64)dst + (__int64)ptr);
                    ptr3 = ptr + 8;
                    if (ptr3 >= dst) {
                        dst = (__int64 *)a1;
                        result = 0;
                        src =  + v9*4;
                        src = (__int64 *)((__int64)src + (__int64)ptr);
                        if (ptr3 == src) {
                            /* cmp ptr2 , a2 */;
                            ptr2 = v_0[(__int64)result];
                            *dst = ptr2;
                            v_0[(__int64)result] = a2;
                            result += 1;
                            if (result >= v9) JUMPOUT(0x14009cfdb);
                            a1 = ptr->field_0;
                            a2 = *(__int64 *)(ptr + (__int64)(__int64)result*4);
                            *(__int64 *)ptr = (__int64)(a2);
                            *(__int64 *)(ptr + (__int64)(__int64)result*4) = (__int64)(a1);
                            a1 = result + 1;
                            v9 -= (__int64)a1;
                            ptr += (__int64)(__int64)result*4 + 4;
                            v11 = 0;
                            return (__int64)v11;
                        }
                        for (; ptr3 != src; ptr3 += 4) {
                            v3 = ptr3->field_0;
                            /* cmp ptr2 , v3 */;
                            v4 = v_0[(__int64)result];
                            *dst = v4;
                            v_0[(__int64)result] = v3;
                            result += 1;
                            dst = (__int64 *)ptr3;
                        }
                        ptr3 -= 4;
                        dst = (__int64 *)ptr3;
                        return (__int64)dst;
                    }
                    result = 0;
                    do {
                        src = ptr3->field_0;
                        /* cmp ptr2 , src */;
                        v3 = v_0[(__int64)result];
                        *(__int64 *)(ptr3 - 4) = (__int64)(v3);
                        v_0[(__int64)result] = src;
                        result += 1;
                        src = ptr3->field_4;
                        /* cmp ptr2 , src */;
                        v3 = v_0[(__int64)result];
                        *(__int64 *)ptr3 = (__int64)(v3);
                        v_0[(__int64)result] = src;
                        result += 1;
                        ptr3 += 8;
                    } while (ptr3 < dst);
                    dst = ptr3 - 4;
                    src =  + v9*4;
                    src = (__int64 *)((__int64)src + (__int64)ptr);
                    if (ptr3 != src) {
                        return (__int64)src;
                    }
                    return (__int64)src;
                }
                a1 = ptr->field_0;
                a2 = *(__int64 *)((__int64)ptr + (__int64)result);
                return (__int64)a2;
            }
            a1 = ptr->field_0;
            a2 = *result;
            ptr3 = (a1 < a2) ? 1 : 0;
            dst = ptr2->field_0;
            a1 = (a1 < dst) ? 1 : 0;
            a1 = (int *)((__int64)(__int64)a1 ^ (__int64)ptr3);
            a2 = (a2 < dst) ? 1 : 0;
            a2 = (size_t *)((__int64)(__int64)a2 ^ (__int64)ptr3);
            if (a2 != 0) result = ptr2;
            if (a1 != 0) result = ptr;
            result = (__int64 *)((__int64)result - (__int64)ptr);
            if (v11 == 0) {
                return (__int64)result;
            }
            return (__int64)result;
        }
        a1 = (int *)ptr;
        a2 = (size_t *)v9;
        return sub_14009CFE0();
    }
    return (__int64)result;
}