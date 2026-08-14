// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_140017B60();
__int64 sub_140024BB5();
__int64 sub_1400F37A0();
__int64 sub_1400F35E0();
__int64 sub_1400F37D0();
extern __int64 off_140024BEA;
extern __int64 off_140024C90;
extern __int64 off_140018400;
extern __int64 off_140110898;
extern __int64 off_1401108D8;
extern __int64 off_140119AA8;
extern __int64 off_140110810;
extern __int64 off_14011B42B;
extern __int64 off_1401107F8;

__int64 __fastcall sub_1400247C7(__int64 *a1, int *a2, size_t a3) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    __int64 arg_18;
    int arg_2;
    int arg_20;
    int arg_3;
    __int64 arg_8;
    int v_1;
    __int64 v_10;
    __int64 v_18;
    __int64 v_20;
    __int64 v_28;
    int v_6;
    int str;
    __int64 v_9;
    __int64 v_a;
    __int64 v_b;
    __int64 v_c;
    __int64 v_d;
    int v_e;
    int v_f;
    char *dst;
    __int64 *src;
    __int64 *result;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 *v3;
    __int64 v8;
    __int64 v4;
    __int64 v2;
    __int64 v10;
    __int64 v11;
    __int64 v9;

    a2 = (int *)arg_8;
    src = a1[4];
    result = 0x110001;
    a2 = (int *)((__int64)a2 - (__int64)src);
    if (!((a2 < 0))) {
        ptr = *a1;
        result = (__int64)ptr + (__int64)src;
        *a1 = result;
        arg_8 = (__int64)a2;
        if (src == 2) {
            a3 = ptr->field_0;
            v7 = a3 - 65;
            v7 &= 0xFFFFFFDF;
            v7 += 10;
            result = a3 - 48;
            if (a3 >= 58) result = v7;
            if (result <= 15) {
                a3 = ptr->field_1;
                v3 = a3 - 65;
                v3 = (__int64 *)((__int64)(__int64)v3 & 0xFFFFFFDF);
                v3 += 10;
                v7 = a3 - 48;
                if (a3 >= 58) v7 = v3;
                if (v7 < 16) {
                    result = (__int64 *)((__int64)(__int64)result << 4);
                    v7 |= (__int64)result;
                    if ((v7 < 0)) {
                        result = 0x110000;
                        if (v7 >= 192) {
                            a3 = 2;
                            if (v7 >= 224) {
                                a3 = 3;
                                if (v7 >= 240) {
                                    a3 = 4;
                                    if (v7 < 248) {
                                        result = dst + 45;
                                        v_1 = v7;
                                        *result = 0;
                                        arg_2 = 0;
                                        v7 = dst + 44;
                                        arg_18 = v7;
                                        arg_20 = a3;
                                        v8 =  + a3*2 - 2;
                                        src = (__int64 *)((__int64)src + (__int64)ptr);
                                        src += 2;
                                        ptr = 0;
                                        v3 = (__int64)a2 + (__int64)ptr;
                                        while (v3 >= 2) {
                                            v3 = (__int64)a2 + (__int64)ptr;
                                            v3 -= 2;
                                            *a1 = src;
                                            arg_8 = (__int64)v3;
                                            v4 = *(src - 2);
                                            v2 = v4 - 65;
                                            v2 &= 0xFFFFFFDF;
                                            v2 += 10;
                                            v3 = v4 - 48;
                                            if (v4 >= 58) v3 = v2;
                                            if (v3 <= 15) {
                                                v2 = *(src - 1);
                                                v10 = v2 - 65;
                                                v10 &= 0xFFFFFFDF;
                                                v10 += 10;
                                                v4 = v2 - 48;
                                                if (v2 >= 58) v4 = v10;
                                                if (v4 < 16) {
                                                    v3 = (__int64 *)((__int64)(__int64)v3 << 4);
                                                    v4 |= (__int64)v3;
                                                    *result = v4;
                                                    ptr -= 2;
                                                    ++result;
                                                    src += 2;
                                                    v3 = (__int64 *)v8;
                                                    v3 = (__int64 *)((__int64)v3 + (__int64)ptr);
                                                    v3 = dst - 40;
                                                    a2 = dst + 44;
                                                    sub_140017B60(v3, a2, 1, src);
                                                    result = 0x110000;
                                                    if (*v3 == 0) {
                                                        a1 = (__int64 *)v_20;
                                                        result = (__int64 *)v_18;
                                                        arg_8 = (__int64)a1;
                                                        arg_10 = (__int64)result;
                                                        a2 = (__int64)a1 + (__int64)result;
                                                        if (result != 0) {
                                                            result = *a1;
                                                            if (result < 0) {
                                                                a3 = (size_t)result;
                                                                a3 &= 31;
                                                                v7 = arg_1;
                                                                v7 &= 63;
                                                                if (result <= 223) {
                                                                    src = a1 + 2;
                                                                    a3 <<= 6;
                                                                    a3 |= v7;
                                                                    result = (__int64 *)a3;
                                                                } else {
                                                                    ptr = (struct Struct_1_t *)arg_2;
                                                                    v7 <<= 6;
                                                                    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 63);
                                                                    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | v7);
                                                                    if (result < 240) {
                                                                        src = a1 + 3;
                                                                        a3 <<= 12;
                                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | a3);
                                                                        result = (__int64 *)ptr;
                                                                    } else {
                                                                        src = a1 + 4;
                                                                        result = (__int64 *)arg_3;
                                                                        a3 &= 7;
                                                                        a3 <<= 18;
                                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 6);
                                                                        result = (__int64 *)((__int64)(__int64)result & 63);
                                                                        result = (__int64 *)((__int64)(__int64)result | (__int64)ptr);
                                                                        result = (__int64 *)((__int64)(__int64)result | a3);
                                                                    }
                                                                }
                                                            } else {
                                                                src = a1 + 1;
                                                            }
                                                            if (src != a2) {
                                                            } else {
                                                                if (result != 0x110000) {
                                                                    return (__int64)src;
                                                                }
                                                            }
                                                        }
                                                        sub_140024BB5();
                                                        a1 = dst - 48;
                                                        *a1 = result;
                                                        result = dst + 24;
                                                        v_28 = (__int64)result;
                                                        result = &off_140024BEA;
                                                        v_20 = (__int64)result;
                                                        result = dst + 8;
                                                        v_18 = (__int64)result;
                                                        result = &off_140024C90;
                                                        v_10 = (__int64)result;
                                                        str = (int)a1;
                                                        result = &off_140018400;
                                                        *dst = result;
                                                        result = &off_140110898;
                                                        a1 = dst - 96;
                                                        *a1 = result;
                                                        arg_8 = 4;
                                                        a1[4] = 0;
                                                        a1[2] = v3;
                                                        a1[3] = 3;
                                                        a2 = &off_1401108D8;
                                                        sub_1400F37A0(a1, a2);
                                                        result = (__int64 *)a2;
                                                        result = (__int64 *)((__int64)(__int64)result | 1);
                                                        result = 31 - __builtin_clz(result);
                                                        result = (__int64 *)((__int64)(__int64)result ^ 28);
                                                        result = (__int64 *)((__int64)(__int64)result >> 2);
                                                        v10 = result - 2;
                                                        str = 0;
                                                        v_6 = 0;
                                                        ptr = (struct Struct_1_t *)a2;
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 20);
                                                        v11 = &off_140119AA8;
                                                        ptr = *(__int64 *)(ptr + v11);
                                                        v_9 = (__int64)ptr;
                                                        ptr = (struct Struct_1_t *)a2;
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 16);
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 15);
                                                        ptr = *(__int64 *)(ptr + v11);
                                                        v_a = (__int64)ptr;
                                                        ptr = (struct Struct_1_t *)a2;
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 12);
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 15);
                                                        ptr = *(__int64 *)(ptr + v11);
                                                        v_b = (__int64)ptr;
                                                        ptr = (struct Struct_1_t *)a2;
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 8);
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 15);
                                                        ptr = *(__int64 *)(ptr + v11);
                                                        v_c = (__int64)ptr;
                                                        ptr = (struct Struct_1_t *)a2;
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 4);
                                                        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & 15);
                                                        ptr = *(__int64 *)(ptr + v11);
                                                        v_d = (__int64)ptr;
                                                        a2 = (int *)((__int64)(__int64)a2 & 15);
                                                        a2 = *(a2 + v11);
                                                        v_e = (int)a2;
                                                        v_f = 125;
                                                        *(__int64 *)(rsp + result + 4) = 0x755C;
                                                        *(__int64 *)(rsp + result + 6) = 123;
                                                        result = (__int64 *)v_e;
                                                        arg_8 = (__int64)result;
                                                        result = (__int64 *)v_6;
                                                        *a1 = result;
                                                        a1[1] = a3;
                                                        a1[1] = 10;
                                                        return (__int64)result;
                                                    }
                                                    return (__int64)result;
                                                }
                                            }
                                            a1 = &off_140110810;
                                            sub_1400F35E0(a1, a2, a3, src);
                                            a1 = &off_14011B42B;
                                            v9 = &off_1401107F8;
                                            sub_1400F37D0(a1, 40, v9);
                                            return v9;
                                        }
                                        result = 0x110000;
                                    }
                                    return (__int64)result;
                                }
                            }
                            return (__int64)result;
                        }
                    } else {
                        result = dst + 44;
                        *result = v7;
                        arg_1 = 0;
                        arg_3 = 0;
                        arg_18 = (__int64)result;
                        arg_20 = 1;
                        return arg_20;
                    }
                    return arg_20;
                }
            }
            return arg_20;
        }
        return arg_20;
    }
    return (__int64)result;
}