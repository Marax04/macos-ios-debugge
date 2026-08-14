// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[768];
    int field_308; // offset 776
    __int64 field_30C; // offset 780
};

__int64 sub_1400F3600();
__int64 sub_1400F3869();
__int64 sub_14001943C();
extern __int64 off_14010B5D0;
extern __int64 off_14010BB88;
extern __int64 off_14010B652;
extern __int64 off_14010B540;
extern __int64 off_14010BB70;

__int64 __fastcall sub_140019140(size_t *a1, int *a2) {
    __int64 v6;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v3;
    __int64 v8;
    __int64 v4;
    __int64 *dst;
    __int64 v11;
    __int64 v12;
    __int64 i;
    __int64 v10;

    v6 = *a1;
    if (v6 != 0) {
        v7 = (__int64)a2;
        ptr = (struct Struct_1_t *)a1;
        v7 &= 63;
        a1 = (size_t *)v7;
        result = &off_14010B5D0;
        v3 = *(result + (__int64)(__int64)a1*2);
        a1 = (size_t *)v3;
        a1 = (size_t *)((__int64)(__int64)a1 & 0x7FF);
        if (a1 > 0x51C) {
            v6 = &off_14010BB88;
            sub_1400F3600(a2, 0x51C, 0x51C, v6);
        } else {
            v3 >>= 11;
            result = *(result + v7*2 + 2);
            result = (__int64 *)((__int64)(__int64)result & 0x7FF);
            result = (__int64 *)((__int64)result - (__int64)a1);
            a2 = result - 1;
            v8 = 0x51C;
            v8 -= (__int64)a1;
            v4 = 0x51B;
            v4 -= (__int64)a1;
            dst = &off_14010B652;
            a1 = (size_t *)((__int64)a1 + (__int64)dst);
            ++a1;
            dst = 0;
            while (result != dst) {
                if (v8 != dst) {
                    if (v6 != dst) {
                        if (dst != 768) {
                            v11 = *(__int64 *)((__int64)a1 + (__int64)dst - 1);
                            v12 = *(__int64 *)((__int64)ptr + (__int64)dst + 8);
                            if (v12 == v11) {
                                if (a2 != dst) {
                                    if (v4 != dst) {
                                        i = dst + 1;
                                        if (i != v6) {
                                            v11 = *(__int64 *)((__int64)a1 + (__int64)dst);
                                            v12 = *(__int64 *)((__int64)ptr + (__int64)dst + 9);
                                            ++i;
                                            dst = (__int64 *)i;
                                            v3 -= 0;
                                            dst = v3 + ptr;
                                            dst += 7;
                                            a2 = 0;
                                            v4 = 0xCCCCCCCCCCCCCCCD;
                                            v11 = v6;
                                            --v6;
                                            while (v11 < 769) {
                                                v8 = *(__int64 *)(ptr + v11 + 7);
                                                a1 = (size_t *)v7;
                                                v8 <<= (__int64)a1;
                                                v8 += (__int64)a2;
                                                result = (__int64 *)v8;
                                                result = (__int64 *)((__int64)(__int64)(__int64)result * v4); /* unsigned; high half in a2 */;
                                                a1 = v11 + v3;
                                                --a1;
                                                a2 = (int *)((__int64)(__int64)a2 >> 3);
                                                result = (__int64)a2 + (__int64)a2;
                                                v12 = result + (__int64)(__int64)result*4;
                                                result = (__int64 *)v8;
                                                result -= v12;
                                                if (a1 < 768) {
                                                    *(dst + v11) = result;
                                                    if (v8 >= 10) {
                                                        v6 = v3 - 1;
                                                        do {
                                                            result = (__int64 *)a2;
                                                            result = (__int64 *)((__int64)(__int64)(__int64)result * v4); /* unsigned; high half in a2 */;
                                                            a2 = (int *)((__int64)(__int64)a2 >> 3);
                                                            result = (__int64)a2 + (__int64)a2;
                                                            v10 = result + (__int64)(__int64)result*4;
                                                            result = (__int64 *)a1;
                                                            result -= v10;
                                                            *(__int64 *)(ptr + v6 + 8) = (__int64)(result);
                                                            --v6;
                                                        } while (a1 >= 10);
                                                    }
                                                    a1 = ptr->field_0;
                                                    a1 += v3;
                                                    result = 768;
                                                    if (a1 < 768) result = a1;
                                                    *(__int64 *)ptr = (__int64)(result);
                                                    ptr->field_308 = ptr->field_308 + v3;
                                                    if (a1 != 0) {
                                                        --result;
                                                        while (*(__int64 *)((__int64)ptr + (__int64)result + 8) == 0) {
                                                            *(__int64 *)ptr = (__int64)(result);
                                                            result -= 1;
                                                        }
                                                    }
                                                    return (__int64)result;
                                                }
                                                if (result == 0) {
                                                    return (__int64)result;
                                                }
                                                ptr->field_30C = 1;
                                                return (__int64)result;
                                            }
                                            ptr = &off_14010B540;
                                            sub_1400F3869(v6, 768, ptr);
                                            ptr = &off_14010BB70;
                                            sub_1400F3869(768, 768, ptr);
                                            result = (__int64 *)a1;
                                            a2 = (int *)((__int64)(__int64)a2 & 63);
                                            v8 = *a1;
                                            v6 = v8 - 1;
                                            v7 = 0;
                                            ptr = 0;
                                            do {
                                                if (v8 == v7) JUMPOUT(0x140019403);
                                                if (v7 == 768) JUMPOUT(0x1400194e1);
                                                a1 = ptr + (__int64)(__int64)ptr*4;
                                                ptr = *(result + v7 + 8);
                                                ptr += (__int64)(__int64)a1*2;
                                                v3 = (__int64)ptr;
                                                a1 = (size_t *)a2;
                                                v3 >>= (__int64)a1;
                                                if (v3 != 0) JUMPOUT(0x140019439);
                                                if (v6 == v7) JUMPOUT(0x140019403);
                                                a1 = ptr + (__int64)(__int64)ptr*4;
                                                ptr = *(result + v7 + 9);
                                                ptr += (__int64)(__int64)a1*2;
                                                v7 += 2;
                                                v3 = (__int64)ptr;
                                                a1 = (size_t *)a2;
                                                v3 >>= (__int64)a1;
                                            } while (v3 == 0);
                                            return sub_14001943C();
                                        }
                                        --v3;
                                    }
                                }
                                return v3;
                            }
                            return v3;
                        }
                        return v3;
                    }
                    return v3;
                }
            }
            return v3;
        }
        return v3;
    }
    return (__int64)result;
}