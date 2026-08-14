__int64 sub_1400B97F0();
__int64 sub_1400F27F0();

__int64 __fastcall sub_1400B91D0(size_t *a1, size_t *a2, int *a3, __int64 a4) {
    __int64 rsp;
    __int64 __rdx_rax;
    __int64 v_20;
    int v_28;
    int v_38;
    int v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    __int64 v_88;
    __int64 *v_d8;
    __int64 *src;
    __int64 *result;
    __int64 *src2;
    __int64 *dst;
    __int64 v3;
    __int64 i;
    __int64 v7;
    __int64 v10;
    __int64 v2;
    __int64 v8;
    __int64 v6;

    v_58 = (int)a1;
    if (a2 >= 2) {
        src = (__int64 *)a2;
        result = 0x4000000000000000;
        a2 = 0;
        result = __rdx_rax / (__int64)src; a2 = __rdx_rax % (__int64)src; /* unsigned */;
        /* cmp a2 , 1 */;
        result += 1;
        v_70 = (__int64)result;
        result = src;
        if (src >= 0x1001) {
            result = (__int64 *)((__int64)(__int64)result | 1);
            a1 = 63 - __builtin_clzll(result);
            result = (__int64 *)a1;
            result = (__int64 *)((__int64)(__int64)result >> 1);
            a1 = (size_t *)((__int64)(__int64)a1 & 1);
            a1 = (size_t *)((__int64)a1 + (__int64)result);
            result = 1;
            result = (__int64 *)((__int64)(__int64)result << (__int64)a1);
            a2 = (size_t *)src;
            a2 = (size_t *)((__int64)(__int64)a2 >> (__int64)a1);
            a2 = (size_t *)((__int64)a2 + (__int64)result);
            a2 = (size_t *)((__int64)(__int64)a2 >> 1);
            v_50 = (__int64)a2;
        } else {
            result = (__int64 *)((__int64)(__int64)result >> 1);
            a1 = (size_t *)src;
            a1 = (size_t *)((__int64)a1 - (__int64)result);
            result = 64;
            if (a1 < 64) result = a1;
            v_50 = (__int64)result;
        }
        result = (__int64 *)v_58;
        result -= 8;
        v_60 = (__int64)result;
        src2 = 1;
        dst = 0;
        v3 = 0x1FFFFFFFFFFFFFFE;
        i = 0;
        v_48 = a4;
        v_38 = (int)a3;
        v_80 = (__int64)src;
        do {
            result = (__int64 *)v_58;
            a1 = result + (__int64)(__int64)dst*8;
            src = (__int64 *)((__int64)src - (__int64)dst);
            v_40 = (int)a1;
            v3 = 0;
            result = 1;
            v_68 = (__int64)result;
            if (i >= 2) {
                result = (__int64 *)v_60;
                result += (__int64)(__int64)dst*8;
                v_78 = (__int64)result;
                v_88 = (__int64)dst;
                while (*(__int64 *)(rsp + i + 149) >= v3) {
                    --i;
                    v7 = v_d8[i];
                    v10 = v7;
                    v10 >>= 1;
                    v2 = (__int64)src2;
                    v2 >>= 1;
                    v8 = v10 + v2;
                    if (v8 > a4) {
                        result = dst;
                        result -= v8;
                        a1 = (size_t *)v_58;
                        dst = a1 + (__int64)(__int64)result*8;
                        if ((v7 & 1) != 0) {
                            if (((__int64)src2 & 1) != 0) {
                                if (src2 >= 2) {
                                    if (v7 < 2) {
                                        src2 =  + v8*2 + 1;
                                        dst = (__int64 *)v_88;
                                        i = 1;
                                        v_d8[i] = src2;
                                        *(__int64 *)(rsp + i + 150) = v3;
                                        src = (__int64 *)v_80;
                                        if (src > dst) {
                                            ++i;
                                            src2 = (__int64 *)v_68;
                                            result = src2;
                                            result = (__int64 *)((__int64)(__int64)result >> 1);
                                            dst = (__int64 *)((__int64)dst + (__int64)result);
                                            v3 = 0x1FFFFFFFFFFFFFFE;
                                        }
                                        if (((__int64)src2 & 1) == 0) {
                                            result = src;
                                            result = (__int64 *)((__int64)(__int64)result | 1);
                                            result = 63 - __builtin_clzll(result);
                                            result = (__int64 *)((__int64)(__int64)result ^ 63);
                                            result = (__int64 *)((__int64)result + (__int64)result);
                                            result = (__int64 *)((__int64)(__int64)result ^ 126);
                                            v_20 = (__int64)result;
                                            v_28 = 0;
                                            a1 = (size_t *)v_58;
                                            sub_1400B97F0(a1, src, a3, a4);
                                        }
                                        return (__int64)a1;
                                    }
                                    v7 = v10;
                                    if (v2 < v10) v10 = v2;
                                    if (a4 < v10) {
                                        return v7;
                                    }
                                    src2 =  + v10*8;
                                    src2 = (__int64 *)((__int64)src2 + (__int64)dst);
                                    if (v10 > v2) dst = src2;
                                    a3 =  + v7*8;
                                    sub_1400F27F0(a3, dst, a3, a4);
                                    src = (__int64 *)v_38;
                                    a3 = src + v7*8;
                                    if (v10 <= v2) {
                                        a2 = (size_t *)src;
                                        v6 = v_40;
                                        a1 = *src2;
                                        result = 0;
                                        a4 = 0;
                                        a1 = (a1 < *a2) ? 1 : 0;
                                        a4 = (0 /* unresolved: flags >= */) ? 1 : 0;
                                        src = (__int64 *)a2;
                                        if (0 /* unresolved: flags < */) src = src2;
                                        src = *src;
                                        *dst = src;
                                        a2 += a4*8;
                                        dst += 8;
                                        while (a2 != a3) {
                                            result = (__int64 *)a1;
                                            src2 += (__int64)(__int64)result*8;
                                        }
                                        a3 = (int *)((__int64)a3 - (__int64)a2);
                                        sub_1400F27F0(dst, src, a3, a4);
                                        a4 = v_48;
                                        a3 = (int *)v_38;
                                        return (__int64)a3;
                                    }
                                    result = (__int64 *)v_78;
                                    a1 = *(a3 - 8);
                                    a2 = 0;
                                    a4 = 0;
                                    a2 = (a1 < *(src2 - 8)) ? 1 : 0;
                                    a4 = (a1 >= *(src2 - 8)) ? 1 : 0;
                                    a1 = (size_t *)a3;
                                    if (0 /* unresolved: flags < */) a1 = src2;
                                    a1 = *(a1 - 8);
                                    *result = a1;
                                    src2 += a4*8;
                                    src2 -= 8;
                                    a3 += (__int64)(__int64)a2*8;
                                    a3 -= 8;
                                    while (src2 != dst) {
                                        result -= 8;
                                    }
                                    dst = src2;
                                    return (__int64)dst;
                                }
                                return (__int64)dst;
                            }
                            a1 =  + v10*8;
                            a1 = (size_t *)((__int64)a1 + (__int64)dst);
                            result = (__int64 *)v2;
                            result = (__int64 *)((__int64)(__int64)result | 1);
                            result = 63 - __builtin_clzll(result);
                            result = (__int64 *)((__int64)(__int64)result ^ 63);
                            result = (__int64 *)((__int64)result + (__int64)result);
                            result = (__int64 *)((__int64)(__int64)result ^ 126);
                            v_20 = (__int64)result;
                            v_28 = 0;
                            sub_1400B97F0(a1, v2, a3, a4);
                            a3 = (int *)v_38;
                            a4 = v_48;
                            if (src2 < 2) {
                                return a4;
                            }
                            return a4;
                        }
                        result = (__int64 *)v10;
                        result = (__int64 *)((__int64)(__int64)result | 1);
                        result = 63 - __builtin_clzll(result);
                        result = (__int64 *)((__int64)(__int64)result ^ 63);
                        result = (__int64 *)((__int64)result + (__int64)result);
                        result = (__int64 *)((__int64)(__int64)result ^ 126);
                        v_20 = (__int64)result;
                        v_28 = 0;
                        sub_1400B97F0(dst, v10, a3, a4);
                        a3 = (int *)v_38;
                        a4 = v_48;
                        if (((__int64)src2 & 1) == 0) {
                            return a4;
                        }
                        return a4;
                    }
                    result = (__int64 *)v7;
                    result = (__int64 *)((__int64)(__int64)result | (__int64)src2);
                    result = (__int64 *)((__int64)(__int64)result & 1);
                    if ((result != 0)) {
                        return (__int64)result;
                    }
                    v8 += v8;
                    src2 = (__int64 *)v8;
                    return (__int64)src2;
                }
                return (__int64)src2;
            }
            return (__int64)src2;
        } while (true);
    }
    return (__int64)result;
}