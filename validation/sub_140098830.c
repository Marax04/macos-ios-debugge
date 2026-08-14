// inferred from 5 accesses on `i`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[32];
    __int64 field_38; // offset 56
    char _pad_38[56];
    int field_78; // offset 120
    __int64 field_7C; // offset 124
};

__int64 sub_140099E40();
__int64 sub_140098FD2();
__int64 sub_140099220();
__int64 sub_1400FB040();
__int64 sub_14009A1C0();
__int64 sub_1400F5F90();
__int64 sub_14009A2D0();
__int64 sub_1400972B0();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140098830(size_t *a1, int *a2, size_t a3, int *a4) {
    __int64 rsp;
    int arg_10;
    int arg_14;
    int arg_20;
    int arg_24;
    int arg_28;
    int arg_2c;
    int arg_78;
    int arg_7c;
    int arg_8;
    int v_100;
    __int64 v_20;
    int v_28;
    int v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    __int64 v_60;
    int v_68;
    int v_70;
    __int64 v_78;
    int v_80;
    __int64 v_88;
    int v_90;
    __int64 v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_c8;
    __int64 v_d8;
    int v_e0;
    int v_f0;
    int v_f8;
    int *arg_0;
    int *arg_2;
    int *v_0;
    int *v_110;
    int *v_2;
    __int64 *v_8;
    __int64 *src;
    __int64 v4;
    __int64 *result;
    __int64 v6;
    __int64 v9;
    __int64 v5;
    __int64 v3;
    __int64 i2;
    __int64 *dst;
    __int64 *src2;
    __m128i xmm0;
    struct Struct_1_t *i;

    v_100 = (int)a4;
    src = (__int64 *)a2;
    v4 = (__int64)a1;
    v_b0 = 0;
    v_c0 = 0;
    if (a1[28] >= 6) {
        a1 = (size_t *)arg_78;
        result = (__int64 *)arg_7c;
        a2 = (int *)result;
        a2 = (int *)((__int64)(__int64)a2 | (__int64)a1);
        if (!((a2 == 0))) {
            a2 = (int *)arg_20;
            a4 = (int *)arg_28;
            a2 -= 28;
            v6 = a4 + (__int64)(__int64)a4*8;
            v9 = v6 + v6*2;
            v9 += (__int64)a4;
            while (v9 != 0) {
                v5 = arg_24;
                v3 = arg_28;
                a4 = (int *)arg_2c;
                if (a4 > v5) v5 = a4;
                v5 += v3;
                if (!((v5 < 0))) {
                    a2 += 28;
                    v9 -= 28;
                    v6 = (__int64)a1;
                    v6 -= v3;
                    if (v6 < a4) {
                        a1 = (size_t *)arg_14;
                        a2 = (int *)v6;
                        a2 = (int *)((__int64)a2 + (__int64)a1);
                        v5 = arg_10;
                        if (a2 >= v5) {
                            v_68 = 0;
                            v_88 = 0;
                            v_a8 = 0;
                            v3 = rsp + 80;
                            v4 = rsp + 104;
                            v9 = off_140108030;
                            i2 = off_140108038;
                            sub_140099E40(v3, v4);
                            result = (__int64 *)v_50;
                            while (result != 0) {
                                a1 = (size_t *)v_60;
                                a1 += (__int64)(__int64)a1*2;
                                result += (__int64)(__int64)a1*8;
                                result += 8;
                                src = (__int64 *)arg_8;
                                ((__int64 (*)())v9)(a1);
                                ((__int64 (*)())i2)(result, 0, src);
                            }
                            a1 = 1;
                            v4 = 0;
                            v3 = 0;
                            result = 0;
                        } else {
                            if (result >= 8) {
                                result = (__int64 *)((__int64)result + (__int64)a2);
                                dst = a2 + 8;
                                a4 = (int *)arg_8;
                                v_f8 = v5;
                                v_f0 = (int)a4;
                                v_c8 = v4;
                                v_e0 = a3;
                                v_d8 = (__int64)result;
                                return sub_140098FD2();
                            } else {
                                v_c8 = v4;
                                if (a3 != 0) {
                                    v3 = src + a3*4;
                                    result = src + 4;
                                    v4 = rsp + 176;
                                    v9 = rsp + 104;
                                    do {
                                        src2 = *src;
                                        src = result;
                                        result = src2;
                                        result = (__int64 *)((__int64)(__int64)result & 0xFFFFF000);
                                        a1 = (size_t *)v_b0;
                                        v_68 = v4;
                                        v_70 = 0;
                                        v_88 = (__int64)result;
                                        sub_140099220(v9, a2, a3, a4);
                                        i2 = arg_10;
                                        if (i2 == *result) {
                                            dst = result;
                                            sub_1400FB040(result, a2, a4, v6);
                                            result = dst;
                                        }
                                        src2 = (__int64 *)((__int64)(__int64)src2 & 0xFFF);
                                        a1 = (size_t *)arg_8;
                                        v_0[i2] = src2;
                                        v_2[i2] = 10;
                                        ++i2;
                                        arg_10 = i2;
                                        result = 0;
                                        result = (src != v3) ? 1 : 0;
                                        result = src + (__int64)(__int64)result*4;
                                    } while (!((result == 0)));
                                }
                                v_38 = 0;
                                v_40 = 1;
                                v_48 = 0;
                                result = (__int64 *)v_b0;
                                a1 = (size_t *)v_b8;
                                a2 = 0;
                                a3 = (size_t)result;
                                a4 = (result != 0) ? 1 : 0;
                                if (result != 0) {
                                    a3 = v_c0;
                                }
                                v_68 = (int)a2;
                                v_70 = 0;
                                v_78 = (__int64)result;
                                v_80 = (int)a1;
                                v_88 = (__int64)a2;
                                v_90 = 0;
                                v_98 = (__int64)result;
                                v_a0 = (int)a1;
                                v_a8 = a3;
                                dst = 1;
                                src = 0;
                                a1 = rsp + 80;
                                a2 = rsp + 104;
                                sub_140099E40(a1, a2, a3, a4);
                                result = (__int64 *)v_50;
                                while (result != 0) {
                                    a1 = (size_t *)v_60;
                                    a2 = a1 + (__int64)(__int64)a1*2;
                                    v9 = v_8[(__int64)a2];
                                    a3 = v9;
                                    a3 = -a3;
                                    if (!((0 /* overflow check on (-a3) */))) {
                                        i2 = v_110[(__int64)a1];
                                        result += (__int64)(__int64)a2*8;
                                        result += 8;
                                        v_50 = v9;
                                        xmm0 = _mm_loadu_si128((__m128i *)(result + 8));
                                        result = rsp + 88;
                                        _mm_storeu_si128((__m128i *)result, xmm0);
                                        src2 = (__int64 *)v_58;
                                        i = (struct Struct_1_t *)v_60;
                                        if (i >= 2) {
                                            if (i >= 21) {
                                                sub_14009A1C0();
                                                if (((__int64)i & 1) == 0) {
                                                    result = (__int64 *)v_38;
                                                    result = (__int64 *)((__int64)result - (__int64)src);
                                                    if (result <= 3) {
                                                        a1 = rsp + 56;
                                                        sub_1400F5F90(a1, src, 4);
                                                        dst = (__int64 *)v_40;
                                                        src = (__int64 *)v_48;
                                                    }
                                                    *(__int64 *)((__int64)dst + (__int64)src) = i2;
                                                    src += 4;
                                                    v3 = (__int64)i + (__int64)i + 8;
                                                    result = 0xFFFFFFFF;
                                                    if (i >= 0x7FFFFFFC) v3 = result;
                                                    v_48 = (__int64)src;
                                                    result = (__int64 *)v_38;
                                                    result = (__int64 *)((__int64)result - (__int64)src);
                                                    if (result <= 3) {
                                                        a1 = rsp + 56;
                                                        sub_1400F5F90(a1, src, 4);
                                                        src = (__int64 *)v_48;
                                                    }
                                                    dst = (__int64 *)v_40;
                                                    *(__int64 *)((__int64)dst + (__int64)src) = v3;
                                                    src += 4;
                                                    v_48 = (__int64)src;
                                                    i2 = v_50;
                                                    v9 = v_58;
                                                    i = (struct Struct_1_t *)((__int64)(__int64)i << 2);
                                                    src2 = (__int64 *)v9;
                                                    if (i == 0) {
                                                        ((__int64 (*)())off_140108030)();
                                                        ((__int64 (*)())off_140108038)(result, 0, v9);
                                                    }
                                                    do {
                                                        v4 = *src2;
                                                        v3 = (__int64)arg_2;
                                                        result = (__int64 *)v_38;
                                                        result = (__int64 *)((__int64)result - (__int64)src);
                                                        a1 = rsp + 56;
                                                        sub_1400F5F90(a1, src, 2);
                                                        dst = (__int64 *)v_40;
                                                        src = (__int64 *)v_48;
                                                        src2 += 4;
                                                        v3 <<= 12;
                                                        v4 &= 0xFFF;
                                                        v4 |= v3;
                                                        *(__int64 *)((__int64)dst + (__int64)src) = v4;
                                                        src += 2;
                                                        v_48 = (__int64)src;
                                                        i -= 4;
                                                    } while (i != 0);
                                                    return (__int64)i;
                                                }
                                                if (i == v9) {
                                                    a1 = rsp + 80;
                                                    sub_1400FB040(a1);
                                                    src2 = (__int64 *)v_58;
                                                }
                                                arg_0[(__int64)i] = 0;
                                                arg_2[(__int64)i] = 0;
                                                ++i;
                                                v_60 = (__int64)i;
                                                result = (__int64 *)v_38;
                                                result = (__int64 *)((__int64)result - (__int64)src);
                                                if (result > 3) {
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            sub_14009A2D0(src2, i);
                                            if (((__int64)i & 1) == 0) {
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        if (((__int64)i & 1) != 0) {
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                }
                                v9 = rsp + 80;
                                i2 = rsp + 104;
                                i = (struct Struct_1_t *)v_c8;
                                sub_140099E40(v9, i2);
                                result = (__int64 *)v_50;
                                while (result != 0) {
                                    a1 = (size_t *)v_60;
                                    a1 += (__int64)(__int64)a1*2;
                                    result += (__int64)(__int64)a1*8;
                                    result += 8;
                                    dst = (__int64 *)arg_8;
                                    ((__int64 (*)())off_140108030)(a1);
                                    ((__int64 (*)())off_140108038)(result, 0, dst);
                                }
                                i2 = 0xFFFFFFFF;
                                if (src < i2) i2 = src;
                                v9 = v_40;
                                v_20 = (__int64)src;
                                v_28 = 0x42000040;
                                a2 = (int *)v_100;
                                sub_1400972B0(i, a2, 8, v9);
                                v3 = (__int64)result;
                                v3 >>= 32;
                                v4 = v3;
                                if (((__int64)result & 1) == 0) {
                                    i->field_78 = v3;
                                    i->field_7C = i2;
                                    a3 = i->field_10;
                                    a2 = i->field_38;
                                    result = a2 + 160;
                                    if (result <= a3) {
                                        a1 = a2 + 152;
                                        a2 += 156;
                                        if (a1 > -5) JUMPOUT(0x1400991d1);
                                        if (a2 > a3) JUMPOUT(0x1400991d1);
                                        a4 = i->field_8;
                                        *(__int64 *)((__int64)a4 + (__int64)a1) = v3;
                                        if (result < a2) JUMPOUT(0x1400991dd);
                                        *(__int64 *)((__int64)a4 + (__int64)a2) = i2;
                                    }
                                    v3 &= 0xFFFF0000;
                                    if (v_38 != 0) {
                                        ((__int64 (*)())off_140108030)(a1, a2, a3, a4);
                                        ((__int64 (*)())off_140108038)(result, 0, v9);
                                    }
                                    result = 0;
                                    a1 = 0;
                                } else {
                                    if (v_38 != 0) {
                                        v3 = (__int64)result;
                                        ((__int64 (*)())off_140108030)();
                                        ((__int64 (*)())off_140108038)(result, 0, v9);
                                        result = (__int64 *)v3;
                                    }
                                    result = (__int64 *)((__int64)(__int64)result & 0xFFFF0000);
                                    a1 = 1;
                                    v3 = 0;
                                }
                            }
                        }
                        result = (__int64 *)((__int64)(__int64)result | (__int64)a1);
                        v4 |= v3;
                        v4 <<= 32;
                        v4 |= (__int64)result;
                        result = (__int64 *)v4;
                        return (__int64)result;
                    }
                }
            }
            return (__int64)result;
        }
    }
    return (__int64)result;
}