// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140028050();
__int64 sub_1400281E0();
__int64 sub_1400F37A0();
__int64 sub_1400F6B50();
__int64 sub_1400F6820();
__int64 sub_1400293D0();
__int64 sub_140029B40();
__int64 sub_140029AF0();
__int64 sub_1400281F0();
__int64 sub_140028220();
__int64 sub_14002E290();
__int64 off_140108060();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14012D268;
extern __int64 off_140027F90;
extern __int64 off_1401140A0;
extern __int64 off_1400143E0;
extern __int64 off_14012D270;
extern __int64 off_140114110;
extern __int64 off_140028030;
extern __int64 off_14012D240;
extern __int64 off_140108260;
extern __int64 off_140113310;
extern __int64 off_140113350;
extern __int64 off_14012D21A;
extern __int64 off_14012D21B;
extern __int64 off_140113E88;
extern __int64 off_14012D220;
extern __int64 off_1401213B0;
extern __int64 off_14012D250;
extern __int64 off_1401084F0;
extern __int64 off_140108500;
extern __int64 off_140114078;
extern __int64 off_14012D21C;
extern __int64 off_140113C68;
extern __int64 off_140114170;
extern __int64 off_140113C76;
extern __int64 off_14012D248;
extern __int64 off_14012D258;

__int64 __fastcall sub_1400277DC(int *a1, int *a2, size_t *a3, int a4) {
    __int64 rsp;
    int arg_18;
    int arg_28;
    __int64 arg_34;
    int arg_38;
    int arg_3c;
    int arg_4;
    int arg_40;
    __int64 arg_8;
    int arg_88;
    int arg_b0;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_50;
    __int64 v_58;
    int v_8;
    __int64 *v_0;
    __int64 *dst;
    __int64 *result;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v4;
    __int64 v6;
    __m128i xmm0;
    __int64 v8;
    __int64 v7;
    int v2;

    dst = rsp + 128;
    arg_40 = -2;
    v_28 = (int)a1;
    v_20 = (int)a2;
    arg_28 = (int)a3;
    ++off_14012D268;
    if ((off_14012D268 <= 0)) {
        a1 = dst - 24;
        *a1 = *a1 & 0;
        arg_4 = 0;
        result = dst + 40;
        a3 = dst - 88;
        *a3 = result;
        result = &off_140027F90;
        arg_8 = (__int64)result;
        result = dst - 40;
        a3[2] = result;
        result = &off_1401140A0;
        a2 = dst - 16;
        *a2 = result;
        arg_8 = 3;
        a2[4] = a2[4] & 0;
        result = &off_1400143E0;
        a3[3] = result;
        a2[2] = a3;
        a2[3] = 2;
        sub_140028050(a1, a2, a3);
        a1 = dst - 56;
    } else {
        result = off_14012D270;
        a3 = __readgsqword(88);
        result = v_0[(__int64)result];
        if (arg_88 != 0) {
            ((__int64 (*)())(a2[6]))();
            push(1);
            a3 = pop();
            if (result != 0) a3 = result;
            if (result == 0) a2 = result;
            result = dst - 56;
            a1 = dst + 56;
            *a1 = *a1 & 0;
            *result = a3;
            arg_8 = (__int64)a2;
            arg_4 = 0;
            a2 = dst + 40;
            a3 = dst - 88;
            *a3 = a2;
            a2 = &off_140027F90;
            arg_8 = (__int64)a2;
            a3[2] = result;
            result = &off_140114110;
            a2 = dst - 16;
            *a2 = result;
            arg_8 = 3;
            a2[4] = a2[4] & 0;
            result = &off_140028030;
            a3[3] = result;
            a2[2] = a3;
            a2[3] = 2;
            sub_140028050(a1, a2, a3);
            a1 = dst - 24;
            *a1 = result;
            sub_1400281E0(a1);
            push(7);
            a1 = pop();
            /* int $41 */;
        } else {
            ptr = result + 128;
            *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
            ptr->field_8 = 1;
            result = off_14012D240;
            if (result <= 0x3FFFFFFD) {
                a1 = result + 1;
                /* cmpxchg %(__int64)a1, off_14012D240 */;
                if ((0 /* unresolved: flags != */)) {
                    a1 = off_14012D240;
                    if (a1 == 0x3FFFFFFF) {
                        push(-99);
                        result = pop();
                        a1 = off_14012D240;
                        while (a1 == 0x3FFFFFFF) {
                            /* test result , result */;
                            ++result;
                        }
                    }
                    result = 0;
                    src = &off_14012D240;
                    v4 = dst - 16;
                    push(4);
                    push(-1);
                    v6 = off_140108260;
                    do {
                        do {
                            result = (__int64 *)a1;
                            result = (__int64 *)((__int64)(__int64)result & 0x3FFFFFFF);
                            a2 = (result >= 0x3FFFFFFE) ? 1 : 0;
                            a3 = (a1 >= 0x40000000) ? 1 : 0;
                            a3 = (size_t *)((__int64)(__int64)a3 | (__int64)a2);
                            if (result != 0x3FFFFFFE) {
                                if (((((__int64)a1 >> 30) & 1))) {
                                    a1 = (int *)((__int64)(__int64)a1 | 0x40000000);
                                    v_10 = (int)a1;
                                    ((__int64 (*)())v6)(src, v4, v7, v8);
                                    if (result == 1) {
                                        a1 = off_14012D240;
                                        result = 1;
                                        push(-99);
                                        a1 = pop();
                                        a2 = a1;
                                        do {
                                            a1 = off_14012D240;
                                            a3 = a2 + 1;
                                            /* test a2 , a2 */;
                                            a2 = (int *)a3;
                                        } while (true);
                                    }
                                    off_140108060();
                                    return (__int64)a2;
                                }
                                a2 = a1;
                                a2 = (int *)((__int64)(__int64)a2 | 0x40000000);
                                result = (__int64 *)a1;
                                /* cmpxchg %(__int64)a2, off_14012D240 */;
                                if ((a2 == 0)) {
                                    return (__int64)result;
                                }
                                a1 = (int *)result;
                            }
                            result = &off_140113310;
                            a1 = dst - 16;
                            *a1 = result;
                            arg_8 = 1;
                            a1[2] = 8;
                            xmm0 = _mm_setzero_si128();
                            _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
                            a2 = &off_140113350;
                            sub_1400F37A0(a1, a2, a3);
                            do {
                                a1 = &off_14012D21A;
                                sub_1400F6B50(a1);
                                do {
                                    result = off_14012D268;
                                    result = (__int64 *)((__int64)(__int64)result << 1);
                                    sub_1400F6820();
                                    result = (__int64 *)((__int64)(__int64)result ^ 1);
                                    a1 = off_14012D21B;
                                    a1 = dst - 24;
                                    v_10 = (int)a1;
                                    a1 = dst - 88;
                                    v_8 = (int)a1;
                                    a1 = dst + 56;
                                    *dst = a1;
                                    a1 = &off_140113E88;
                                    arg_8 = (__int64)a1;
                                    a2 = off_14012D270;
                                    a1 = __readgsqword(88);
                                    a1 = v_0[(__int64)a2];
                                    a3 = a1[13];
                                    arg_34 = (__int64)result;
                                    if (a3 <= 2) {
                                        result = off_14012D220;
                                        if (result == 0) {
                                            a1 = dst - 16;
                                            sub_1400293D0(a1, 0);
                                            result = (__int64 *)v8;
                                            a1 = &off_1401213B0;
                                            result = v_0[(__int64)result];
                                            result = (__int64 *)((__int64)result + (__int64)a1);
                                            JUMPOUT(result);
                                            a1 = dst + 56;
                                            sub_140029B40(a1, 0);
                                            a1 = dst - 16;
                                            *a1 = result;
                                            sub_1400281E0(a1);
                                            a1 = &off_14012D21A;
                                            a2 = (int *)arg_34;
                                            sub_140029AF0(a1, a2);
                                            sub_1400281F0(off_14012D250, a3, a3);
                                            ptr->field_8 = 0;
                                            if (v2 != 0) {
                                                sub_140028220();
                                                v8 = 1;
                                                if (ptr->field_0 > 1) {
                                                    v_18 = v6;
                                                    v4 = arg_18;
                                                    a1 = dst - 16;
                                                    ((__int64 (*)())v4)(a1, src);
                                                    xmm0 = _mm_load_si128((__m128i *)&v_10);
                                                    xmm0 = _mm_cmpeq_epi8(xmm0, _mm_load_si128((__m128i *)&off_1401084F0));
                                                    result = _mm_movemask_epi8(xmm0);
                                                    if (result != 0xFFFF) {
                                                        a1 = dst - 16;
                                                        ((__int64 (*)())v4)(a1, src);
                                                        xmm0 = _mm_load_si128((__m128i *)&v_10);
                                                        xmm0 = _mm_cmpeq_epi8(xmm0, _mm_load_si128((__m128i *)&off_140108500));
                                                        result = _mm_movemask_epi8(xmm0);
                                                        if (result != 0xFFFF) {
                                                            result = &off_140114078;
                                                            push(12);
                                                            a1 = pop();
                                                            v_58 = (__int64)result;
                                                            v_50 = (int)a1;
                                                            arg_38 &= 0;
                                                            arg_3c = 0;
                                                            a1 = 1;
                                                            result = 0;
                                                            /* cmpxchg %(__int64)a1, off_14012D21A */;
                                                        }
                                                        result = src + 8;
                                                        push(16);
                                                        a1 = pop();
                                                        result = *result;
                                                        a1 = *(__int64 *)((__int64)src + (__int64)a1);
                                                        return (__int64)a1;
                                                    }
                                                    push(8);
                                                    a1 = pop();
                                                    result = src;
                                                    return (__int64)result;
                                                }
                                                v8 = off_14012D21C;
                                                --v8;
                                                if (v8 >= 3) {
                                                    a2 = &off_140113C68;
                                                    a1 = dst - 16;
                                                    push(14);
                                                    a3 = pop();
                                                    sub_14002E290(a1, a2, a3);
                                                    result = (__int64 *)v_10;
                                                    a1 = (int *)result;
                                                    a1 = (int *)(-(__int64)a1);
                                                    if ((0 /* overflow check on (-a1) */)) {
                                                        a2 = (int *)v_8;
                                                        a1 = *dst;
                                                        if (a1 == 4) {
                                                            if (*a2 != 0x6C6C7566) {
                                                                v7 = 1;
                                                                v8 = 0;
                                                                if (result == 0) {
                                                                    result = 0;
                                                                    /* cmpxchg %v7, off_14012D21C */;
                                                                    if ((0 /* unresolved: flags == */)) {
                                                                        return (__int64)result;
                                                                    }
                                                                    v8 = 3;
                                                                    if (result > 3) {
                                                                        return v8;
                                                                    }
                                                                    result = (__int64 *)((__int64)(__int64)result << 3);
                                                                    v8 = 0x2010003;
                                                                    a1 = (int *)result;
                                                                    v8 >>= (__int64)a1;
                                                                    return v8;
                                                                }
                                                                arg_34 = (__int64)a1;
                                                                v8 = (__int64)a2;
                                                                off_140108030(0);
                                                                off_140108038(result, 0, v8);
                                                                v8 = arg_34;
                                                                return v8;
                                                            }
                                                            a1 = 1;
                                                            v7 = 2;
                                                            v8 = 1;
                                                            return v8;
                                                        }
                                                        if (a1 != 1) {
                                                            return v8;
                                                        }
                                                        if (*a2 != 48) {
                                                            return v8;
                                                        }
                                                        a1 = 2;
                                                        v7 = 3;
                                                        v8 = 2;
                                                        return v8;
                                                    }
                                                    v8 = 2;
                                                    v7 = 3;
                                                    return v7;
                                                }
                                                return v7;
                                            }
                                            a1 = dst - 56;
                                            *a1 = *a1 & 0;
                                            arg_4 = 0;
                                            result = &off_140114170;
                                            a2 = dst - 16;
                                            *a2 = result;
                                            arg_8 = 1;
                                            a2[2] = 8;
                                            xmm0 = _mm_setzero_si128();
                                            _mm_storeu_si128((__m128i *)(a2 + 24), xmm0);
                                            sub_140028050(a1, a2);
                                            a1 = dst - 88;
                                            *a1 = result;
                                            sub_1400281E0(a1);
                                            push(7);
                                            a1 = pop();
                                            /* int $41 */;
                                            v_10 = (int)a2;
                                            dst = a2 + 128;
                                            return sub_1400281F0(a1);
                                        }
                                        a1 = off_14012D270;
                                        a2 = __readgsqword(88);
                                        a1 = v_0[(__int64)a1];
                                        if (a1[12] != result) {
                                            return (__int64)a1;
                                        }
                                        a2 = &off_140113C76;
                                        a1 = dst - 16;
                                        push(4);
                                        a3 = pop();
                                        sub_1400293D0(a1, a2, a3);
                                        return (__int64)a3;
                                    }
                                    a2 = (int *)arg_8;
                                    if (a2 != 0) {
                                        a3 = a3[2];
                                        --a3;
                                        a1 = dst - 16;
                                        sub_1400293D0(a1, a2, a3);
                                        return (__int64)a1;
                                    }
                                    a1 = off_14012D220;
                                    if (*a3 != a1) {
                                        a1 = dst - 16;
                                        sub_1400293D0(a1, 0);
                                        return (__int64)a1;
                                    }
                                    a2 = &off_140113C76;
                                    a1 = dst - 16;
                                    push(4);
                                    a3 = pop();
                                    sub_1400293D0(a1, a2, a3);
                                    return (__int64)a3;
                                } while (!((0 /* unresolved: flags != */)));
                                return (__int64)a3;
                            } while ((0 /* unresolved: flags != */));
                        } while (true);
                    } while (a1 != 0x3FFFFFFF);
                }
                v7 = arg_b0;
                result = off_14012D248;
                if (off_14012D250 != 0) {
                    a1 = (int *)v_28;
                    result = (__int64 *)v_20;
                    ((__int64 (*)())(arg_28))();
                    a3 = dst - 16;
                    *a3 = result;
                    arg_8 = (__int64)a2;
                    result = (__int64 *)arg_28;
                    a3[2] = result;
                    a3[3] = v2;
                    a3[3] = v7;
                    result = off_14012D258;
                    ((__int64 (*)())(arg_28))();
                } else {
                    a1 = (int *)v_28;
                    result = (__int64 *)v_20;
                    ((__int64 (*)())(arg_28))();
                    src = result;
                    v4 = (__int64)a2;
                    v6 = arg_28;
                    if (v7 != 0) {
                        v8 = 3;
                        return v8;
                    }
                    return v8;
                }
                return v8;
            }
            return v8;
        }
        return v8;
    }
    return (__int64)result;
}