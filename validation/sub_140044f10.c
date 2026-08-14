// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14002E290();
__int64 sub_140045536();
__int64 sub_1400F2808();
__int64 sub_14004550A();
__int64 sub_1400F6D50();
__int64 off_140108030();
__int64 off_140108038();
__int64 off_1401080D8();
__int64 off_1401080E0();
__int64 off_1401080E8();
extern __int64 off_14012D238;
extern __int64 off_140113E70;
extern __int64 off_140113C68;
extern __int64 off_14012D21A;
extern __int64 off_14012D268;
extern __int64 off_14012D21B;
extern __int64 off_140044F10;

__int64 __fastcall sub_140044F10(int *a1) {
    int arg_490;
    int arg_498;
    int arg_4a0;
    __int64 arg_4a8;
    int arg_4b0;
    int arg_4b8;
    int arg_4c0;
    __int64 arg_4c8;
    __int64 arg_4d0;
    __int64 arg_4d8;
    int arg_4e0;
    __int64 arg_4e8;
    int arg_4f0;
    int arg_4f8;
    __int64 arg_500;
    int arg_50c;
    int arg_510;
    int arg_58;
    int arg_b8;
    __int64 v_20;
    int v_21;
    int v_23;
    int v_27;
    __int64 v_28;
    __int64 v_30;
    int v_38;
    int v_40;
    char *str;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v3;
    __int64 v11;
    __int64 v5;
    __int64 v7;
    __int64 *src;
    int v8;
    __int64 *i;
    __int64 v4;
    __int64 v9;
    __int64 v10;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;

    arg_510 = -2;
    ptr = (struct Struct_1_t *)a1;
    result = off_14012D238;
    if (result != 1) {
        if (result == 0) {
            v3 = &off_140113E70;
            a1 = str - 64;
            sub_14002E290(a1, v3, 18);
            v11 = v_40;
            result = (__int64 *)v11;
            result = (__int64 *)(-(__int64)result);
            if ((0 /* overflow check on (-result) */)) {
                v5 = v_38;
                result = (__int64 *)v_30;
                if ((v_28 & 1) == 0) {
                    if (result != 0) {
                        a1 = (int *)v_21;
                        a1 = (int *)((__int64)(__int64)a1 << 16);
                        v3 = v_23;
                        v3 |= (__int64)a1;
                        v3 <<= 32;
                        a1 = (int *)v_27;
                        a1 = (int *)((__int64)(__int64)a1 | v3);
                        v3 = v5 + result;
                        v7 = v5 + 1;
                        src = (__int64 *)v5;
                        do {
                            v8 = *src;
                            src = (__int64 *)v7;
                            v7 = 0;
                            v7 = (src != v3) ? 1 : 0;
                            v7 += (__int64)src;
                        } while (src != v3);
                    }
                }
                result = (__int64 *)v5;
                v5 = v11;
                v11 = 0x8000000000000000;
                arg_4a0 = v5;
                arg_4a8 = (__int64)result;
                arg_4b0 = (int)a1;
                if (v11 <= v3) v11 = v3;
                arg_498 = v11;
                if (v11 != v3) {
                    v3 = &off_140113C68;
                    a1 = str - 64;
                    sub_14002E290(a1, v3, 14);
                    result = (__int64 *)v_40;
                    a1 = (int *)result;
                    a1 = (int *)(-(__int64)a1);
                    if ((0 /* overflow check on (-a1) */)) {
                        i = (__int64 *)v_38;
                        a1 = (int *)v_30;
                        if ((v_28 & 1) == 0) {
                            if (a1 != 0) {
                                v3 = (__int64)i + (__int64)a1;
                                v7 = i + 1;
                                src = i;
                                do {
                                    v8 = *src;
                                    src = (__int64 *)v7;
                                    v7 = 0;
                                    v7 = (src != v3) ? 1 : 0;
                                    v7 += (__int64)src;
                                } while (src != v3);
                                if (a1 != 1) {
                                    v4 = 1;
                                    if (result != 0) {
                                        off_140108030(a1, v3, src, v7);
                                        off_140108038(result, 0, i);
                                    }
                                } else {
                                    v4 = (*i != 48) ? 1 : 0;
                                    if (result != 0) {
                                        return v4;
                                    } else {
                                    }
                                }
                                v11 <<= 1;
                                if (v11 != 0) {
                                    off_140108030(result, 0x8000000000000001, src, v7);
                                    off_140108038(result, 0, v5);
                                }
                                result = v4 + 1;
                                off_14012D238 = result;
                                if (v4 == 0) {
                                    *(__int64 *)ptr = (__int64)(1);
                                    return sub_140045536();
                                } else {
                                    a1 = 1;
                                    result = 0;
                                    /* cmpxchg %(__int64)a1, off_14012D21A */;
                                    if ((0 /* unresolved: flags != */)) JUMPOUT(0x14004559c);
                                    result = off_14012D268;
                                    result = (__int64 *)((__int64)(__int64)result << 1);
                                    arg_4d8 = (__int64)ptr;
                                    if (result != 0) JUMPOUT(0x1400455ad);
                                    arg_50c = 0;
                                    result = off_14012D21B;
                                    arg_4f0 = 0;
                                    arg_4f8 = 8;
                                    arg_500 = 0;
                                    v5 = 0;
                                    v4 = str - 64;
                                    sub_1400F2808(v4, 0, 0x4D0);
                                    off_1401080D8(v4);
                                    result = 8;
                                    arg_4e8 = (__int64)result;
                                    v9 = arg_b8;
                                    i = 0;
                                    v11 = 0;
                                    arg_4e0 = 0;
                                    v3 = str + 0x4E0;
                                    off_1401080E0(v9, v3, 0);
                                    while (result != 0) {
                                        v10 = (__int64)result;
                                        v3 = arg_4e0;
                                        result = (__int64 *)arg_58;
                                        arg_4b0 = 0;
                                        arg_4b8 = v3;
                                        arg_4c0 = v9;
                                        arg_4c8 = (__int64)result;
                                        arg_498 = 0;
                                        arg_4a0 = 8;
                                        arg_4a8 = 0;
                                        if (i != arg_4f0) {
                                            result = (__int64 *)arg_4c8;
                                            a1 = (int *)arg_4e8;
                                            *(a1 + v5 + 48) = result;
                                            xmm0 = _mm_loadu_si128((__m128i *)&arg_498);
                                            xmm1 = _mm_loadu_si128((__m128i *)&arg_4a8);
                                            xmm2 = _mm_loadu_si128((__m128i *)&arg_4b8);
                                            _mm_storeu_si128((__m128i *)(a1 + v5 + 32), xmm2);
                                            _mm_storeu_si128((__m128i *)(a1 + v5 + 16), xmm1);
                                            ptr = (struct Struct_1_t *)v5;
                                            _mm_storeu_si128((__m128i *)(a1 + v5), xmm0);
                                            v4 = (__int64)i;
                                            ++i;
                                            result = (__int64 *)v9;
                                            a1 = &off_140044F10;
                                            result = (__int64 *)((__int64)(__int64)result ^ (__int64)a1);
                                            result = (__int64 *)((__int64)(__int64)result | v11);
                                            result = (__int64 *)arg_4d0;
                                            if (result == 0) result = i;
                                            arg_4d0 = (__int64)result;
                                            result = 1;
                                            if (0 /* unresolved: flags == */) v11 = result;
                                            arg_500 = (__int64)i;
                                            v5 = arg_58;
                                            arg_490 = 0;
                                            arg_498 = 0;
                                            result = str + 0x498;
                                            v_30 = (__int64)result;
                                            result = str + 0x490;
                                            v_28 = (__int64)result;
                                            result = str - 64;
                                            v_20 = (__int64)result;
                                            v_38 = 0;
                                            off_1401080E8(0, v3, v9, v10);
                                            result = (__int64 *)arg_b8;
                                            if (result != 0) {
                                                if (result != v9) {
                                                    v5 = (__int64)ptr;
                                                    v5 += 56;
                                                    v9 = (__int64)result;
                                                }
                                                if (arg_58 != v5) {
                                                    return v9;
                                                }
                                            }
                                            i = (__int64 *)v4;
                                            ++i;
                                            a1 = (int *)arg_4d0;
                                            if (i == 0) JUMPOUT(0x1400454c9);
                                            result = 0;
                                            if ((v11 & 1) != 0) result = a1;
                                            a1 = (int *)arg_500;
                                            v_30 = (__int64)a1;
                                            xmm0 = _mm_loadu_si128((__m128i *)&arg_4f0);
                                            _mm_store_si128((__m128i *)&v_40, xmm0);
                                            ptr = (struct Struct_1_t *)arg_4d8;
                                            *(__int64 *)ptr = (__int64)(2);
                                            xmm0 = _mm_loadu_si128((__m128i *)&arg_4f0);
                                            _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
                                            a1 = (int *)arg_500;
                                            ptr->field_18 = a1;
                                            ptr->field_20 = result;
                                            ptr->field_28 = 3;
                                            return sub_14004550A();
                                        }
                                        a1 = str + 0x4F0;
                                        sub_1400F6D50(a1, v3);
                                        result = (__int64 *)arg_4f8;
                                        arg_4e8 = (__int64)result;
                                        v3 = arg_4e0;
                                        return v3;
                                    }
                                    return v3;
                                }
                            }
                            return v3;
                        }
                        return v3;
                    } else {
                        v4 = 0;
                    }
                    return v4;
                } else {
                    v4 = 1;
                    if (a1 == 1) {
                        v4 = (*result != 48) ? 1 : 0;
                    }
                    v5 = (__int64)result;
                    if (!((v5 == 0))) {
                        return v5;
                    }
                    return v5;
                }
                return v5;
            } else {
                v11 = 0x8000000000000000;
                arg_498 = v11;
            }
            return arg_498;
        }
        return arg_498;
    }
    return (__int64)result;
}