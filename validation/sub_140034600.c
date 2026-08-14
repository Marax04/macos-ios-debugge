// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[7];
    char field_7; // offset 7
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
__int64 sub_14000ECF0();
__int64 sub_1400F37A0();
__int64 sub_1400F6B50();
__int64 sub_1400F3B20();
__int64 sub_1400F6B10();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401129E7;
extern __int64 off_14012D270;
extern __int64 off_14012D230;
extern __int64 off_14012D1F8;
extern __int64 off_14012D200;
extern __int64 off_1401125A0;
extern __int64 off_140112578;
extern __int64 off_140112588;
extern __int64 off_14012D204;
extern __int64 off_140113A30;
extern __int64 off_140113A80;
extern __int64 off_140028030;
extern __int64 off_1400339F0;
extern __int64 off_140112A20;
extern __int64 off_140112A40;

__int64 __fastcall sub_140034600(__int64 *a1) {
    __int64 arg_10;
    __int64 arg_18;
    int arg_20;
    int arg_60;
    __int64 arg_8;
    int v_10;
    __int64 v_18;
    __int64 v_20;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    __int64 v_60;
    __int64 src;
    __int64 *v_0;
    char *dst;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v4;
    __int64 v2;
    __int64 v3;
    __int64 v6;
    __m128i xmm0;
    __int64 v7;

    arg_20 = -2;
    ptr = (struct Struct_1_t *)a1;
    result = &off_1401129E7;
    v_60 = (__int64)result;
    v_58 = 6;
    result = off_14012D270;
    a1 = __readgsqword(88);
    result = v_0[(__int64)result];
    v4 = arg_60;
    if (v4 == 0) {
        a1 = result + 96;
        result = off_14012D230;
        while (result != -1) {
            v4 = result + 1;
            /* cmpxchg %v4, off_14012D230 */;
            *a1 = v4;
            result = off_14012D1F8;
            if (v4 == result) {
                result = off_14012D200;
                if (result != 0xFFFFFFFF) {
                    ++result;
                    off_14012D200 = result;
                    result = &off_14012D1F8;
                    arg_18 = (__int64)result;
                    result = ptr->field_8;
                    if (result == 1) {
                        v2 = dst + 24;
                        v_20 = v2;
                        v_18 = 0;
                        v3 = &off_1401125A0;
                        v4 = dst - 32;
                        sub_140011760(v4, v3, ptr);
                        ptr = (struct Struct_1_t *)v_18;
                        if (result == 0) {
                            result = (__int64 *)ptr;
                            result = (__int64 *)((__int64)(__int64)result & 3);
                            if (result == 1) {
                                result = ptr - 1;
                                *dst = result;
                                result = *(__int64 *)(ptr - 1);
                                arg_8 = (__int64)result;
                                result = ptr->field_7;
                                arg_10 = (__int64)result;
                                result = *result;
                                if (result == 0) {
                                    a1 = (__int64 *)arg_8;
                                    result = (__int64 *)arg_10;
                                    if (arg_8 == 0) {
                                        off_140108030();
                                        ptr = 0;
                                        v6 = *dst;
                                        off_140108038(result, 0, v6);
                                        a1 = (__int64 *)arg_18;
                                        --arg_8;
                                        if ((arg_8 != 0)) {
                                            return arg_8;
                                        }
                                        *a1 = 0;
                                        result = 0;
                                        result = _InterlockedExchange64(&a1[1], result);
                                        if (result == 2) JUMPOUT(0x140034878);
                                        return (__int64)result;
                                    }
                                    v3 = arg_10;
                                    sub_14000ECF0(a1, v3);
                                    return v3;
                                }
                                a1 = (__int64 *)arg_8;
                                ((__int64 (*)())result)(a1);
                                return (__int64)a1;
                            }
                            ptr = 0;
                            a1 = (__int64 *)arg_18;
                            --arg_8;
                            if ((arg_8 != 0)) {
                                return arg_8;
                            }
                            return arg_8;
                        }
                        if (ptr != 0) {
                            return arg_8;
                        }
                        result = &off_140112578;
                        v_50 = (__int64)result;
                        v_48 = 1;
                        v_40 = 8;
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)&v_38, xmm0);
                        v3 = &off_140112588;
                        a1 = dst - 80;
                        sub_1400F37A0(a1, v3);
                    }
                    /* test result , result */;
                    return (__int64)a1;
                }
            } else {
                a1 = 1;
                result = 0;
                /* cmpxchg %(__int64)a1, off_14012D204 */;
                if ((0 /* unresolved: flags != */)) {
                    a1 = &off_14012D204;
                    sub_1400F6B50(a1);
                }
                off_14012D1F8 = v4;
                result = 1;
                return (__int64)result;
            }
            a1 = &off_140113A30;
            v7 = &off_140113A80;
            sub_1400F3B20(a1, 38, v7);
            return v7;
        }
        sub_1400F6B10(a1);
    } else {
        result = off_14012D1F8;
        if (v4 != result) {
            return (__int64)result;
        } else {
            return (__int64)result;
        }
        return (__int64)result;
    }
    do {
        arg_18 = (__int64)ptr;
        result = dst - 96;
        v_20 = (__int64)result;
        result = &off_140028030;
        v_18 = (__int64)result;
        v_10 = v2;
        result = &off_1400339F0;
        src = (__int64)result;
        result = &off_140112A20;
        v_50 = (__int64)result;
        v_48 = 2;
        v_30 = 0;
        v_40 = v4;
        v_38 = 2;
        v3 = &off_140112A40;
        a1 = dst - 80;
        sub_1400F37A0(a1, v3);
        do {
            return (__int64)a1;
        } while (true);
    } while (ptr != 0);
    return (__int64)result;
}