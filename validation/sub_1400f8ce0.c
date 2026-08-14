// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[2048];
    __int64 field_810; // offset 0x810
    __int64 field_818; // offset 0x818
    __int64 field_820; // offset 0x820
    __int64 field_828; // offset 0x828
    char _pad_828[80];
    __int64 field_880; // offset 0x880
};

__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F5140();
__int64 sub_1400F27F0();
__int64 sub_1400F3340();
__int64 sub_14001B9E0();
__int64 sub_1400F4200();
__int64 sub_1400F3D20();
__int64 sub_1400F35E0();
__int64 sub_1400F41A0();
__int64 sub_14001BEA0();
extern __int64 off_14012D270;
extern __int64 off_140110058;
extern __int64 off_140110048;
extern __int64 off_140074130;
extern __int64 off_1401177B0;
extern __int64 off_14012D000;

__int64 __fastcall sub_1400F8CE0(int *a1, int *a2) {
    __int64 rsp;
    int arg_100;
    int arg_108;
    int arg_180;
    __int64 arg_8;
    int arg_808;
    int arg_810;
    int arg_818;
    int v_1040;
    int v_1050;
    int v_28;
    __int64 v_30;
    __int64 v_838;
    __int64 *v_0;
    char *str;
    __int64 v11;
    __int64 *result;
    __int64 v9;
    __int64 v10;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v8;
    __int64 *dst;
    __int64 v5;
    __m128i xmm0;
    __int64 src;
    __m128i xmm6;
    __m128i xmm7;
    __int64 v6;

    sub_1400F1D90(0x1068);
    _mm_store_si128((__m128i *)&v_1050, xmm7);
    _mm_store_si128((__m128i *)&v_1040, xmm6);
    v11 = (__int64)a2;
    result = *a1;
    v9 = arg_108;
    v10 = arg_100;
    ptr = (struct Struct_1_t *)a2;
    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 4);
    result = (__int64 *)a2;
    result = (__int64 *)((__int64)(__int64)result >> 60);
    result = (result == 0) ? 1 : 0;
    a2 = 0x7FFFFFFFFFFFFFF9;
    a2 = (ptr < a2) ? 1 : 0;
    if (((__int64)result & (__int64)a2) == 0) {
        sub_1400F3360(a1, a2);
    }
    v7 = arg_8;
    v8 = a1[2];
    if (ptr == 0) {
        dst = 8;
        if (v9 != v10) {
            --v8;
            result = v11 - 1;
            v5 = v9;
            v5 -= v10;
            a2 = v10 + 1;
            if ((v5 & 1) != 0) {
                v5 = v10;
                v5 &= v8;
                v5 <<= 4;
                v10 &= (__int64)result;
                v10 <<= 4;
                xmm0 = _mm_loadu_si128((__m128i *)(v7 + v5));
                _mm_storeu_si128((__m128i *)(dst + v10), xmm0);
                v10 = (__int64)a2;
            }
            if (v9 != a2) {
                do {
                    a2 = (int *)v10;
                    a2 = (int *)((__int64)(__int64)a2 & v8);
                    a2 = (int *)((__int64)(__int64)a2 << 4);
                    v5 = v10;
                    v5 &= (__int64)result;
                    v5 <<= 4;
                    xmm0 = _mm_loadu_si128((__m128i *)(v7 + a2));
                    _mm_storeu_si128((__m128i *)(dst + v5), xmm0);
                    a2 = v10 + 1;
                    v5 = (__int64)a2;
                    v5 &= v8;
                    v5 <<= 4;
                    a2 = (int *)((__int64)(__int64)a2 & (__int64)result);
                    a2 = (int *)((__int64)(__int64)a2 << 4);
                    xmm0 = _mm_loadu_si128((__m128i *)(v7 + v5));
                    _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)a2), xmm0);
                    v10 += 2;
                } while (v10 != v9);
            }
        }
    } else {
        src = (__int64)a1;
        sub_14002EDF0(0, ptr);
        a1 = (int *)src;
        dst = result;
        if (result == 0) {
            sub_1400F3326(8, ptr);
        } else {
            if (v9 != v10) {
                return (__int64)dst;
            } else {
            }
            result = off_14012D270;
            a2 = __readgsqword(88);
            a2 = v_0[(__int64)result];
            result = a2 + 8;
            if (a2[2] != 1) {
                do {
                    v9 = (__int64)a1;
                    sub_1400F5140(result);
                    a1 = (int *)v9;
                } while (true);
            }
            ptr = *result;
            v_838 = (__int64)ptr;
            result = ptr->field_818;
            if (result != -1) {
                a2 = result + 1;
                ptr->field_818 = a2;
                if (result != 0) {
                    v_30 = (__int64)ptr;
                    arg_8 = (__int64)dst;
                    a1[2] = v11;
                    src = *a1;
                    sub_14002EDF0(0, 16, v5);
                    if (result != 0) {
                        v9 = (__int64)result;
                        *result = dst;
                        v_28 = v11;
                        arg_8 = v11;
                        v9 = _InterlockedExchange64(src + 128, v9);
                        dst = ptr + 16;
                        result = ptr->field_810;
                        if (result >= 64) {
                            xmm6 = _mm_loadu_si128((__m128i *)&off_140110058);
                            xmm7 = _mm_loadu_si128((__m128i *)&off_140110048);
                            v10 = rsp + 0x838;
                            do {
                                v11 = ptr->field_8;
                                result = 96;
                                do {
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 24), xmm6);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 40), xmm7);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 8), xmm7);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 8), xmm6);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 24), xmm7);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 40), xmm6);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 56), xmm7);
                                    _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 72), xmm6);
                                    result += 128;
                                } while (result != 0x860);
                                sub_1400F27F0(v10, dst, 0x808);
                                sub_1400F27F0(dst, str, 0x800);
                                ptr->field_810 = 0;
                                *(__int64 *)rsp = *(__int64 *)rsp | 0;
                                src = arg_180;
                                sub_14002EDF0(0, 0x818);
                                if (result == 0) {
                                    sub_1400F3340(8, 0x818);
                                }
                                v6 = (__int64)result;
                                sub_1400F27F0(result, v10, 0x808);
                                arg_808 = src;
                                arg_810 = 0;
                                do {
                                    a1 = (int *)arg_100;
                                    a2 = a1;
                                    a2 = (int *)((__int64)(__int64)a2 & -8);
                                    v5 = a2[258];
                                    result = (__int64 *)a1;
                                    /* cmpxchg %v5, 256(%v11) */;
                                } while ((a2 != 0));
                                result = (__int64 *)a1;
                                /* cmpxchg %v6, 256(%v11) */;
                                result = ptr->field_810;
                            } while (result >= 64);
                        }
                        result = (__int64 *)((__int64)(__int64)result << 5);
                        a1 = &off_140074130;
                        *(__int64 *)((__int64)dst + (__int64)result) = a1;
                        *(__int64 *)((__int64)dst + (__int64)result + 8) = v9;
                        ptr->field_810 = ptr->field_810 + 1;
                        if (v_28 >= 64) {
                            a1 = rsp + 48;
                            sub_14001B9E0(a1, a2, v5);
                        }
                        result = ptr->field_818;
                        a1 = result - 1;
                        ptr->field_818 = a1;
                        if (result == 1) {
                            ptr->field_880 = 0;
                            if (ptr->field_820 == 0) {
                                a1 = (int *)ptr;
                                xmm6 = _mm_load_si128((__m128i *)&v_1040);
                                xmm7 = _mm_load_si128((__m128i *)&v_1050);
                                return sub_1400F4200();
                            }
                        }
                        xmm6 = _mm_load_si128((__m128i *)&v_1040);
                        xmm7 = _mm_load_si128((__m128i *)&v_1050);
                        return _mm_cvtsi128_si64(xmm7);
                    }
                    sub_1400F3340(8, 16);
                    return _mm_cvtsi128_si64(xmm7);
                }
                result = ptr->field_8;
                a2 = (int *)arg_180;
                a2 = (int *)((__int64)(__int64)a2 | 1);
                result = 0;
                /* cmpxchg %(__int64)a2, 0x880(%(__int64)ptr) */;
                result = ptr->field_828;
                a2 = result + 1;
                ptr->field_828 = a2;
                if (((__int64)result & 127) == 0) {
                    result = ptr->field_8;
                    result += 128;
                    a2 = rsp + 0x838;
                    src = (__int64)a1;
                    sub_1400F3D20(result, a2);
                    a1 = (int *)src;
                }
                return (__int64)a1;
            }
            a1 = &off_1401177B0;
            sub_1400F35E0(a1);
            return (__int64)a1;
        }
        sub_1400F41A0();
        sub_14001BEA0(off_14012D000);
        ptr = (struct Struct_1_t *)result;
        v_838 = (__int64)result;
        result = (__int64 *)arg_818;
        if (result != -1) {
            a1 = result + 1;
            ptr->field_818 = a1;
            if (result != 0) {
                result = ptr->field_820;
                a1 = result - 1;
                ptr->field_820 = a1;
                result = (__int64 *)((__int64)(__int64)result ^ 1);
                result = (__int64 *)((__int64)(__int64)result | (__int64)ptr->field_818);
                if ((result == 0)) JUMPOUT(0x1400f91ea);
                a1 = (int *)v9;
                return (__int64)a1;
            }
            result = ptr->field_8;
            a1 = (int *)arg_180;
            a1 = (int *)((__int64)(__int64)a1 | 1);
            result = 0;
            /* cmpxchg %(__int64)a1, 0x880(%(__int64)ptr) */;
            result = ptr->field_828;
            a1 = result + 1;
            ptr->field_828 = a1;
            if (((__int64)result & 127) == 0) JUMPOUT(0x1400f91f7);
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}