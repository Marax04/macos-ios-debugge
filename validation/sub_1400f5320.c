// inferred from 8 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[240];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
    char _pad_108[112];
    __int64 field_180; // offset 384
    char _pad_180[1664];
    __int64 field_808; // offset 0x808
    __int64 field_810; // offset 0x810
    __int64 field_818; // offset 0x818
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 6 accesses on `ptr2`
struct Struct_3_t {
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
__int64 sub_1400F3D20();
__int64 sub_1400F35E0();
__int64 sub_1400F3340();
__int64 sub_1400F4200();
__int64 sub_1400F41A0();
__int64 sub_14001BEA0();
__int64 sub_1400F27F0();
__int64 sub_14001B9E0();
extern __int64 off_14012D270;
extern __int64 off_1401177B0;
extern __int64 off_14012D008;
extern __int64 off_14012D000;
extern __int64 off_140110058;
extern __int64 off_140110048;
extern __int64 off_140074130;

__int64 __fastcall sub_1400F5320(int *a1, int *a2) {
    __int64 rsp;
    int arg_100;
    int arg_180;
    int v_1040;
    int v_1050;
    int v_28;
    __int64 v_30;
    __int64 v_838;
    __int64 *v_0;
    char *str;
    struct Struct_2_t *ptr;
    struct Struct_1_t *result;
    __int64 v10;
    __int64 v7;
    struct Struct_3_t *ptr2;
    __int64 src;
    __int64 v8;
    __int64 v11;
    __int64 *dst;
    __m128i xmm0;
    __m128i xmm6;
    __m128i xmm7;
    __int64 v6;
    __int64 v5;

    sub_1400F1D90(0x1068);
    _mm_store_si128((__m128i *)&v_1050, xmm7);
    _mm_store_si128((__m128i *)&v_1040, xmm6);
    ptr = (struct Struct_2_t *)a1;
    result = *a1;
    v10 = result->field_108;
    v7 = result->field_100;
    ptr2 = (struct Struct_3_t *)a2;
    ptr2 = (struct Struct_3_t *)((__int64)(__int64)ptr2 << 4);
    result = (struct Struct_1_t *)a2;
    result = (struct Struct_1_t *)((__int64)(__int64)result >> 60);
    result = (result == 0) ? 1 : 0;
    a1 = 0x7FFFFFFFFFFFFFF9;
    a1 = (ptr2 < a1) ? 1 : 0;
    if (((__int64)result & (__int64)a1) == 0) {
        sub_1400F3360(a1);
    }
    src = (__int64)a2;
    v8 = ptr->field_8;
    v11 = ptr->field_10;
    sub_14002EDF0(0, ptr2);
    if (result == 0) {
        sub_1400F3326(8, ptr2);
    } else {
        dst = (__int64 *)result;
        if (v10 != v7) {
            --v11;
            result = src - 1;
            a2 = (int *)v10;
            a2 -= v7;
            a1 = v7 + 1;
            if (((__int64)a2 & 1) != 0) {
                a2 = (int *)v7;
                a2 = (int *)((__int64)(__int64)a2 & v11);
                a2 = (int *)((__int64)(__int64)a2 << 4);
                v7 &= (__int64)result;
                v7 <<= 4;
                xmm0 = _mm_loadu_si128((__m128i *)(v8 + a2));
                _mm_storeu_si128((__m128i *)(dst + v7), xmm0);
                v7 = (__int64)a1;
            }
            if (v10 != a1) {
                do {
                    a1 = (int *)v7;
                    a1 = (int *)((__int64)(__int64)a1 & v11);
                    a1 = (int *)((__int64)(__int64)a1 << 4);
                    a2 = (int *)v7;
                    a2 = (int *)((__int64)(__int64)a2 & (__int64)result);
                    a2 = (int *)((__int64)(__int64)a2 << 4);
                    xmm0 = _mm_loadu_si128((__m128i *)(v8 + a1));
                    _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)a2), xmm0);
                    a1 = v7 + 1;
                    a2 = a1;
                    a2 = (int *)((__int64)(__int64)a2 & v11);
                    a2 = (int *)((__int64)(__int64)a2 << 4);
                    a1 = (int *)((__int64)(__int64)a1 & (__int64)result);
                    a1 = (int *)((__int64)(__int64)a1 << 4);
                    xmm0 = _mm_loadu_si128((__m128i *)(v8 + a2));
                    _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)a1), xmm0);
                    v7 += 2;
                } while (v7 != v10);
            }
        }
        result = off_14012D270;
        a1 = __readgsqword(88);
        a1 = v_0[(__int64)result];
        result = a1 + 8;
        if (a1[2] != 1) {
            sub_1400F5140(result);
            if (result != 0) {
                ptr2 = result->field_0;
                v_838 = (__int64)ptr2;
                result = ptr2->field_818;
                if (result != -1) {
                    a1 = result + 1;
                    ptr2->field_818 = a1;
                    result = ptr2->field_8;
                    a1 = result->field_180;
                    a1 = (int *)((__int64)(__int64)a1 | 1);
                    result = 0;
                    /* cmpxchg %(__int64)a1, 0x880(%(__int64)ptr2) */;
                    result = ptr2->field_828;
                    a1 = result + 1;
                    ptr2->field_828 = a1;
                    a1 = ptr2->field_8;
                    a1 += 128;
                    a2 = rsp + 0x838;
                    sub_1400F3D20(a1, a2);
                }
                a1 = &off_1401177B0;
                sub_1400F35E0(a1);
                sub_1400F3340(8, 16);
                a1 = (int *)ptr2;
                xmm6 = _mm_load_si128((__m128i *)&v_1040);
                xmm7 = _mm_load_si128((__m128i *)&v_1050);
                return sub_1400F4200();
            }
            result = off_14012D008;
        }
        return (__int64)result;
    }
    do {
        sub_1400F41A0();
        sub_14001BEA0(off_14012D000);
        ptr2 = (struct Struct_3_t *)result;
        v_838 = (__int64)result;
        result = result->field_818;
        while (result != -1) {
            a1 = result + 1;
            ptr2->field_818 = a1;
            if (result != 0) {
                result = ptr2->field_820;
                a1 = result - 1;
                ptr2->field_820 = a1;
                result = (struct Struct_1_t *)((__int64)(__int64)result ^ 1);
                result = (struct Struct_1_t *)((__int64)(__int64)result | (__int64)ptr2->field_818);
                if ((result != 0)) {
                    v_30 = (__int64)ptr2;
                    ptr->field_8 = dst;
                    ptr->field_10 = src;
                    v10 = src;
                    src = ptr->field_0;
                    sub_14002EDF0(0, 16);
                    while (result != 0) {
                        ptr = (struct Struct_2_t *)result;
                        *(__int64 *)result = (__int64)(dst);
                        v_28 = v10;
                        result->field_8 = v10;
                        ptr = _InterlockedExchange64(src + 128, ptr);
                        dst = ptr2 + 16;
                        result = ptr2->field_810;
                        if (result >= 64) {
                            xmm6 = _mm_loadu_si128((__m128i *)&off_140110058);
                            xmm7 = _mm_loadu_si128((__m128i *)&off_140110048);
                            v10 = rsp + 0x838;
                            do {
                                v11 = ptr2->field_8;
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
                                ptr2->field_810 = 0;
                                *(__int64 *)rsp = *(__int64 *)rsp | 0;
                                src = arg_180;
                                sub_14002EDF0(0, 0x818);
                                if (result == 0) {
                                    sub_1400F3340(8, 0x818);
                                    return src;
                                }
                                v6 = (__int64)result;
                                sub_1400F27F0(result, v10, 0x808);
                                result->field_808 = src;
                                result->field_810 = 0;
                                do {
                                    a1 = (int *)arg_100;
                                    a2 = a1;
                                    a2 = (int *)((__int64)(__int64)a2 & -8);
                                    v5 = a2[258];
                                    result = (struct Struct_1_t *)a1;
                                    /* cmpxchg %v5, 256(%v11) */;
                                } while (true);
                                result = (struct Struct_1_t *)a1;
                                /* cmpxchg %v6, 256(%v11) */;
                                result = ptr2->field_810;
                            } while (result >= 64);
                        }
                        result = (struct Struct_1_t *)((__int64)(__int64)result << 5);
                        a1 = &off_140074130;
                        *(__int64 *)((__int64)dst + (__int64)result) = a1;
                        *(__int64 *)((__int64)dst + (__int64)result + 8) = ptr;
                        ptr2->field_810 = ptr2->field_810 + 1;
                        if (v_28 >= 64) {
                            a1 = rsp + 48;
                            sub_14001B9E0(a1, a2, v5);
                        }
                        result = ptr2->field_818;
                        a1 = result - 1;
                        ptr2->field_818 = a1;
                        if (result == 1) {
                            ptr2->field_880 = 0;
                            if (ptr2->field_820 == 0) {
                                return (__int64)a1;
                            }
                        }
                        xmm6 = _mm_load_si128((__m128i *)&v_1040);
                        xmm7 = _mm_load_si128((__m128i *)&v_1050);
                        return _mm_cvtsi128_si64(xmm7);
                    }
                    return _mm_cvtsi128_si64(xmm7);
                }
                sub_1400F4200(ptr2);
                return _mm_cvtsi128_si64(xmm7);
            }
            result = ptr2->field_8;
            a1 = result->field_180;
            a1 = (int *)((__int64)(__int64)a1 | 1);
            result = 0;
            /* cmpxchg %(__int64)a1, 0x880(%(__int64)ptr2) */;
            result = ptr2->field_828;
            a1 = result + 1;
            ptr2->field_828 = a1;
            if (((__int64)result & 127) == 0) JUMPOUT(0x1400f5800);
            return (__int64)a1;
        }
        return (__int64)result;
    } while (result != 0);
}