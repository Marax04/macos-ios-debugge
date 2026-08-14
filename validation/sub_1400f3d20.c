// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[2056];
    __int64 field_808; // offset 0x808
    __int64 field_810; // offset 0x810
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[120];
    __int64 field_80; // offset 128
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    char _pad_100[120];
    __int64 field_180; // offset 384
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[2048];
    __int64 field_810; // offset 0x810
};

__int64 sub_1400F1D90();
__int64 sub_1400F40B0();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140110048;
extern __int64 off_140110058;
extern __int64 off_14001BB70;

__int64 __fastcall sub_1400F3D20(__int64 *a1, int *a2, size_t a3) {
    __int64 rsp;
    int arg_808;
    int v_1048;
    __int64 v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    int v_50;
    __int64 v_848;
    char *str;
    char *str2;
    __int64 *src;
    struct Struct_2_t *ptr;
    __int64 v4;
    struct Struct_4_t *ptr3;
    struct Struct_1_t *result;
    __int64 v8;
    __int64 v6;
    __int64 *src2;
    __m128i xmm0;
    __m128i xmm1;
    struct Struct_3_t *ptr2;

    sub_1400F1D90(0x1058);
    src = (__int64 *)a2;
    ptr = (struct Struct_2_t *)a1;
    sub_1400F40B0();
    v4 = (__int64)result;
    ptr3 = *a2;
    result = ptr3 + 16;
    v_20 = (__int64)result;
    a3 = 0;
    v8 = rsp + 0x848;
    v6 = ptr->field_0;
    src = (__int64 *)v6;
    src = (__int64 *)((__int64)(__int64)src & -8);
    a1 = *(src + 0x810);
    src2 = a1;
    src2 = (__int64 *)((__int64)(__int64)src2 & -8);
    while (!((src2 == 0))) {
        ++a3;
        result = (struct Struct_1_t *)arg_808;
        result = (struct Struct_1_t *)((__int64)(__int64)result & -2);
        a2 = (int *)v4;
        a2 = (int *)((__int64)a2 - (__int64)result);
        while (a2 >= 4) {
            result = (struct Struct_1_t *)v6;
            /* cmpxchg %(__int64)a1, (%(__int64)ptr) */;
            if ((0 /* unresolved: flags == */)) {
                result = ptr->field_80;
                if (v6 != result) {
                    v_28 = a3;
                    if (ptr3 == 0) {
                        off_140108030(a1, a2, a3);
                        off_140108038(result, 0, src);
                        src = *src2;
                        if (src != 0) {
                            src2 += 8;
                            sub_1400F27F0(str2, src2, 0x808);
                            v_848 = (__int64)src;
                            src = (__int64 *)v_1048;
                            if (src >= 65) JUMPOUT(0x1400f4091);
                            src2 = (__int64 *)v8;
                            if (src == 0) {
                                a3 = v_28;
                                v8 = (__int64)src2;
                                return v8;
                            }
                            src = (__int64 *)((__int64)(__int64)src << 5);
                            v8 = 0;
                            do {
                                xmm0 = _mm_loadu_si128((__m128i *)&*(__int64 *)(rsp + v8 + 0x848));
                                xmm1 = _mm_loadu_si128((__m128i *)&*(__int64 *)(rsp + v8 + 0x858));
                                _mm_store_si128((__m128i *)&v_50, xmm1);
                                _mm_store_si128((__m128i *)&v_40, xmm0);
                                xmm0 = _mm_loadu_si128((__m128i *)&off_140110048);
                                _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v8 + 0x848), xmm0);
                                xmm0 = _mm_loadu_si128((__m128i *)&off_140110058);
                                _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v8 + 0x858), xmm0);
                                a1 = (__int64 *)str;
                                ((__int64 (*)())(v_40))();
                                v8 += 32;
                            } while (src != v8);
                            return v8;
                        }
                        return v8;
                    }
                    result = ptr3->field_810;
                    v_38 = (__int64)ptr;
                    v_30 = v4;
                    if (result < 64) {
                        result = (struct Struct_1_t *)((__int64)(__int64)result << 5);
                        a1 = (__int64 *)v_20;
                        a2 = &off_14001BB70;
                        *(__int64 *)((__int64)a1 + (__int64)result) = a2;
                        *(__int64 *)((__int64)a1 + (__int64)result + 8) = v6;
                        ptr3->field_810 = ptr3->field_810 + 1;
                        src = *src2;
                        if (src != 0) {
                            return (__int64)src;
                        }
                        return (__int64)src;
                    }
                    do {
                        ptr2 = ptr3->field_8;
                        result = 96;
                        do {
                            xmm0 = _mm_loadu_si128((__m128i *)&off_140110058);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 16), xmm0);
                            xmm1 = _mm_loadu_si128((__m128i *)&off_140110048);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 32), xmm1);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result), xmm1);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 16), xmm0);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 32), xmm1);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 48), xmm0);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 64), xmm1);
                            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 80), xmm0);
                            result += 128;
                        } while (result != 0x860);
                        src = (__int64 *)v_20;
                        sub_1400F27F0(v8, src, 0x808);
                        a2 = rsp + 64;
                        sub_1400F27F0(src, a2, 0x800);
                        v4 = (__int64)ptr3;
                        ptr3->field_810 = 0;
                        *(__int64 *)rsp = *(__int64 *)rsp | 0;
                        ptr3 = ptr2->field_180;
                        sub_14002EDF0(0, 0x818);
                        if (result == 0) JUMPOUT(0x1400f4082);
                        src = (__int64 *)result;
                        ptr = (struct Struct_2_t *)v8;
                        sub_1400F27F0(result, v8, 0x808);
                        result->field_808 = ptr3;
                        result->field_810 = 0;
                        ptr3 = (struct Struct_4_t *)v4;
                        do {
                            a1 = ptr2->field_100;
                            a2 = (int *)a1;
                            a2 = (int *)((__int64)(__int64)a2 & -8);
                            a3 = a2[258];
                            result = (struct Struct_1_t *)a1;
                            /* cmpxchg %a3, 256(%(__int64)ptr2) */;
                        } while ((a2 != 0));
                        result = (struct Struct_1_t *)a1;
                        /* cmpxchg %(__int64)src, 256(%(__int64)ptr2) */;
                        result = ptr3->field_810;
                        v8 = (__int64)ptr;
                        v4 = v_30;
                        ptr = (struct Struct_2_t *)v_38;
                    } while (result >= 64);
                    return (__int64)ptr;
                }
                result = (struct Struct_1_t *)v6;
                /* cmpxchg %(__int64)a1, 128(%(__int64)ptr) */;
                return (__int64)result;
            }
            v6 = ptr->field_0;
            src = (__int64 *)v6;
            src = (__int64 *)((__int64)(__int64)src & -8);
            a1 = *(src + 0x810);
            src2 = a1;
            src2 = (__int64 *)((__int64)(__int64)src2 & -8);
        }
    }
    return (__int64)result;
}