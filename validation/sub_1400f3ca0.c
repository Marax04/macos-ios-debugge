// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[120];
    __int64 field_80; // offset 128
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    char _pad_100[120];
    __int64 field_180; // offset 384
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[2048];
    __int64 field_810; // offset 0x810
};

__int64 sub_14002EE30();
__int64 sub_1400F3D04();
__int64 sub_1400F3C50();
__int64 sub_1400F1D90();
__int64 sub_1400F40B0();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14010FA90;
extern __int64 off_140110048;
extern __int64 off_140110058;
extern __int64 off_14001BB70;

__int64 __fastcall sub_1400F3CA0(__int64 *a1, int *a2, size_t a3) {
    __int64 rsp;
    __int64 arg_808;
    int arg_810;
    int v_10;
    int v_1048;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    int v_50;
    int str;
    __int64 v_848;
    char *str2;
    char *str3;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 result;
    __int64 *src2;
    struct Struct_1_t *ptr;
    __int64 v4;
    struct Struct_3_t *ptr3;
    __int64 v8;
    __int64 v6;
    struct Struct_2_t *ptr2;

    src = rsp + 112;
    str = -2;
    xmm0 = _mm_loadu_si128((__m128i *)a1);
    xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a1 + 32));
    _mm_store_si128((__m128i *)&v_30, xmm2);
    _mm_store_si128((__m128i *)&v_40, xmm1);
    _mm_store_si128((__m128i *)&v_50, xmm0);
    result = src - 80;
    v_20 = result;
    result = &off_14010FA90;
    v_18 = result;
    v_10 = 0;
    a1 = src - 32;
    sub_14002EE30(a1);
    v_10 = (int)a2;
    src = a2 + 112;
    sub_1400F3D04();
    sub_1400F3C50();
    sub_1400F1D90(0x1058);
    src2 = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    sub_1400F40B0();
    v4 = result;
    ptr3 = *a2;
    result = ptr3 + 16;
    v_20 = result;
    a3 = 0;
    v8 = rsp + 0x848;
    v6 = ptr->field_0;
    src2 = (__int64 *)v6;
    src2 = (__int64 *)((__int64)(__int64)src2 & -8);
    a1 = *(src2 + 0x810);
    src = a1;
    src = (__int64 *)((__int64)(__int64)src & -8);
    while (!((src == 0))) {
        ++a3;
        result = arg_808;
        result &= -2;
        a2 = (int *)v4;
        a2 -= result;
        while (a2 >= 4) {
            result = v6;
            /* cmpxchg %(__int64)a1, (%(__int64)ptr) */;
            if ((0 /* unresolved: flags == */)) {
                result = ptr->field_80;
                if (v6 != result) {
                    v_28 = a3;
                    if (ptr3 == 0) {
                        off_140108030(a1, a2, a3);
                        off_140108038(result, 0, src2);
                        src2 = *src;
                        if (src2 != 0) {
                            src += 8;
                            sub_1400F27F0(str3, src, 0x808);
                            v_848 = (__int64)src2;
                            src2 = (__int64 *)v_1048;
                            if (src2 >= 65) JUMPOUT(0x1400f4091);
                            src = (__int64 *)v8;
                            if (src2 == 0) {
                                a3 = v_28;
                                v8 = (__int64)src;
                                return v8;
                            }
                            src2 = (__int64 *)((__int64)(__int64)src2 << 5);
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
                                a1 = (__int64 *)str2;
                                ((__int64 (*)())(v_40))();
                                v8 += 32;
                            } while (src2 != v8);
                            return v8;
                        }
                        return v8;
                    }
                    result = ptr3->field_810;
                    v_38 = (__int64)ptr;
                    v_30 = v4;
                    if (result < 64) {
                        result <<= 5;
                        a1 = (__int64 *)v_20;
                        a2 = &off_14001BB70;
                        *(a1 + result) = a2;
                        *(a1 + result + 8) = v6;
                        ptr3->field_810 = ptr3->field_810 + 1;
                        src2 = *src;
                        if (src2 != 0) {
                            return (__int64)src2;
                        }
                        return (__int64)src2;
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
                        src2 = (__int64 *)v_20;
                        sub_1400F27F0(v8, src2, 0x808);
                        a2 = rsp + 64;
                        sub_1400F27F0(src2, a2, 0x800);
                        v4 = (__int64)ptr3;
                        ptr3->field_810 = 0;
                        *(__int64 *)rsp = *(__int64 *)rsp | 0;
                        ptr3 = ptr2->field_180;
                        sub_14002EDF0(0, 0x818);
                        if (result == 0) JUMPOUT(0x1400f4082);
                        src2 = (__int64 *)result;
                        ptr = (struct Struct_1_t *)v8;
                        sub_1400F27F0(result, v8, 0x808);
                        arg_808 = (__int64)ptr3;
                        arg_810 = 0;
                        ptr3 = (struct Struct_3_t *)v4;
                        do {
                            a1 = ptr2->field_100;
                            a2 = (int *)a1;
                            a2 = (int *)((__int64)(__int64)a2 & -8);
                            a3 = a2[258];
                            result = (__int64)a1;
                            /* cmpxchg %a3, 256(%(__int64)ptr2) */;
                        } while ((a2 != 0));
                        result = (__int64)a1;
                        /* cmpxchg %(__int64)src2, 256(%(__int64)ptr2) */;
                        result = ptr3->field_810;
                        v8 = (__int64)ptr;
                        v4 = v_30;
                        ptr = (struct Struct_1_t *)v_38;
                    } while (result >= 64);
                    return (__int64)ptr;
                }
                result = v6;
                /* cmpxchg %(__int64)a1, 128(%(__int64)ptr) */;
                return result;
            }
            v6 = ptr->field_0;
            src2 = (__int64 *)v6;
            src2 = (__int64 *)((__int64)(__int64)src2 & -8);
            a1 = *(src2 + 0x810);
            src = a1;
            src = (__int64 *)((__int64)(__int64)src & -8);
        }
    }
    return result;
}