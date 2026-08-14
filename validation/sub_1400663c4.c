// inferred from 3 accesses on `i`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 6 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_140067F50();
__int64 sub_1400F8440();
__int64 sub_1400679E0();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_140067D00();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_140066332();
__int64 sub_1400F37A0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140116BF1;
extern __int64 off_140116BF3;
extern __int64 off_140115AC0;
extern __int64 off_14011AF40;
extern __int64 off_1401162A8;

__int64 __fastcall sub_1400663C4(size_t *a1, int *a2, int a3, int a4) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    int arg_18;
    int arg_2;
    int arg_20;
    int arg_5;
    int arg_7;
    int arg_8;
    int v_100;
    int v_104;
    __int64 v_108;
    int v_110;
    int v_118;
    int v_120;
    int v_121;
    int v_128;
    __int64 v_130;
    int v_138;
    __int64 v_150;
    __int64 v_154;
    __int64 v_158;
    int v_160;
    int v_180;
    int v_190;
    int v_1f0;
    int v_21;
    int v_25;
    int v_27;
    __int64 v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    int v_59;
    int v_5d;
    int v_5f;
    int v_60;
    int v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_88;
    __int64 v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    __int64 v_c0;
    int v_c8;
    __int64 v_f0;
    int v_f8;
    __int64 *v_0;
    __int64 *v_10;
    char *str;
    __int64 *result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v5;
    __int64 v3;
    struct Struct_1_t *i;
    __int64 v8;
    __m128i xmm6;
    struct Struct_2_t *ptr;
    __int64 v7;
    __int64 v9;
    __int64 v2;

    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
    *result = *result + (__int64)result;
    *(__int64 *)i = (__int64)(i->field_0 + a2);
    result = &off_140116BF1;
    v_f0 = (__int64)result;
    v_f8 = 2;
    v_100 = 3;
    result = &off_140116BF3;
    v_108 = (__int64)result;
    v_110 = 13;
    result = (__int64 *)v_100;
    v_150 = (__int64)result;
    result = (__int64 *)v_104;
    v_154 = (__int64)result;
    result = (__int64 *)v_108;
    v_158 = (__int64)result;
    v_160 = 13;
    arg_10 = v2;
    arg_18 = v8;
    if (v3 != 2) {
        result = (__int64 *)arg_2;
        a1 = v3 - 3;
        a2 = v9 + 3;
        arg_10 = (__int64)a2;
        arg_18 = (int)a1;
        result = (__int64 *)((__int64)(__int64)result & 248);
        if (result != 48) {
            arg_10 = v2;
            arg_18 = v8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_68, xmm0);
            result = rsp + 88;
            v_58 = 0;
            v_5f = 0;
            v_5d = 0;
            v_59 = 0;
            v_60 = 8;
            a1 = (size_t *)v_78;
            v_40 = (__int64)a1;
            _mm_store_si128((__m128i *)&v_30, xmm0);
            a1 = (size_t *)v_58;
            str = (char *)a1;
            a1 = (size_t *)v_59;
            v_21 = (int)a1;
            a1 = (size_t *)v_5d;
            v_25 = (int)a1;
            a1 = (size_t *)v_5f;
            v_27 = (int)a1;
            a1 = (size_t *)v_60;
            v_28 = (__int64)a1;
        } else {
            result = rsp + 168;
            v_120 = 0;
            v_130 = (__int64)result;
            v_138 = 0;
            a1 = rsp + 32;
            a2 = rsp + 288;
            sub_140067F50(a1, a2, str);
            a2 = (int *)str;
            if (a2 != 3) {
                result = (__int64 *)v_48;
                v_78 = (__int64)result;
                xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                xmm1 = _mm_loadu_si128((__m128i *)&v_38);
                _mm_storeu_si128((__m128i *)&v_68, xmm1);
                _mm_storeu_si128((__m128i *)&v_58, xmm0);
                v_40 = (__int64)result;
                _mm_store_si128((__m128i *)&v_30, xmm1);
                _mm_store_si128((__m128i *)&str, xmm0);
                if (a2 == 1) {
                    result = rsp + 88;
                    a1 = (size_t *)v_40;
                    arg_20 = (int)a1;
                    a1 = (size_t *)str;
                    a2 = (int *)v_21;
                    a3 = v_25;
                    a4 = v_27;
                    v5 = v_28;
                    xmm0 = _mm_load_si128((__m128i *)&v_30);
                    _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                    *result = a1;
                    arg_1 = (int)a2;
                    arg_5 = a3;
                    arg_7 = a4;
                    arg_8 = v5;
                    result = (__int64 *)v_58;
                    a1 = (size_t *)v_60;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                    _mm_store_si128((__m128i *)&v_190, xmm0);
                } else {
                    result = (__int64 *)v_58;
                    a1 = (size_t *)v_60;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                    _mm_store_si128((__m128i *)&v_190, xmm0);
                    if (a2 != 0) {
                        a2 = (int *)v_78;
                        str = (char *)result;
                        v_28 = (__int64)a1;
                        v3 = rsp + 48;
                        xmm0 = _mm_load_si128((__m128i *)&v_190);
                        _mm_storeu_si128((__m128i *)&v_30, xmm0);
                        v_40 = (__int64)a2;
                        i = (struct Struct_1_t *)v_30;
                        if (i == result) {
                            a1 = rsp + 32;
                            sub_1400F8440(a1, a2, 2);
                            result = (__int64 *)str;
                            a1 = (size_t *)v_28;
                            a2 = (int *)v_40;
                        }
                        a3 = i + (__int64)(__int64)i*2;
                        a4 = v_160;
                        v_10[a3] = a4;
                        xmm0 = _mm_load_si128((__m128i *)&v_150);
                        _mm_storeu_si128((__m128i *)(a1 + a3*8), xmm0);
                        ++i;
                        v_30 = (__int64)i;
                        xmm0 = _mm_loadu_si128((__m128i *)v3);
                        _mm_store_si128((__m128i *)&v_50, xmm0);
                        a3 = 2;
                    } else {
                        a3 = 0;
                    }
                    xmm0 = _mm_load_si128((__m128i *)&v_50);
                    _mm_storeu_si128((__m128i *)&v_38, xmm0);
                    v_48 = (__int64)a2;
                    a2 = rsp + 40;
                    v_28 = (__int64)result;
                    v_30 = (__int64)a1;
                    v8 = (__int64)a2;
                    result = a2[4];
                    v_c0 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)a2);
                    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
                    _mm_store_si128((__m128i *)&v_b0, xmm1);
                    _mm_store_si128((__m128i *)&v_a0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)v8);
                    xmm1 = _mm_loadu_si128((__m128i *)(v8 + 16));
                    _mm_store_si128((__m128i *)&v_50, xmm0);
                    _mm_store_si128((__m128i *)&v_60, xmm1);
                    result = (__int64 *)arg_20;
                    v_70 = (__int64)result;
                    str = (char *)a3;
                    a2[4] = result;
                    _mm_storeu_si128((__m128i *)(a2 + 16), xmm1);
                    _mm_storeu_si128((__m128i *)a2, xmm0);
                    result = (__int64 *)str;
                    a1 = (size_t *)v_28;
                    a2 = (int *)v_30;
                    a3 = v_38;
                    a4 = v_40;
                    ptr->field_28 = a4;
                    a4 = v_48;
                    ptr->field_30 = a4;
                    ptr->field_18 = a2;
                    ptr->field_20 = a3;
                    ptr->field_8 = result;
                    ptr->field_10 = a1;
                    *(__int64 *)ptr = (__int64)(8);
                    xmm6 = _mm_load_si128((__m128i *)&v_1f0);
                    return _mm_cvtsi128_si64(xmm6);
                }
                return _mm_cvtsi128_si64(xmm6);
            } else {
                v_98 = v9;
                v_118 = v3;
                v_90 = (__int64)ptr;
                a1 = (size_t *)arg_10;
                a1 -= v2;
                v8 -= (__int64)a1;
                if (!((v8 < 0))) {
                    result = v2 + a1;
                    arg_10 = (__int64)result;
                    v_88 = (__int64)str;
                    arg_18 = v8;
                    v_50 = 0;
                    v_58 = 1;
                    v_60 = 0;
                    v_a0 = v2;
                    v_a8 = (int)a1;
                    v_b0 = 0;
                    v_180 = (int)a1;
                    v_b8 = (int)a1;
                    result = 0x5F0000005F;
                    v_c0 = (__int64)result;
                    v_c8 = 1;
                    ptr = 1;
                    v7 = 0;
                    v8 = rsp + 160;
                    v9 = 0;
                    sub_1400679E0(str, v8);
                    while (str == 1) {
                        i = (struct Struct_1_t *)v_28;
                        v3 = v_30;
                        i -= v9;
                        result = (__int64 *)v_50;
                        result -= v7;
                        if (i > result) {
                            a1 = rsp + 80;
                            sub_1400F5F90(a1, v7, i);
                            ptr = (struct Struct_2_t *)v_58;
                            v7 = v_60;
                        }
                        v9 += v2;
                        a1 = ptr + v7;
                        sub_1400F27F0(a1, v9, i);
                        v7 += (__int64)i;
                        v_60 = v7;
                        v9 = v3;
                    }
                    a3 = v_180;
                    a3 -= v9;
                    v3 = v_50;
                    result = (__int64 *)v3;
                    result -= v7;
                    if (a3 > result) {
                        a1 = rsp + 80;
                        v3 = a3;
                        sub_1400F5F90(a1, v7);
                        a3 = v3;
                        v7 = v_60;
                        v3 = v_50;
                        ptr = (struct Struct_2_t *)v_58;
                    }
                    i = (struct Struct_1_t *)v_88;
                    v2 += v9;
                    a1 = ptr + v7;
                    v2 = a3;
                    sub_1400F27F0(a1, v2, a3);
                    v7 += v2;
                    a1 = rsp + 288;
                    a2 = (int *)ptr;
                    a3 = v7;
                    sub_140067D00(a1, ptr, v7, 2);
                    if (v3 == 0) {
                        result = (__int64 *)v_118;
                        a1 = (size_t *)v_98;
                        if (v_120 == 1) {
                            v2 = v_121;
                            i->field_10 = a1;
                            i->field_18 = result;
                            sub_14002EDF0(0, 1);
                            ptr = (struct Struct_2_t *)v_90;
                            if (result == 0) {
                                sub_1400F3340(1, 1);
                            }
                            *result = v2;
                            str = 1;
                            a2 = rsp + 40;
                            v_28 = 0;
                            v_30 = 8;
                            v_38 = 0;
                            v_40 = (__int64)result;
                            result = &off_140115AC0;
                            v_48 = (__int64)result;
                            a3 = 2;
                            return a3;
                        }
                        result = (__int64 *)v_128;
                        ptr = (struct Struct_2_t *)v_90;
                        return sub_140066332();
                    }
                    off_140108030();
                    off_140108038(result, 0, ptr);
                    return (__int64)ptr;
                }
                do {
                    result = &off_14011AF40;
                    str = (char *)result;
                    v_28 = 1;
                    v_30 = 8;
                    xmm0 = _mm_setzero_si128();
                    _mm_storeu_si128((__m128i *)&v_38, xmm0);
                    a2 = &off_1401162A8;
                    a1 = rsp + 32;
                    sub_1400F37A0(a1, a2);
                    return (__int64)a1;
                } while (true);
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}