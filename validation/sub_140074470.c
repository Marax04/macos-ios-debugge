// inferred from 3 accesses on `i`
struct Struct_1_t {
    char _pad_start[88];
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    char _pad_60[28];
    __int64 field_84; // offset 132
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14007BF40();
__int64 sub_14007C0E0();
__int64 sub_1400F96F0();
__int64 sub_1400F4450();
__int64 sub_14007C250();
__int64 sub_140011760();
__int64 sub_1400F2D20();
__int64 sub_1400F9220();
__int64 sub_14007B080();
__int64 sub_1400F3360();
__int64 sub_14007B220();
__int64 sub_1400F87E0();
__int64 sub_1400F8980();
__int64 sub_14007AC6F();
__int64 sub_14007B540();
__int64 sub_140070F60();
__int64 sub_1400F9B90();
extern __int64 off_14011D5E0;
extern __int64 off_14011D5D0;
extern __int64 off_1400186D0;
extern __int64 off_1401175D8;
extern __int64 off_140118E40;
extern __int64 off_140117688;
extern __int64 off_1401223D8;
extern __int64 off_14011ED08;
extern __int64 off_1401190A3;
extern __int64 off_14012283C;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140074470(size_t *a1, size_t *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    int arg_10;
    int arg_12;
    int arg_18;
    int arg_1d;
    int arg_20;
    int arg_28;
    int arg_30;
    int arg_40;
    int arg_50;
    int arg_58;
    __int64 arg_8;
    int v_10;
    __int64 v_100;
    int v_108;
    __int64 v_110;
    __int64 v_120;
    __int64 v_128;
    int v_138;
    __int64 v_140;
    __int64 v_148;
    __int64 v_150;
    __int64 v_160;
    int v_168;
    __int64 v_170;
    int v_178;
    int v_180;
    __int64 v_188;
    int v_190;
    int v_198;
    int v_1a0;
    int v_1a8;
    int v_1ac;
    int v_1b8;
    int v_1c0;
    __int64 v_1c8;
    __int64 v_1d0;
    __int64 v_1d8;
    __int64 v_1e0;
    __int64 v_1e8;
    int v_1fc;
    __int64 v_20;
    int v_200;
    int v_210;
    int v_218;
    int v_220;
    __int64 v_238;
    int v_240;
    __int64 v_248;
    __int64 v_250;
    int v_258;
    int v_260;
    int v_268;
    int v_270;
    __int64 v_278;
    int v_280;
    int v_288;
    int v_290;
    int v_298;
    int v_2a0;
    int v_2a8;
    __int64 v_2b0;
    int v_2b8;
    int v_2c0;
    __int64 v_2d0;
    int v_2e0;
    int v_2f0;
    int v_30;
    int v_300;
    int v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    __int64 v_58;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    int v_88;
    int v_90;
    __int64 v_98;
    int v_a8;
    __int64 v_b8;
    __int64 v_c0;
    __int64 v_c8;
    __int64 v_d0;
    __int64 v_d8;
    __int64 v_e0;
    __int64 v_e8;
    __int64 v_f0;
    int v_f8;
    int *v_0;
    __int64 *v_8;
    __int64 *i2;
    __int64 *i3;
    __int64 *result;
    __int64 i4;
    __int64 *i5;
    struct Struct_2_t *ptr;
    __m128i xmm0;
    __m128i xmm1;
    struct Struct_1_t *i;
    __int64 i6;
    __int64 i7;
    __m128i xmm6;
    __m128i xmm7;
    __int64 *src;
    __m128i xmm8;
    __m128i xmm2;
    __int64 *src2;
    __m128i xmm3;

    _mm_store_si128((__m128i *)&v_300, xmm8);
    _mm_store_si128((__m128i *)&v_2f0, xmm7);
    _mm_store_si128((__m128i *)&v_2e0, xmm6);
    i2 = (__int64 *)a2;
    i3 = (__int64 *)a1;
    v_2a0 = (int)a4;
    v_c0 = (__int64)a3;
    result = (__int64 *)a3;
    result = (__int64 *)((__int64)(__int64)result >> 3);
    i4 = 4;
    if (result >= 5) i4 = result;
    i5 =  + i4*8;
    sub_14002EDF0(0, i5);
    if (result == 0) {
        sub_1400F3326(8, i5);
    } else {
        ptr = (struct Struct_2_t *)result;
        v_70 = i4;
        v_78 = (__int64)result;
        v_80 = 0;
        a1 = rsp + 352;
        sub_14007BF40(a1, 8, i4);
        xmm0 = _mm_loadu_si128((__m128i *)&v_160);
        xmm1 = _mm_loadu_si128((__m128i *)&v_170);
        _mm_store_si128((__m128i *)&v_e0, xmm1);
        _mm_store_si128((__m128i *)&v_d0, xmm0);
        v_58 = (__int64)i2;
        i4 = *(i2 + 88);
        a1 = rsp + 208;
        sub_14007C0E0(a1, i4);
        v_238 = (__int64)i3;
        v_50 = i4;
        if (result == 0) {
            *(__int64 *)ptr = (__int64)(i4);
            v_80 = 1;
            i5 = 1;
        } else {
            i5 = 0;
        }
        i2 = v_c0 * 152;
        a2 = (size_t *)v_58;
        result = (__int64)a2 + (__int64)i2;
        v_c8 = (__int64)result;
        i = 1;
        i6 = 0;
        i3 = 183;
        i7 = rsp + 208;
        do {
            result = *(a2 + i6 + 96);
            a1 = result - 4;
            result = (__int64 *)a1;
            if (result < 4) a1 = i3;
            i6 += 152;
            ++i;
        } while (i2 != i6);
        i3 = (__int64 *)v_70;
        ptr = (struct Struct_2_t *)v_78;
        a1 = (size_t *)v_d8;
        if (a1 != 0) {
            result =  + (__int64)(__int64)a1*8 + 23;
            result = (__int64 *)((__int64)(__int64)result & -16);
            a1 = (size_t *)((__int64)a1 + (__int64)result);
            if (a1 != -17) {
                i4 = v_d0;
                i4 -= (__int64)result;
                ((__int64 (*)())off_140108030)(a1, a2);
                ((__int64 (*)())off_140108038)(result, 0, i4);
            }
        }
        xmm6 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
        _mm_store_si128((__m128i *)&v_170, xmm6);
        xmm7 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
        _mm_store_si128((__m128i *)&v_160, xmm7);
        if (i5 != 0) {
            i2 =  + (__int64)(__int64)i5*8;
            a3 = rsp + 384;
            i4 = rsp + 352;
            sub_1400F96F0(i4, i5, a3);
            for (i5 = 0; i2 != i5; i5 += 8) {
                a2 = *(__int64 *)((__int64)ptr + (__int64)i5);
                sub_14007C0E0(i4, a2);
            }
        }
        if (i3 != 0) {
            ((__int64 (*)())off_140108030)();
            ((__int64 (*)())off_140108038)(result, 0, ptr);
        }
        i4 = v_178;
        i5 = 4;
        if (i4 >= 5) i5 = i4;
        if (i4 < result) {
            do {
                src = (__int64 *)v_160;
                a4 = (size_t *)v_168;
                result = i5;
                result = (__int64 *)((__int64)(__int64)result << 4);
                i3 = result + (__int64)(__int64)result*2;
                v_60 = (__int64)src;
                v_68 = (__int64)a4;
                sub_14002EDF0(0, i3, a3, a4);
                a4 = (size_t *)v_68;
                src = (__int64 *)v_60;
                if (result == 0) JUMPOUT(0x14007ad8e);
                v_d0 = (__int64)i5;
                v_d8 = (__int64)a2;
                v_e0 = 0;
                v_1e0 = 0;
                result = (__int64 *)v_50;
                v_1d0 = (__int64)result;
                v_1d8 = (__int64)result;
                v_1b8 = 0;
                v_1c0 = 8;
                v_1c8 = 0;
                i5 = 1;
                i7 = 0;
                ptr = 0xF1357AEA2E62A9C5;
                xmm8 = _mm_cmpeq_epi32(xmm8, xmm8);
                i3 = 0;
                i = (struct Struct_1_t *)v_58;
                do {
                    i6 = i->field_58;
                    i2 = (__int64 *)v_1c8;
                    if (i2 == v_1b8) {
                        a1 = rsp + 440;
                        ptr = (struct Struct_2_t *)i7;
                        i7 = (__int64)a2;
                        sub_1400F4450(a1, a2, a3, a4);
                        a4 = (size_t *)v_68;
                        src = (__int64 *)v_60;
                        i7 = (__int64)ptr;
                        ptr = 0xF1357AEA2E62A9C5;
                    }
                    result = (__int64 *)v_1c0;
                    v_0[(__int64)i2] = i3;
                    ++i2;
                    v_1c8 = (__int64)i2;
                    result = i->field_84;
                    i6 += (__int64)result;
                    v_1d8 = i6;
                    result = i->field_60;
                    a1 = result - 4;
                    result = (__int64 *)a1;
                    a1 = 183;
                    if (result < 4) result = a1;
                    if (result > 54) {
                        i += 152;
                        ++i3;
                        if (v_1c8 != 0) {
                            i = (struct Struct_1_t *)v_d0;
                            if (i7 != i) {
                                result =  + i7*2;
                                result += i7;
                                result = (__int64 *)((__int64)(__int64)result << 4);
                                xmm0 = _mm_loadu_si128((__m128i *)&v_1b8);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_1c8);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_1d8);
                                _mm_storeu_si128((__m128i *)((__int64)a2 + (__int64)result + 32), xmm2);
                                _mm_storeu_si128((__m128i *)((__int64)a2 + (__int64)result + 16), xmm1);
                                _mm_storeu_si128((__m128i *)((__int64)a2 + (__int64)result), xmm0);
                                ++i7;
                                v_e0 = i7;
                                result = (__int64 *)v_c0;
                                v_20 = (__int64)result;
                                a1 = rsp + 352;
                                v_50 = (int)a2;
                                a4 = (size_t *)v_58;
                                sub_14007C250(a1, a2, i7, a4);
                                i6 = v_160;
                                i2 = (__int64 *)v_168;
                                i4 = v_60;
                                a1 = (size_t *)v_68;
                                if (a1 == 0) {
                                    sub_14002EDF0(0, 4);
                                    if (result != 0) {
                                        *result = 0x5F627573;
                                        v_2a8 = 4;
                                        v_2b0 = (__int64)result;
                                        v_2b8 = 4;
                                        result = rsp + 672;
                                        v_d0 = (__int64)result;
                                        result = &off_1400186D0;
                                        v_d8 = (__int64)result;
                                        result = &off_1401175D8;
                                        v_160 = (__int64)result;
                                        v_168 = 1;
                                        v_180 = 0;
                                        result = rsp + 208;
                                        v_170 = (__int64)result;
                                        v_178 = 1;
                                        a2 = &off_140118E40;
                                        a1 = rsp + 680;
                                        a3 = rsp + 352;
                                        sub_140011760(a1, a2, a3);
                                        result = (__int64 *)v_2b8;
                                        v_170 = (__int64)result;
                                        xmm0 = _mm_loadu_si128((__m128i *)&v_2a8);
                                        _mm_store_si128((__m128i *)&v_160, xmm0);
                                        v_1a8 = 0;
                                        v_178 = 0;
                                        v_180 = 8;
                                        xmm0 = _mm_setzero_si128();
                                        _mm_storeu_si128((__m128i *)&v_188, xmm0);
                                        v_198 = 4;
                                        v_1a0 = 0;
                                        v_1ac = 8;
                                        if (i7 != 0) {
                                            i3 = (__int64 *)i7;
                                            a1 = rsp + 376;
                                            v_20 = 32;
                                            sub_1400F2D20(a1, 0, i7, 8);
                                            _mm_store_si128((__m128i *)&v_e0, xmm6);
                                            _mm_store_si128((__m128i *)&v_d0, xmm7);
                                            a3 = rsp + 240;
                                            i4 = rsp + 208;
                                            sub_1400F9220(i4, i7, a3);
                                            result = (__int64 *)v_50;
                                            i5 = result + 40;
                                            do {
                                                a2 = (size_t *)v_10;
                                                a3 = *i5;
                                                sub_14007B080(i4, a2, a3);
                                                i5 += 48;
                                                --i3;
                                            } while ((i3 != 0));
                                            result = (__int64 *)i7;
                                            result = (__int64 *)((__int64)(__int64)result << 4);
                                            result += (__int64)(__int64)result*2;
                                            xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                            xmm1 = _mm_load_si128((__m128i *)&v_e0);
                                            _mm_store_si128((__m128i *)&v_220, xmm1);
                                            _mm_store_si128((__m128i *)&v_210, xmm0);
                                            src2 = (__int64 *)v_50;
                                            i3 = *(src2 + 40);
                                            v_278 = (__int64)result;
                                            if (i7 == 1) {
                                                do {
                                                    src = (__int64 *)v_58;
                                                    a1 = src + 152;
                                                    result = 0;
                                                    a4 = 183;
                                                    xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
                                                    v_1e8 = 0;
                                                    v_60 = (__int64)i3;
                                                    do {
                                                        a2 = (size_t *)src;
                                                        src = (__int64 *)a1;
                                                        a1 = a2[12];
                                                        a3 = a1 - 4;
                                                        a1 = a3;
                                                        if (a1 < 4) a3 = a4;
                                                        a1 = src + 152;
                                                        if (src == v_c8) a1 = src;
                                                    } while (src != v_c8);
                                                    ptr = (struct Struct_2_t *)v_1e8;
                                                    i4 = (__int64)ptr;
                                                    i4 <<= 5;
                                                    a1 = (size_t *)ptr;
                                                    a1 = (size_t *)((__int64)(__int64)a1 >> 59);
                                                    a1 = (a1 == 0) ? 1 : 0;
                                                    a2 = 0x7FFFFFFFFFFFFFF9;
                                                    a2 = (i4 < a2) ? 1 : 0;
                                                    if (((__int64)a1 & (__int64)a2) == 0) {
                                                        sub_1400F3360(0x2AAAAAAAAAAAAAB);
                                                    }
                                                    i5 = result;
                                                    v_148 = (__int64)i2;
                                                    if (i4 != 0) {
                                                        sub_14002EDF0(0, i4, a3, a4);
                                                        a1 = (size_t *)ptr;
                                                        if (result == 0) {
                                                            sub_1400F3326(8, i4);
                                                            a3 = src2 + 88;
                                                            a2 = 0x7FFFFFFFFFFFFFC;
                                                            a1 = (size_t *)((__int64)(__int64)a1 & (__int64)a2);
                                                            a3 += 144;
                                                            a2 = 0;
                                                            do {
                                                                a4 = (size_t *)v_90;
                                                                a4 = (size_t *)v_60;
                                                                if (i3 > a4) {
                                                                    a4 = (size_t *)v_30;
                                                                    if (i3 > a4) {
                                                                        a4 = *a3;
                                                                        if (i3 > a4) {
                                                                            a2 += 4;
                                                                            a3 += 192;
                                                                            a1 = a2 + (__int64)(__int64)a2*2;
                                                                            a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                            a1 = (size_t *)((__int64)a1 + (__int64)src2);
                                                                            a1 += 88;
                                                                            result = (__int64 *)((__int64)(__int64)result << 4);
                                                                            result += (__int64)(__int64)result*2;
                                                                            a2 = 0;
                                                                            a3 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                                                            if (i3 <= a3) i3 = a3;
                                                                            a2 += 48;
                                                                        }
                                                                        i3 = (__int64 *)a4;
                                                                        return (__int64)i3;
                                                                    }
                                                                    i3 = (__int64 *)a4;
                                                                    a4 = *a3;
                                                                    if (i3 > a4) {
                                                                        return (__int64)a4;
                                                                    }
                                                                    return (__int64)a4;
                                                                }
                                                                i3 = (__int64 *)a4;
                                                                a4 = (size_t *)v_30;
                                                                if (i3 <= a4) {
                                                                    return (__int64)a4;
                                                                }
                                                                return (__int64)a4;
                                                            } while (a1 != a2);
                                                            return (__int64)a4;
                                                        }
                                                        v_240 = (int)a1;
                                                        i2 = result;
                                                        v_248 = (__int64)result;
                                                        v_250 = 0;
                                                        result = 0;
                                                        if (i5 == 0) ptr = i5;
                                                        result = (i5 != 0) ? 1 : 0;
                                                        v_d0 = (__int64)result;
                                                        v_d8 = 0;
                                                        v_e0 = (__int64)i5;
                                                        a1 = (size_t *)v_150;
                                                        v_e8 = (__int64)a1;
                                                        v_f0 = (__int64)result;
                                                        v_f8 = 0;
                                                        v_100 = (__int64)i5;
                                                        v_108 = (int)a1;
                                                        v_110 = (__int64)ptr;
                                                        result = i3;
                                                        v_c8 = (__int64)result;
                                                        i3 = 1;
                                                        ptr = 0;
                                                        i4 = rsp + 112;
                                                        v_140 = (__int64)i;
                                                        v_138 = i6;
                                                        i5 = i3 - 1;
                                                        a2 = rsp + 208;
                                                        sub_14007B220(i4, a2, a3, a4);
                                                        result = (__int64 *)v_70;
                                                        while (result != 0) {
                                                            i = (struct Struct_1_t *)i4;
                                                            a1 = (size_t *)v_c8;
                                                            i4 = (__int64)a1 + (__int64)i3;
                                                            a1 = (size_t *)v_80;
                                                            i6 = v_8[(__int64)a1];
                                                            a1 = rsp + 528;
                                                            sub_14007B080(a1, i6, i4);
                                                            v_270 = i4;
                                                            i4 = (__int64)i;
                                                            v_258 = 0;
                                                            v_260 = 8;
                                                            v_268 = 0;
                                                            v_200 = i6;
                                                            v_30 = 0;
                                                            v_38 = 1;
                                                            v_40 = 0;
                                                            result = rsp + 512;
                                                            v_120 = (__int64)result;
                                                            result = &off_1400186D0;
                                                            v_128 = (__int64)result;
                                                            result = &off_140117688;
                                                            v_70 = (__int64)result;
                                                            v_78 = 1;
                                                            v_90 = 0;
                                                            result = rsp + 288;
                                                            v_80 = (__int64)result;
                                                            v_88 = 1;
                                                            a1 = rsp + 48;
                                                            a2 = &off_140118E40;
                                                            sub_140011760(a1, a2, i);
                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                                                            _mm_store_si128((__m128i *)&v_70, xmm0);
                                                            result = (__int64 *)v_40;
                                                            v_80 = (__int64)result;
                                                            a1 = rsp + 600;
                                                            sub_1400F87E0(a1);
                                                            result = (__int64 *)v_260;
                                                            /* cmp v_258 , 1 */;
                                                            *result = 0;
                                                            arg_8 = 1;
                                                            arg_10 = 0;
                                                            xmm0 = _mm_load_si128((__m128i *)&v_70);
                                                            _mm_storeu_si128((__m128i *)(result + 24), xmm0);
                                                            a1 = (size_t *)v_80;
                                                            arg_28 = (int)a1;
                                                            v_268 = 1;
                                                            if ((0 /* unresolved: flags == */)) {
                                                                a1 = rsp + 600;
                                                                sub_1400F87E0(a1);
                                                                result = (__int64 *)v_260;
                                                            }
                                                            a1 = 0x8000000000000009;
                                                            arg_30 = (int)a1;
                                                            v_268 = 2;
                                                            result = i2;
                                                            if (i5 == v_240) {
                                                                a1 = rsp + 576;
                                                                sub_1400F8980(a1);
                                                                result = (__int64 *)v_248;
                                                            }
                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_258);
                                                            xmm1 = _mm_loadu_si128((__m128i *)&v_268);
                                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)ptr + 16), xmm1);
                                                            i2 = result;
                                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)ptr), xmm0);
                                                            v_250 = (__int64)i3;
                                                            ++i3;
                                                            ptr += 32;
                                                        }
                                                        i4 = rsp + 112;
                                                        i6 = rsp + 208;
                                                        do {
                                                            sub_14007B220(i4, i6);
                                                        } while (v_70 != 0);
                                                        result = (__int64 *)v_178;
                                                        a2 = (size_t *)v_188;
                                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                                        if (i5 > result) JUMPOUT(0x14007af61);
                                                        src2 = (__int64 *)v_50;
                                                        v_278 += (__int64)src2;
                                                        i3 = 0;
                                                        ptr = (struct Struct_2_t *)src2;
                                                        a2 = (size_t *)v_58;
                                                        do {
                                                            ++i3;
                                                            a1 = ptr->field_28;
                                                            v_30 = 0;
                                                            v_38 = 8;
                                                            v_40 = 0;
                                                            v_48 = (int)a1;
                                                            result = ptr->field_10;
                                                            if (result == 0) {
                                                                result = 8;
                                                                i4 = 0;
                                                                if (i3 >= i7) {
                                                                    if (i4 == v_30) {
                                                                        a1 = rsp + 48;
                                                                        sub_1400F87E0(a1, a2);
                                                                        a2 = (size_t *)v_58;
                                                                        src2 = (__int64 *)v_50;
                                                                        result = (__int64 *)v_38;
                                                                    }
                                                                    a1 = i4 + i4*2;
                                                                    a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                    *(__int64 *)((__int64)result + (__int64)a1) = a3;
                                                                    ++i4;
                                                                    v_40 = i4;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                                                                    result = (__int64 *)v_40;
                                                                    v_e0 = (__int64)result;
                                                                    result = (__int64 *)v_48;
                                                                    v_e8 = (__int64)result;
                                                                    _mm_store_si128((__m128i *)&v_d0, xmm0);
                                                                    i4 = v_188;
                                                                    if (i4 == v_178) {
                                                                        a1 = rsp + 376;
                                                                        sub_1400F8980(a1, a2, 0x8000000000000009);
                                                                        a2 = (size_t *)v_58;
                                                                        src2 = (__int64 *)v_50;
                                                                    }
                                                                    ptr += 48;
                                                                    result = (__int64 *)v_180;
                                                                    a1 = (size_t *)i4;
                                                                    a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                                                    xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                    xmm1 = _mm_load_si128((__m128i *)&v_e0);
                                                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1), xmm0);
                                                                    ++i4;
                                                                    v_188 = i4;
                                                                    result = (__int64 *)v_240;
                                                                    v_60 = (__int64)result;
                                                                    a1 = (size_t *)v_248;
                                                                    result = (__int64 *)v_250;
                                                                    a2 = (size_t *)result;
                                                                    a2 = (size_t *)((__int64)(__int64)a2 << 5);
                                                                    a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                    v_c8 = (__int64)a2;
                                                                    v_68 = (__int64)a1;
                                                                    v_c0 = (__int64)a1;
                                                                    if (result == 0) JUMPOUT(0x14007aba0);
                                                                    result = (__int64 *)v_68;
                                                                    result += 32;
                                                                    i4 = rsp + 376;
                                                                    do {
                                                                        v_c0 = (__int64)result;
                                                                        i3 = (__int64 *)v_20;
                                                                        result = i3;
                                                                        result = (__int64 *)(-(__int64)result);
                                                                        if ((0 /* overflow check on (-result) */)) JUMPOUT(0x14007aba0);
                                                                        result = (__int64 *)v_c0;
                                                                        i5 = result - 32;
                                                                        result = (__int64 *)arg_18;
                                                                        v_2d0 = (__int64)result;
                                                                        xmm0 = _mm_loadu_si128((__m128i *)(i5 + 8));
                                                                        _mm_store_si128((__m128i *)&v_2c0, xmm0);
                                                                        i2 = (__int64 *)v_188;
                                                                        if (i2 == v_178) JUMPOUT(0x14007ab96);
                                                                        result = (__int64 *)v_180;
                                                                        a1 = (size_t *)i2;
                                                                        a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                                                        *(__int64 *)((__int64)result + (__int64)a1) = i3;
                                                                        xmm0 = _mm_load_si128((__m128i *)&v_2c0);
                                                                        _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1 + 8), xmm0);
                                                                        a2 = (size_t *)v_2d0;
                                                                        *(__int64 *)((__int64)result + (__int64)a1 + 24) = a2;
                                                                        ++i2;
                                                                        v_188 = (__int64)i2;
                                                                        result = (__int64 *)v_c0;
                                                                        result += 32;
                                                                        i5 += 32;
                                                                    } while (i5 != v_c8);
                                                                    return sub_14007AC6F();
                                                                }
                                                                a1 = i3 + (__int64)(__int64)i3*2;
                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                i5 = *(__int64 *)((__int64)src2 + (__int64)a1 + 40);
                                                                if (i4 == v_30) {
                                                                    a1 = rsp + 48;
                                                                    sub_1400F87E0(a1, a2);
                                                                    a2 = (size_t *)v_58;
                                                                    src2 = (__int64 *)v_50;
                                                                    result = (__int64 *)v_38;
                                                                }
                                                                a1 = i4 + i4*2;
                                                                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                a3 = 0x800000000000000B;
                                                                *(__int64 *)((__int64)result + (__int64)a1) = a3;
                                                                *(__int64 *)((__int64)result + (__int64)a1 + 8) = i5;
                                                                return (__int64)a3;
                                                            }
                                                            v_1fc = (int)a1;
                                                            v_150 = (__int64)i3;
                                                            v_1e8 = (__int64)ptr;
                                                            i3 = ptr->field_8;
                                                            result = i3 + (__int64)(__int64)result*8;
                                                            v_c8 = (__int64)result;
                                                            result = i3 + 8;
                                                            do {
                                                                a1 = *i3;
                                                                if (a1 >= v_c0) JUMPOUT(0x14007afcf);
                                                                i3 = result;
                                                                result = (__int64)(__int64)a1 * 152;
                                                                i6 = (__int64)a2 + (__int64)result;
                                                                i2 = *(__int64 *)((__int64)a2 + (__int64)result + 96);
                                                                a4 = 16;
                                                                if (i2 == 186) {
                                                                    src = (__int64)a2 + (__int64)result;
                                                                    src += 96;
                                                                    result = i2 - 4;
                                                                    i5 = result;
                                                                    result = 183;
                                                                    if (i2 < 4) i5 = result;
                                                                    if (i5 > 182) JUMPOUT(0x14007ae14);
                                                                    result = i5;
                                                                    a2 = &off_1401223D8;
                                                                    a1 = v_0[(__int64)result];
                                                                    a1 = (size_t *)((__int64)a1 + (__int64)a2);
                                                                    JUMPOUT(a1);
                                                                    a1 = 0x3E007F;
                                                                    if ((a1 >= 0)) JUMPOUT(0x14007b020);
                                                                    i4 = arg_10;
                                                                    if (i4 != 4) {
                                                                        i2 = (__int64 *)arg_20;
                                                                        if (i2 != 4) {
                                                                            a1 = &off_14011ED08;
                                                                            a3 = *(__int64 *)((__int64)result + (__int64)a1);
                                                                            v_68 = (__int64)i3;
                                                                            if (i4 == 0) {
                                                                                result = (__int64 *)arg_12;
                                                                                result = (__int64 *)((__int64)(__int64)result & 7);
                                                                                a1 = &off_1401190A3;
                                                                                src = *(__int64 *)((__int64)result + (__int64)a1);
                                                                                result = i2;
                                                                                a1 = &off_14012283C;
                                                                                result = v_0[(__int64)result];
                                                                                result = (__int64 *)((__int64)result + (__int64)a1);
                                                                                JUMPOUT(result);
                                                                                i = (struct Struct_1_t *)arg_28;
                                                                                ptr = 1;
                                                                                i3 = 6;
                                                                                if (i4 != 0) {
                                                                                    i5 = (__int64 *)i6;
                                                                                    i6 = v_40;
                                                                                    if (i6 == v_30) {
                                                                                        a1 = rsp + 48;
                                                                                        v_60 = (__int64)a4;
                                                                                        v_a8 = (int)a3;
                                                                                        v_b8 = (__int64)src;
                                                                                        sub_1400F87E0(a1, 0x8000000000000002);
                                                                                        src = (__int64 *)v_b8;
                                                                                        a3 = (size_t *)v_a8;
                                                                                        a4 = (size_t *)v_60;
                                                                                        src2 = (__int64 *)v_50;
                                                                                    }
                                                                                    result = (__int64 *)v_38;
                                                                                    a1 =  + i6*2;
                                                                                    a1 += i6;
                                                                                    a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                    a2 = 0x8000000000000001;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1) = a2;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 8) = 0;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 9) = src;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 24) = ptr;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 25) = i2;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 32) = i;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 40) = i3;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 41) = a3;
                                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 42) = a4;
                                                                                    ++i6;
                                                                                    v_40 = i6;
                                                                                    a2 = (size_t *)v_58;
                                                                                    i3 = (__int64 *)v_68;
                                                                                    if (i4 != 1) {
                                                                                        result = 0;
                                                                                        result = (i3 != v_c8) ? 1 : 0;
                                                                                        result = i3 + (__int64)(__int64)result*8;
                                                                                        result = (__int64 *)v_38;
                                                                                        i4 = v_40;
                                                                                        a2 = (i4 == 0) ? 1 : 0;
                                                                                        a1 = i4 + i4*2;
                                                                                        a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                                                        a1 -= 48;
                                                                                        a3 = (a1 == 0) ? 1 : 0;
                                                                                        a3 = (size_t *)((__int64)(__int64)a3 | (__int64)a2);
                                                                                        if ((a3 == 0)) {
                                                                                            a2 = 0x7FFFFFFFFFFFFFF7;
                                                                                            a2 += *a1;
                                                                                            a2 = (size_t *)v_58;
                                                                                            i3 = (__int64 *)v_150;
                                                                                            ptr = (struct Struct_2_t *)v_1e8;
                                                                                            if ((a2 < 3)) {
                                                                                                return (__int64)ptr;
                                                                                            }
                                                                                            return (__int64)ptr;
                                                                                        }
                                                                                        a2 = (size_t *)v_58;
                                                                                        i3 = (__int64 *)v_150;
                                                                                        ptr = (struct Struct_2_t *)v_1e8;
                                                                                        return (__int64)ptr;
                                                                                    }
                                                                                    ptr = (struct Struct_2_t *)a4;
                                                                                    i5 += 20;
                                                                                    a1 = rsp + 48;
                                                                                    sub_14007B540(a1, i5, a3, i5);
                                                                                    i4 = v_40;
                                                                                    if (i4 == v_30) {
                                                                                        a1 = rsp + 48;
                                                                                        i5 = result;
                                                                                        sub_1400F87E0(a1);
                                                                                        result = i5;
                                                                                    }
                                                                                    a1 = (size_t *)v_38;
                                                                                    a2 = i4 + i4*2;
                                                                                    a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                    a3 = 0x8000000000000005;
                                                                                    *(__int64 *)((__int64)a1 + (__int64)a2) = a3;
                                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 8) = 0x600;
                                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 24) = result;
                                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 28) = 7;
                                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 29) = ptr;
                                                                                    ++i4;
                                                                                    v_40 = i4;
                                                                                    src2 = (__int64 *)v_50;
                                                                                    a2 = (size_t *)v_58;
                                                                                    return (__int64)a2;
                                                                                }
                                                                                result = (__int64 *)arg_12;
                                                                                result = (__int64 *)((__int64)(__int64)result & 7);
                                                                                a1 = &off_1401190A3;
                                                                                i3 = *(__int64 *)((__int64)result + (__int64)a1);
                                                                                return (__int64)i3;
                                                                            }
                                                                            if (i4 == 1) {
                                                                                ptr = (struct Struct_2_t *)a3;
                                                                                i = (struct Struct_1_t *)a4;
                                                                                a2 = i6 + 20;
                                                                                a1 = rsp + 48;
                                                                                sub_14007B540(a1, a2, a3, a4);
                                                                                a1 = (size_t *)arg_1d;
                                                                                a1 = (size_t *)((__int64)(__int64)a1 << 3);
                                                                                i5 = 0x80808040201;
                                                                                i5 = (__int64 *)((__int64)(__int64)i5 >> (__int64)a1);
                                                                                i3 = (__int64 *)v_40;
                                                                                if (i3 == v_30) {
                                                                                    a1 = rsp + 48;
                                                                                    v_b8 = i6;
                                                                                    i6 = (__int64)result;
                                                                                    sub_1400F87E0(a1, 0x8000000000000005);
                                                                                    result = (__int64 *)i6;
                                                                                    i6 = v_b8;
                                                                                }
                                                                                a1 = (size_t *)v_38;
                                                                                a2 = i3 + (__int64)(__int64)i3*2;
                                                                                a2 = (size_t *)((__int64)(__int64)a2 << 4);
                                                                                a3 = 0x8000000000000004;
                                                                                *(__int64 *)((__int64)a1 + (__int64)a2) = a3;
                                                                                *(__int64 *)((__int64)a1 + (__int64)a2 + 8) = result;
                                                                                *(__int64 *)((__int64)a1 + (__int64)a2 + 12) = i5;
                                                                                *(__int64 *)((__int64)a1 + (__int64)a2 + 13) = 0x706;
                                                                                ++i3;
                                                                                v_40 = (__int64)i3;
                                                                                src = 6;
                                                                                result = i2;
                                                                                a1 = &off_14012283C;
                                                                                result = v_0[(__int64)result];
                                                                                result = (__int64 *)((__int64)result + (__int64)a1);
                                                                                src2 = (__int64 *)v_50;
                                                                                a3 = (size_t *)ptr;
                                                                                JUMPOUT(result);
                                                                                return (__int64)a3;
                                                                            }
                                                                        }
                                                                    }
                                                                    result = *(src + 32);
                                                                    a1 = rsp + 128;
                                                                    a1[2] = result;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)src);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
                                                                    _mm_storeu_si128((__m128i *)(a1 + 4), xmm1);
                                                                    _mm_storeu_si128((__m128i *)(a1 - 12), xmm0);
                                                                    result = (__int64 *)arg_58;
                                                                    v_70 = 1;
                                                                    v_98 = (__int64)result;
                                                                    result = 1;
                                                                    a3 = rsp + 128;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)(a3 - 12));
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 4));
                                                                    a1 = a3[2];
                                                                    a2 = (size_t *)v_238;
                                                                    a2[5] = a1;
                                                                    a1 = a3[2];
                                                                    a2[5] = a1;
                                                                    a1 = a3[3];
                                                                    a2[6] = a1;
                                                                    _mm_storeu_si128((__m128i *)(a2 + 28), xmm1);
                                                                    _mm_storeu_si128((__m128i *)(a2 + 12), xmm0);
                                                                    arg_8 = (__int64)result;
                                                                    result = 0x8000000000000000;
                                                                    *a2 = result;
                                                                    i4 = v_38;
                                                                    i5 = (__int64 *)v_40;
                                                                    if (i5 != 0) {
                                                                        i3 = i4 + 32;
                                                                        ptr = off_140108030;
                                                                        i = off_140108038;
                                                                        do {
                                                                            i3 += 48;
                                                                            --i5;
                                                                        } while (!((i5 == 0)));
                                                                    }
                                                                    if (v_30 != 0) {
                                                                        ((__int64 (*)())off_140108030)();
                                                                        ((__int64 (*)())off_140108038)(result, 0, i4);
                                                                    }
                                                                    a1 = rsp + 576;
                                                                    sub_140070F60(a1);
                                                                    a1 = (size_t *)v_218;
                                                                    if (a1 != 0) {
                                                                        result = (__int64 *)a1;
                                                                        result = (__int64 *)((__int64)(__int64)result << 4);
                                                                        a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                                        if (a1 != -33) {
                                                                            i4 = v_210;
                                                                            i4 -= (__int64)result;
                                                                            i4 -= 16;
                                                                            ((__int64 (*)())off_140108030)(a1);
                                                                            ((__int64 (*)())off_140108038)(result, 0, i4);
                                                                        }
                                                                    }
                                                                    if (v_160 != 0) {
                                                                        i4 = v_168;
                                                                        ((__int64 (*)())off_140108030)();
                                                                        ((__int64 (*)())off_140108038)(result, 0, i4);
                                                                    }
                                                                    a1 = rsp + 376;
                                                                    sub_140070F60(a1);
                                                                    if (v_190 != 0) {
                                                                        i4 = v_198;
                                                                        ((__int64 (*)())off_140108030)();
                                                                        ((__int64 (*)())off_140108038)(result, 0, i4);
                                                                    }
                                                                    if (i7 == 0) {
                                                                        i2 = (__int64 *)v_148;
                                                                        i = (struct Struct_1_t *)v_140;
                                                                        i6 = v_138;
                                                                    } else {
                                                                        result = (__int64 *)v_50;
                                                                        i5 = result + 8;
                                                                        i3 = off_140108030;
                                                                        ptr = off_140108038;
                                                                        i2 = (__int64 *)v_148;
                                                                        i = (struct Struct_1_t *)v_140;
                                                                        i6 = v_138;
                                                                        do {
                                                                            i5 += 48;
                                                                            --i7;
                                                                        } while (!((i7 == 0)));
                                                                    }
                                                                    if (i != 0) {
                                                                        ((__int64 (*)())off_140108030)(a1);
                                                                        a3 = (size_t *)v_50;
                                                                        ((__int64 (*)())off_140108038)(result, 0, a3);
                                                                    }
                                                                    if (i6 != 0) {
                                                                        ((__int64 (*)())off_140108030)();
                                                                        ((__int64 (*)())off_140108038)(result, 0, i2);
                                                                    }
                                                                    xmm6 = _mm_load_si128((__m128i *)&v_2e0);
                                                                    xmm7 = _mm_load_si128((__m128i *)&v_2f0);
                                                                    xmm8 = _mm_load_si128((__m128i *)&v_300);
                                                                    return _mm_cvtsi128_si64(xmm8);
                                                                }
                                                                a3 = (size_t *)arg_50;
                                                                a4 = 8;
                                                                if (a3 == 0) {
                                                                    return (__int64)a4;
                                                                }
                                                                a1 = (size_t *)arg_10;
                                                                a2 = (a1 != 4) ? 1 : 0;
                                                                src = (a3 == 1) ? 1 : 0;
                                                                src = (__int64 *)((__int64)(__int64)src | (__int64)a2);
                                                                if ((src == 0)) {
                                                                    a1 = (size_t *)arg_20;
                                                                    a2 = (a1 != 4) ? 1 : 0;
                                                                    src = (a3 == 2) ? 1 : 0;
                                                                    src = (__int64 *)((__int64)(__int64)src | (__int64)a2);
                                                                    if ((src == 0)) {
                                                                        a1 = (size_t *)arg_30;
                                                                        a2 = (a1 != 4) ? 1 : 0;
                                                                        src = (a3 == 3) ? 1 : 0;
                                                                        src = (__int64 *)((__int64)(__int64)src | (__int64)a2);
                                                                        if ((src == 0)) {
                                                                            a1 = (size_t *)arg_40;
                                                                            a2 = (a1 != 4) ? 1 : 0;
                                                                            src = (a1 == 4) ? 1 : 0;
                                                                            a3 = (a3 != 4) ? 1 : 0;
                                                                            if (((__int64)a3 & (__int64)src) != 0) {
                                                                                a2 = (size_t *)v_58;
                                                                                return (__int64)a2;
                                                                            }
                                                                            a3 = i6 + 64;
                                                                            if (a2 == 0) {
                                                                                return (__int64)a3;
                                                                            }
                                                                            a2 = (size_t *)v_58;
                                                                            if (a1 == 0) {
                                                                                a1 = 1;
                                                                                a1 = *(__int64 *)((__int64)a3 + (__int64)a1);
                                                                                a1 = (size_t *)((__int64)(__int64)a1 << 3);
                                                                                a4 = 0x80808040201;
                                                                                a4 = (size_t *)((__int64)(__int64)a4 >> (__int64)a1);
                                                                                return (__int64)a4;
                                                                            }
                                                                            if (a1 != 1) {
                                                                                return (__int64)a4;
                                                                            }
                                                                            a1 = 13;
                                                                            return (__int64)a1;
                                                                        }
                                                                        a3 = i6 + 48;
                                                                        return (__int64)a3;
                                                                    }
                                                                    a3 = i6 + 32;
                                                                    return (__int64)a3;
                                                                }
                                                                a3 = i6 + 16;
                                                                return (__int64)a3;
                                                            } while (!((result == 0)));
                                                            return (__int64)a3;
                                                        } while (ptr != v_278);
                                                        return (__int64)a3;
                                                    }
                                                    result = 8;
                                                    a1 = 0;
                                                    return (__int64)a1;
                                                } while (result == 0);
                                            }
                                            result -= 48;
                                            result = (__int64 *)((__int64)(__int64)result >> 4);
                                            a1 = 0xAAAAAAAAAAAAAAAB;
                                            a1 = (size_t *)((__int64)(__int64)(__int64)a1 * (__int64)result);
                                            a2 = a1 - 1;
                                            result = (__int64 *)a1;
                                            result = (__int64 *)((__int64)(__int64)result & 3);
                                            if (a2 >= 3) {
                                                return (__int64)result;
                                            }
                                            a2 = 0;
                                            return (__int64)a2;
                                        }
                                        v_298 = 0;
                                        v_280 = 0;
                                        v_288 = 8;
                                        v_290 = 0;
                                        a1 = rsp + 640;
                                        sub_1400F87E0(a1);
                                        result = (__int64 *)v_288;
                                        a1 = 0x8000000000000009;
                                        *result = a1;
                                        v_290 = 1;
                                        a1 = rsp + 376;
                                        sub_1400F8980(a1);
                                        result = (__int64 *)v_180;
                                        xmm0 = _mm_loadu_si128((__m128i *)&v_280);
                                        xmm1 = _mm_loadu_si128((__m128i *)&v_290);
                                        _mm_storeu_si128((__m128i *)(result + 16), xmm1);
                                        _mm_storeu_si128((__m128i *)result, xmm0);
                                        v_188 = 1;
                                        xmm0 = _mm_load_si128((__m128i *)&v_160);
                                        xmm1 = _mm_load_si128((__m128i *)&v_170);
                                        xmm2 = _mm_load_si128((__m128i *)&v_190);
                                        xmm3 = _mm_load_si128((__m128i *)&v_1a0);
                                        a1 = (size_t *)v_238;
                                        _mm_storeu_si128((__m128i *)(a1 + 64), xmm3);
                                        _mm_storeu_si128((__m128i *)(a1 + 48), xmm2);
                                        _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
                                        _mm_storeu_si128((__m128i *)a1, xmm0);
                                        result = (__int64 *)v_180;
                                        a1[4] = result;
                                        result = (__int64 *)v_188;
                                        a1[5] = result;
                                        return (__int64)result;
                                    }
                                    sub_1400F3326(1, 4);
                                    return (__int64)result;
                                }
                                result =  + (__int64)(__int64)a1*8 + 23;
                                result = (__int64 *)((__int64)(__int64)result & -16);
                                a1 = (size_t *)((__int64)a1 + (__int64)result);
                                if (a1 == -17) {
                                    return (__int64)a1;
                                }
                                i4 -= (__int64)result;
                                ((__int64 (*)())off_140108030)(a1);
                                ((__int64 (*)())off_140108038)(result, 0, i4);
                                return i4;
                            }
                            a1 = rsp + 208;
                            sub_1400F9B90(a1);
                            i = (struct Struct_1_t *)v_d0;
                            a2 = (size_t *)v_d8;
                            return (__int64)a2;
                        }
                        result = (__int64 *)v_c0;
                        v_20 = (__int64)result;
                        a1 = rsp + 352;
                        v_50 = (int)a2;
                        a4 = (size_t *)v_58;
                        sub_14007C250(a1, a2, i7, a4);
                        i = (struct Struct_1_t *)v_d0;
                        i6 = v_160;
                        i2 = (__int64 *)v_168;
                        if (v_1b8 == 0) {
                            return (__int64)i2;
                        }
                        i4 = v_1c0;
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, i4);
                        return i4;
                    }
                    a1 = 0x47680000000000;
                    if ((!(((__int64)a1 >> (__int64)result) & 1))) {
                        return (__int64)a1;
                    }
                    xmm0 = _mm_loadu_si128((__m128i *)&v_1b8);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_1c8);
                    xmm2 = _mm_loadu_si128((__m128i *)&v_1d8);
                    _mm_store_si128((__m128i *)&v_180, xmm2);
                    _mm_store_si128((__m128i *)&v_170, xmm1);
                    _mm_store_si128((__m128i *)&v_160, xmm0);
                    v_1b8 = 0;
                    v_1c0 = 8;
                    v_1c8 = 0;
                    v_1d0 = i6;
                    v_1d8 = i6;
                    v_1e0 = (__int64)i5;
                    if (i7 != v_d0) {
                        result =  + i7*2;
                        result += i7;
                        result = (__int64 *)((__int64)(__int64)result << 4);
                        xmm0 = _mm_load_si128((__m128i *)&v_160);
                        xmm1 = _mm_load_si128((__m128i *)&v_170);
                        xmm2 = _mm_load_si128((__m128i *)&v_180);
                        _mm_storeu_si128((__m128i *)((__int64)a2 + (__int64)result + 32), xmm2);
                        _mm_storeu_si128((__m128i *)((__int64)a2 + (__int64)result + 16), xmm1);
                        _mm_storeu_si128((__m128i *)((__int64)a2 + (__int64)result), xmm0);
                        ++i7;
                        v_e0 = i7;
                        ++i5;
                        return (__int64)i5;
                    }
                    a1 = rsp + 208;
                    sub_1400F9B90(a1, result, a3, a4);
                    a4 = (size_t *)v_68;
                    src = (__int64 *)v_60;
                    a2 = (size_t *)v_d8;
                    return (__int64)a2;
                } while (i != v_c8);
                return (__int64)a2;
            } while (true);
        }
        return (__int64)a2;
    }
    return (__int64)result;
}