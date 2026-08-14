// inferred from 18 accesses on `result`
struct Struct_1_t {
    char field_0; // offset 0
    __int16 field_1; // offset 1
    char field_3; // offset 3
    int field_4; // offset 4
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int16 field_28; // offset 40
    int field_2A; // offset 42
    char _pad_2A[2];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[8];
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int16 field_58; // offset 88
    int field_5A; // offset 90
    char _pad_5A[2];
    __int64 field_60; // offset 96
    char _pad_60[168];
    __int64 field_110; // offset 272
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[48];
    __int64 field_60; // offset 96
};

__int64 sub_1400F27F0();
__int64 sub_1400FBF24();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14009D420();
__int64 sub_1400972B0();
__int64 sub_1400F87E0();
__int64 sub_1400F8980();
__int64 sub_1400F8910();
__int64 sub_1400986D0();
__int64 sub_140098290();
__int64 sub_1400BCBC0();
__int64 sub_1400B1470();
__int64 sub_1400FBFA5();
__int64 sub_1400FBF4F();
extern __int64 off_14011AEE8;
extern __int64 off_14011AF30;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400FC4EB() {
    __int64 rsp;
    __int64 arg_10;
    int arg_18;
    int arg_20;
    __int64 arg_28;
    __int64 arg_30;
    int arg_38;
    int arg_3c;
    int arg_40;
    __int64 arg_44;
    __int64 arg_45;
    int arg_8;
    __int64 arg_a;
    __int64 arg_c;
    __int64 v_100;
    int v_108;
    int v_110;
    int v_1100;
    int v_118;
    int v_120;
    int v_1210;
    __int64 v_1220;
    int v_128;
    int v_1a0;
    __int64 v_1b0;
    int v_1c0;
    __int64 v_1d0;
    int v_1e0;
    __int64 v_1f0;
    int v_20;
    int v_200;
    int v_210;
    int v_250;
    int v_260;
    int v_270;
    int v_28;
    int v_280;
    int v_290;
    int v_2a0;
    int v_2b0;
    int v_2c0;
    int v_2e8;
    int v_2f0;
    __int64 v_2f2;
    int v_2f8;
    int v_30;
    int v_300;
    int v_308;
    int v_310;
    int v_38;
    int v_3c4;
    int v_3d0;
    int v_3d8;
    int v_3da;
    int v_40;
    int v_48;
    __int64 v_50;
    int v_57;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_8d8;
    int v_8e0;
    int v_8e4;
    __int64 v_8ec;
    __int64 v_8f0;
    int v_90;
    int v_94;
    int v_98;
    __int64 v_a0;
    __int64 v_a8;
    int v_b0;
    __int64 v_b08;
    int v_b10;
    __int64 v_b20;
    int v_b28;
    int v_b29;
    int v_b39;
    int v_b49;
    __int64 v_b4a;
    __int64 v_b52;
    int v_b8;
    int v_c0;
    int v_c8;
    int i;
    int v_d8;
    int v_e0;
    __int64 v_e8;
    __int64 v_f0;
    __int64 v_f8;
    __int64 v13;
    __int64 v2;
    __int64 v15;
    struct Struct_1_t *result;
    __m128i xmm0;
    __int64 *dst;
    __int64 v4;
    __m128i xmm1;
    struct Struct_3_t *ptr2;
    __int64 v11;
    __int64 v12;
    __int64 *dst2;
    __int64 v6;
    __m128i xmm6;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v7;
    struct Struct_2_t *ptr;
    __int64 v9;
    __int64 v8;

    result->field_10 = v15;
    result->field_18 = v13;
    result->field_110 = v2;
    v13 = v_58;
    ++i;
    v2 = v_1100;
    if (v2 != 0) JUMPOUT(0x1400fc416);
    v15 = 0;
    result = (struct Struct_1_t *)i;
    v_1d0 = (__int64)result;
    xmm0 = _mm_loadu_si128((__m128i *)&v_c0);
    _mm_store_si128((__m128i *)&v_1c0, xmm0);
    dst = rsp + 0x1430;
    v4 = rsp + 0x1630;
    sub_1400F27F0(dst, v4, 512);
    xmm0 = _mm_load_si128((__m128i *)&v_200);
    _mm_store_si128((__m128i *)&v_1e0, xmm0);
    result = (struct Struct_1_t *)v_210;
    v_1f0 = (__int64)result;
    xmm0 = _mm_load_si128((__m128i *)&v_290);
    xmm1 = _mm_load_si128((__m128i *)&v_2a0);
    _mm_store_si128((__m128i *)&v_270, xmm0);
    _mm_store_si128((__m128i *)&v_280, xmm1);
    result = (struct Struct_1_t *)v_108;
    v_f8 = (__int64)result;
    result = (struct Struct_1_t *)v_110;
    v_100 = (__int64)result;
    dst = (__int64 *)v_d8;
    if (dst != 0) {
        result =  + (__int64)(__int64)dst*8 + 23;
        result = (struct Struct_1_t *)((__int64)(__int64)result & -16);
        dst = (__int64 *)((__int64)dst + (__int64)result);
        if (dst != -17) {
            ptr2 = (struct Struct_3_t *)((__int64)ptr2 - (__int64)result);
            ((__int64 (*)())off_140108030)(dst);
            ((__int64 (*)())off_140108038)(result, 0, ptr2);
        }
    }
    v11 = v6;
    v11 >>= 32;
    dst = (__int64 *)v_118;
    result = (struct Struct_1_t *)dst;
    result = (struct Struct_1_t *)(-(__int64)result);
    v2 = (0 /* overflow check on (-result) */) ? 1 : 0;
    if ((0 /* overflow check on (-result) */)) {
        v12 = v_90;
        return sub_1400FBF24();
    } else {
        ptr2 = (struct Struct_3_t *)dst2;
        ptr2 = (struct Struct_3_t *)((__int64)(__int64)ptr2 >> 32);
        result = (struct Struct_1_t *)v_1f0;
        v_1220 = (__int64)result;
        xmm0 = _mm_load_si128((__m128i *)&v_1e0);
        _mm_store_si128((__m128i *)&v_1210, xmm0);
        v13 = (__int64)dst;
        dst = rsp + 0x1228;
        v4 = rsp + 0x1430;
        sub_1400F27F0(dst, v4, 512);
        xmm0 = _mm_load_si128((__m128i *)&v_1c0);
        _mm_store_si128((__m128i *)&v_1a0, xmm0);
        result = (struct Struct_1_t *)v_1d0;
        v_1b0 = (__int64)result;
        xmm0 = _mm_load_si128((__m128i *)&v_270);
        xmm1 = _mm_load_si128((__m128i *)&v_280);
        _mm_store_si128((__m128i *)&v_250, xmm0);
        _mm_store_si128((__m128i *)&v_260, xmm1);
        result = (struct Struct_1_t *)v_f8;
        v_e8 = (__int64)result;
        result = (struct Struct_1_t *)v_100;
        v_f0 = (__int64)result;
        v_8ec = (__int64)ptr2;
        result = (struct Struct_1_t *)v_1210;
        v_8f0 = (__int64)result;
        dst = rsp + 0x8F8;
        v4 = rsp + 0x1218;
        sub_1400F27F0(dst, v4, 528);
        result = (struct Struct_1_t *)v_a8;
        v_b08 = (__int64)result;
        xmm0 = _mm_load_si128((__m128i *)&v_1a0);
        _mm_storeu_si128((__m128i *)&v_b10, xmm0);
        result = (struct Struct_1_t *)v_1b0;
        v_b20 = (__int64)result;
        v_b28 = v15;
        xmm0 = _mm_load_si128((__m128i *)&v_250);
        xmm1 = _mm_load_si128((__m128i *)&v_260);
        _mm_storeu_si128((__m128i *)&v_b29, xmm0);
        _mm_storeu_si128((__m128i *)&v_b39, xmm1);
        v_b49 = v15;
        result = (struct Struct_1_t *)v_e8;
        v_b4a = (__int64)result;
        result = (struct Struct_1_t *)v_f0;
        v_b52 = (__int64)result;
        v_8d8 = v13;
        v_8e0 = v6;
        v_8e4 = v11;
        v12 = (__int64)dst2;
        v11 = v12;
        v11 += 16;
        if ((v11 < 0)) JUMPOUT(0x1400fbf0b);
        sub_14002EDF0(0, v11);
        if (result == 0) {
            sub_1400F3326(1, v11);
        } else {
            dst2 = (__int64 *)result;
            result = 0x14250595A;
            *dst2 = result;
            result = (struct Struct_1_t *)v_a0;
            *(dst2 + 8) = result;
            v4 = v_8e0;
            dst = dst2;
            dst += 16;
            sub_1400F27F0(dst, v4, v12);
            dst = rsp + 976;
            v15 = v_e0;
            sub_14009D420(dst, v15);
            v13 = v_3d0;
            result = (struct Struct_1_t *)v13;
            result = (struct Struct_1_t *)(-(__int64)result);
            v6 = v_3d8;
            ptr2 = (struct Struct_3_t *)v_3da;
            if ((0 /* overflow check on (-result) */)) {
                v4 = rsp + 988;
                dst = rsp + 756;
                sub_1400F27F0(dst, v4, 220);
                v_2e8 = v13;
                v_2f0 = v6;
                v_2f2 = (__int64)ptr2;
                v6 = v_3c4;
                v_20 = v11;
                v_28 = 0x40000040;
                v4 = &off_14011AEE8;
                dst = rsp + 744;
                sub_1400972B0(dst, v4, 5, dst2);
                v13 = (__int64)result;
                v13 >>= 32;
                if (((__int64)result & 1) == 0) {
                    sub_14002EDF0(8, 5);
                    if (result != 0) {
                        v12 = (__int64)result;
                        v_28 = 0x60000020;
                        v_20 = 5;
                        v4 = &off_14011AF30;
                        dst = rsp + 744;
                        sub_1400972B0(dst, v4, 6, result);
                        v15 = (__int64)result;
                        v15 >>= 32;
                        if (((__int64)result & 1) == 0) {
                            ptr2 = 0;
                            sub_14002EDF0(0, 5);
                            if (result == 0) {
                                sub_1400F3326(1, 5);
                                _mm_store_si128((__m128i *)&v_100, xmm6);
                                ptr2 = (struct Struct_3_t *)dst;
                                sub_14002EDF0(0, 12);
                                if (result == 0) JUMPOUT(0x1400fdbec);
                                dst = 0x2D61726F6870797A;
                                *(__int64 *)result = (__int64)(dst);
                                result->field_8 = 0x6F6D6564;
                                v_98 = 12;
                                v_a0 = (__int64)result;
                                v_a8 = 12;
                                v_b0 = 0;
                                v_b8 = 8;
                                xmm6 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&v_c0, xmm6);
                                i = 8;
                                _mm_storeu_si128((__m128i *)&v_d8, xmm6);
                                v_e8 = 8;
                                v_f0 = 0;
                                v_f8 = 1;
                                sub_14002EDF0(0, 7);
                                if (result == 0) JUMPOUT(0x1400fdbfb);
                                result->field_3 = 0x65747570;
                                *(__int64 *)result = (__int64)(0x706D6F63);
                                v_48 = 7;
                                v_50 = (__int64)result;
                                v_58 = 7;
                                v_90 = 0;
                                v_60 = 0;
                                v_68 = 8;
                                _mm_storeu_si128((__m128i *)&v_70, xmm6);
                                v_80 = 4;
                                v_88 = 0;
                                v_94 = 0xF08;
                                v_40 = 0;
                                v_28 = 0;
                                v_30 = 8;
                                v_38 = 0;
                                dst = rsp + 40;
                                sub_1400F87E0(dst);
                                dst = (__int64 *)v_28;
                                result = (struct Struct_1_t *)v_30;
                                v6 = 0x8000000000000001;
                                *(__int64 *)result = (__int64)(v6);
                                result->field_8 = 1;
                                result->field_10 = 3;
                                result->field_18 = 1;
                                result->field_20 = 7;
                                result->field_28 = 512;
                                result->field_2A = 8;
                                v_38 = 1;
                                if (dst == 1) {
                                    dst = rsp + 40;
                                    sub_1400F87E0(dst);
                                    dst = (__int64 *)v_28;
                                    result = (struct Struct_1_t *)v_30;
                                }
                                result->field_30 = v6;
                                result->field_38 = 0;
                                result->field_48 = 1;
                                result->field_50 = 256;
                                result->field_58 = 0;
                                result->field_5A = 8;
                                v_38 = 2;
                                if (dst == 2) {
                                    dst = rsp + 40;
                                    sub_1400F87E0(dst);
                                    result = (struct Struct_1_t *)v_30;
                                }
                                dst = 0x8000000000000009;
                                result->field_60 = dst;
                                v_38 = 3;
                                dst = rsp + 96;
                                sub_1400F8980(dst);
                                result = (struct Struct_1_t *)v_68;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_38);
                                _mm_storeu_si128((__m128i *)(result + 16), xmm1);
                                _mm_storeu_si128((__m128i *)result, xmm0);
                                v_70 = 1;
                                dst = rsp + 176;
                                sub_1400F8910(dst);
                                result = (struct Struct_1_t *)v_b8;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_88);
                                _mm_storeu_si128((__m128i *)(result + 64), xmm0);
                                xmm0 = _mm_loadu_si128((__m128i *)&v_48);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_58);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_68);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_78);
                                _mm_storeu_si128((__m128i *)(result + 48), xmm3);
                                _mm_storeu_si128((__m128i *)(result + 32), xmm2);
                                _mm_storeu_si128((__m128i *)(result + 16), xmm1);
                                _mm_storeu_si128((__m128i *)result, xmm0);
                                v_c0 = 1;
                                result = (struct Struct_1_t *)v_f8;
                                ptr2->field_60 = result;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_e8);
                                _mm_storeu_si128((__m128i *)(ptr2 + 80), xmm0);
                                xmm0 = _mm_loadu_si128((__m128i *)&v_98);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_a8);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c8);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d8);
                                _mm_storeu_si128((__m128i *)(ptr2 + 64), xmm3);
                                _mm_storeu_si128((__m128i *)(ptr2 + 48), xmm2);
                                _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                                _mm_storeu_si128((__m128i *)ptr2, xmm0);
                                result = (struct Struct_1_t *)v_b8;
                                ptr2->field_20 = result;
                                result = (struct Struct_1_t *)v_c0;
                                ptr2->field_28 = result;
                                xmm6 = _mm_load_si128((__m128i *)&v_100);
                                return _mm_cvtsi128_si64(xmm6);
                            } else {
                                v7 = v6;
                                v7 -= v15;
                                dst = 0xFFFFFFFF7FFFFFFB;
                                dst += v7;
                                v7 += 0xFFFFFFFB;
                                v4 = 0xFFFFFFFF00000000;
                                if (dst < v4) v7 = ptr2;
                                *(__int64 *)result = (__int64)(233);
                                result->field_1 = v7;
                                ptr = (struct Struct_2_t *)v_308;
                                v4 = v_310;
                                ptr -= 28;
                                dst = v4 + v4*8;
                                dst += (__int64)(__int64)dst*2;
                                dst += v4;
                                while (dst != 0) {
                                    v7 = ptr->field_24;
                                    v9 = ptr->field_28;
                                    v4 = ptr->field_2C;
                                    if (v4 > v7) v7 = v4;
                                    v7 += v9;
                                    if (!((v7 < 0))) {
                                        ptr += 28;
                                        dst -= 28;
                                        v8 = v15;
                                        v8 -= v9;
                                        if (v8 < v4) {
                                            dst = ptr->field_14;
                                            v4 = v8;
                                            v9 = dst + v4;
                                            v7 = v_2f8;
                                            v8 = (v9 >= v7) ? 1 : 0;
                                            dst += v4;
                                            dst += 5;
                                            dst = (dst > v7) ? 1 : 0;
                                            dst = (__int64 *)((__int64)(__int64)dst | v8);
                                            if (dst != 1) {
                                                dst = (__int64 *)v_2f0;
                                                v4 = result->field_4;
                                                *(dst + v9 + 4) = v4;
                                                v4 = result->field_0;
                                                *(dst + v9) = v4;
                                                v2 = rsp + 744;
                                                v_a8 = (__int64)result;
                                                sub_1400986D0(v2, v15, v7);
                                                dst = rsp + 688;
                                                sub_140098290(dst, v2);
                                                result = (struct Struct_1_t *)v_2c0;
                                                dst = (__int64 *)v_88;
                                                arg_10 = (__int64)result;
                                                xmm0 = _mm_loadu_si128((__m128i *)&v_2b0);
                                                _mm_storeu_si128((__m128i *)dst, xmm0);
                                                arg_18 = v11;
                                                v4 = v_128;
                                                arg_20 = v4;
                                                arg_28 = (__int64)result;
                                                result = (struct Struct_1_t *)v_a0;
                                                arg_30 = (__int64)result;
                                                arg_38 = v13;
                                                arg_3c = v6;
                                                arg_40 = v15;
                                                result = (struct Struct_1_t *)v_120;
                                                arg_44 = (__int64)result;
                                                result = (struct Struct_1_t *)v_57;
                                                arg_45 = (__int64)result;
                                                v6 = off_140108030;
                                                ((__int64 (*)())v6)(dst, v4);
                                                ptr2 = off_140108038;
                                                v7 = v_a8;
                                                ((__int64 (*)())ptr2)(result, 0, v7);
                                                ((__int64 (*)())v6)();
                                                ((__int64 (*)())ptr2)(result, 0, v12);
                                                ((__int64 (*)())v6)();
                                                ((__int64 (*)())ptr2)(result, 0, dst2);
                                                dst = rsp + 0x8D8;
                                                sub_1400BCBC0(dst);
                                                ((__int64 (*)())v6)();
                                                v7 = v_58;
                                                ((__int64 (*)())ptr2)(result, 0, v7);
                                                ((__int64 (*)())v6)();
                                                v7 = v_90;
                                                ((__int64 (*)())ptr2)(result, 0, v7);
                                                dst = rsp + 0x768;
                                                sub_1400B1470(dst);
                                                return sub_1400FBFA5();
                                            }
                                        }
                                    }
                                }
                                dst = (__int64 *)v_88;
                                arg_8 = 2;
                                arg_c = 0;
                                *dst = v4;
                                ptr2 = (struct Struct_3_t *)result;
                                ((__int64 (*)())off_140108030)(dst, 0x8000000000000000, v7, v8);
                                ((__int64 (*)())off_140108038)(result, 0, result);
                            }
                        } else {
                            result = (struct Struct_1_t *)((__int64)(__int64)result >> 16);
                            dst = (__int64 *)v_88;
                            arg_8 = 2;
                            arg_a = (__int64)result;
                            arg_c = v15;
                            result = 0x8000000000000000;
                            *dst = result;
                        }
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, v12);
                        v12 = v_90;
                        v13 = v_58;
                        v15 = v_e0;
                        if (v_2e8 != 0) {
                            v13 = v_2f0;
                            ((__int64 (*)())off_140108030)();
                            v13 = v_58;
                            ((__int64 (*)())off_140108038)(result, 0, v13);
                        }
                        if (v_300 != 0) {
                            v13 = v_308;
                            ((__int64 (*)())off_140108030)();
                            v13 = v_58;
                            ((__int64 (*)())off_140108038)(result, 0, v13);
                        }
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, dst2);
                        dst = rsp + 0x8D8;
                        sub_1400BCBC0(dst);
                        return sub_1400FBF4F();
                    }
                    return (__int64)dst;
                } else {
                    result = (struct Struct_1_t *)((__int64)(__int64)result >> 16);
                    dst = (__int64 *)v_88;
                    arg_8 = 2;
                    arg_a = (__int64)result;
                    arg_c = v13;
                    result = 0x8000000000000000;
                    *dst = result;
                    v12 = v_90;
                    v13 = v_58;
                }
                return v13;
            } else {
                dst = (__int64 *)v_88;
                arg_8 = 2;
                arg_a = v6;
                arg_c = (__int64)ptr2;
                result = 0x8000000000000000;
                *dst = result;
                v12 = v_90;
                v13 = v_58;
            }
            return v13;
        }
        return (__int64)result;
    }
}