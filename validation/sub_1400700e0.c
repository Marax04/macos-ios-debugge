// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F37A0();
__int64 sub_1400F37D0();
__int64 sub_1400F8A60();
__int64 sub_14002EDF0();
__int64 sub_14007C9D0();
__int64 sub_140074470();
__int64 sub_1400FA140();
__int64 sub_1400F3326();
__int64 sub_1400F3360();
__int64 sub_140071090();
__int64 sub_140070D2F();
__int64 sub_1400207F0();
__int64 sub_1400F8B80();
__int64 sub_140073270();
extern __int64 off_140117488;
extern __int64 off_140117508;
extern __int64 off_14011AF40;
extern __int64 off_140119008;
extern __int64 off_140117520;
extern __int64 off_140117540;
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14012D270;

__int64 __fastcall sub_1400700E0(int *a1, size_t *a2) {
    __int64 rsp;
    int arg_10;
    int arg_110;
    int arg_18;
    int arg_20;
    int arg_208;
    int arg_28;
    __int64 arg_8;
    int v_10;
    int v_100;
    __int64 v_108;
    int v_110;
    int v_124;
    __int64 v_138;
    int v_140;
    __int64 v_148;
    int v_15;
    __int64 v_150;
    int v_158;
    int v_160;
    int v_168;
    int v_170;
    int v_178;
    int v_180;
    int v_188;
    int v_190;
    int v_1a0;
    int v_1b0;
    int v_1c0;
    int v_1d0;
    __int64 v_1df;
    int v_1f0;
    __int64 v_1ff;
    int v_20;
    int v_210;
    __int64 v_220;
    int v_230;
    int v_248;
    __int64 v_250;
    __int64 v_27;
    int v_28;
    int v_2c0;
    int v_2c8;
    int v_2d0;
    int v_2d8;
    __int64 v_30;
    int v_34;
    __int64 v_38;
    int v_40;
    __int64 v_4c;
    int v_50;
    __int64 v_58;
    __int64 v_60;
    __int64 v_68;
    __int64 v_74;
    __int64 v_78;
    int v_8;
    __int64 v_80;
    int v_88;
    int v_90;
    int v_9c;
    __int64 v_a0;
    int v_a2;
    int v_a3;
    int v_a5;
    int v_a8;
    int v_ac;
    __int64 v_b0;
    int v_b8;
    int v_bc;
    int v_be;
    int v_bf;
    int v_c0;
    int v_c8;
    int v_d0;
    __int64 v_d8;
    int v_e0;
    __int64 v_e8;
    __int64 v_f0;
    int v_f8;
    __int64 *v_0;
    struct Struct_2_t *ptr2;
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 *dst2;
    __int64 i;
    __int64 i2;
    __int64 *dst3;
    __int64 v9;
    __int64 *dst;
    __int64 v6;
    __int64 v8;
    __m128i xmm0;
    __int64 v7;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    v_90 = (int)a1;
    ptr2 = (struct Struct_2_t *)v_2d8;
    v4 = v_2d0;
    ptr = (struct Struct_1_t *)v_2c8;
    result = (__int64 *)v_2c0;
    v_158 = (int)a2;
    v_250 = (__int64)result;
    a2 = (size_t *)((__int64)(__int64)a2 >> 1);
    if (a2 >= result) {
        if (dst == 0) {
            if (v6 == 0) {
                dst2 = ptr2->field_8;
                i = ptr2->field_10;
                if (v4 == 0) {
                    i2 = 0;
                } else {
                    dst3 = ptr2->field_0;
                    result = v4 + v4*2;
                    v9 = ptr + (__int64)(__int64)result*4;
                    i2 = 0;
                    v_58 = (__int64)dst2;
                    v_50 = i;
                    v_68 = (__int64)dst3;
                    v_40 = v9;
                    do {
                        v_28 = i2;
                        i2 = ptr->field_0;
                        v4 = ptr->field_4;
                        ptr += 12;
                        result = *dst3;
                        a1 = (int *)arg_20;
                        dst = (__int64 *)arg_28;
                        a1 -= 28;
                        a2 = dst + (__int64)(__int64)dst*8;
                        a2 += (__int64)(__int64)a2*2;
                        a2 = (size_t *)((__int64)a2 + (__int64)dst);
                        ptr2 = 3;
                        while (a2 != 0) {
                            v6 = a1[4];
                            v8 = a1[5];
                            dst = a1[5];
                            if (dst > v6) v6 = dst;
                            v6 += v8;
                            if ((v6 < 0)) {
                                dst = (__int64 *)v_38;
                                a2 = (size_t *)i2;
                                v4 = 0x8000000000000000;
                                i2 = v_28;
                                if (i2 != i) {
                                    result = i2 * 88;
                                    *(__int64 *)((__int64)dst2 + (__int64)result) = v4;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 8) = ptr2;
                                    v_34 = (int)a2;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 12) = a2;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 16) = dst;
                                    a1 = (int *)v_4c;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 24) = a1;
                                    a1 = (int *)v_30;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 28) = a1;
                                    a1 = (int *)((__int64)(__int64)a1 >> 16);
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 30) = a1;
                                    a1 = (int *)v_27;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 31) = a1;
                                    a1 = (int *)v_148;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 32) = a1;
                                    xmm0 = _mm_load_si128((__m128i *)&v_230);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 40), xmm0);
                                    a1 = (int *)v_74;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 56) = a1;
                                    xmm0 = _mm_load_si128((__m128i *)&v_210);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 60), xmm0);
                                    a1 = (int *)v_220;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 76) = a1;
                                    a1 = (int *)v_9c;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 80) = a1;
                                    ++i2;
                                    v_38 = (__int64)dst;
                                    result = (__int64 *)v_90;
                                    *result = dst2;
                                    arg_8 = i;
                                    arg_10 = i2;
                                    return arg_10;
                                }
                                result = &off_140117488;
                                v_a0 = (__int64)result;
                                v_a8 = 1;
                                v_b0 = 8;
                                xmm0 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&v_b8, xmm0);
                                a2 = &off_140117508;
                                a1 = rsp + 160;
                                sub_1400F37A0(a1, a2);
                                result = &off_14011AF40;
                                v_a0 = (__int64)result;
                                v_a8 = 1;
                                v_b0 = 8;
                                xmm0 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&v_b8, xmm0);
                                a2 = &off_140119008;
                                a1 = rsp + 160;
                                sub_1400F37A0(a1, a2);
                                a1 = &off_140117520;
                                dst = &off_140117540;
                                sub_1400F37D0(a1, 30, dst);
                                a2 += 128;
                                a1 = rsp + 352;
                                dst = rsp + 160;
                                sub_1400F8A60(a1, a2, dst);
                                a1 = (int *)v_160;
                                result = (__int64 *)v_168;
                                a2 = (size_t *)v_170;
                                ptr2 = (struct Struct_2_t *)v_178;
                                v4 = v_188;
                                dst = (__int64)(__int64)a2 * 88;
                                dst = (__int64 *)((__int64)dst + (__int64)a1);
                                if (dst == ptr2) {
                                    result += v_180;
                                    v4 += (__int64)a2;
                                    a2 = (size_t *)v_90;
                                    *a2 = a1;
                                    arg_8 = (__int64)result;
                                    a2[2] = v4;
                                } else {
                                    dst = (__int64 *)v_90;
                                    *dst = a1;
                                    arg_8 = (__int64)result;
                                    arg_10 = (int)a2;
                                    if (v4 != 0) {
                                        ptr2 += 56;
                                        i2 = off_140108030;
                                        ptr = off_140108038;
                                        do {
                                            result = *(__int64 *)(ptr2 - 56);
                                            result = (__int64 *)(-(__int64)result);
                                            ptr2 += 88;
                                            --v4;
                                        } while (!((v4 == 0)));
                                    }
                                }
                                return v4;
                            }
                            a1 += 28;
                            a2 -= 28;
                            v7 = i2;
                            v7 -= v8;
                            if (v7 >= dst) {
                                return v7;
                            }
                            a1 = a1[2];
                            v9 = v7;
                            v9 += (__int64)a1;
                            if (v9 >= arg_10) {
                                dst = (__int64 *)v_38;
                                a2 = (size_t *)i2;
                                v4 = 0x8000000000000000;
                                v9 = v_40;
                                return v9;
                            }
                            v4 -= i2;
                            result = 0;
                            if (v4 < 0) v4 = result;
                            v4 += v9;
                            result = (__int64 *)arg_8;
                            v_138 = (__int64)result;
                            result = (__int64 *)arg_10;
                            if (v4 <= result) {
                                v_60 = (__int64)ptr;
                                dst2 = (__int64 *)v4;
                                dst2 -= v9;
                                result = dst2;
                                a1 = 0xAAAAAAAAAAAAAAAB;
                                result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                ptr = (struct Struct_1_t *)a2;
                                ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 1);
                                result = 8;
                                if (ptr < 9) ptr = result;
                                result = 0x10000;
                                if (ptr >= 0x10000) ptr = result;
                                i = (__int64)(__int64)ptr * 152;
                                sub_14002EDF0(0, i, dst, v6);
                                if (result != 0) {
                                    dst3 = result;
                                    v_78 = (__int64)ptr;
                                    v_80 = (__int64)result;
                                    v_88 = 0;
                                    if (v4 != v9) {
                                        v_138 += v9;
                                        v9 = 133;
                                        i = 0;
                                        v4 = 0;
                                        v_150 = (__int64)dst2;
                                        dst = dst2;
                                        dst -= v4;
                                        result = (__int64 *)v_138;
                                        a2 = result + v4;
                                        a1 = rsp + 160;
                                        v_140 = v6;
                                        sub_14007C9D0(a1, a2, dst, i2);
                                        while (v_a2 != 2) {
                                            xmm0 = _mm_loadu_si128((__m128i *)&v_f0);
                                            _mm_store_si128((__m128i *)&v_1b0, xmm0);
                                            xmm0 = _mm_loadu_si128((__m128i *)&v_e0);
                                            _mm_store_si128((__m128i *)&v_1a0, xmm0);
                                            xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                            xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                            xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                            xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                            _mm_store_si128((__m128i *)&v_190, xmm3);
                                            _mm_store_si128((__m128i *)&v_180, xmm2);
                                            _mm_store_si128((__m128i *)&v_170, xmm1);
                                            _mm_store_si128((__m128i *)&v_160, xmm0);
                                            ptr = (struct Struct_1_t *)v_100;
                                            a1 = rsp + 257;
                                            result = a1[3];
                                            v_1df = (__int64)result;
                                            xmm0 = _mm_loadu_si128((__m128i *)a1);
                                            xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                            _mm_store_si128((__m128i *)&v_1d0, xmm1);
                                            _mm_store_si128((__m128i *)&v_1c0, xmm0);
                                            dst2 = (__int64 *)v_124;
                                            xmm0 = _mm_loadu_si128((__m128i *)(a1 + 36));
                                            _mm_store_si128((__m128i *)&v_1f0, xmm0);
                                            result = a1[6];
                                            v_1ff = (__int64)result;
                                            if (dst2 == 0) {
                                                dst3 = (__int64 *)v_78;
                                                v9 = v_80;
                                                v4 = v_38;
                                                if (i == 0) {
                                                    ptr = (struct Struct_1_t *)v_60;
                                                    dst2 = (__int64 *)v_58;
                                                    i = v_50;
                                                    dst3 = (__int64 *)v_68;
                                                    if ((dst3 == 0)) {
                                                        dst = (__int64 *)v4;
                                                        return (__int64)dst;
                                                    }
                                                    ((__int64 (*)())off_140108030)(a1, a2, dst);
                                                    ((__int64 (*)())off_140108038)(result, 0, v9);
                                                    return (__int64)dst;
                                                }
                                                a1 = rsp + 160;
                                                sub_140074470(a1, v9, i, i2);
                                                v4 = v_a0;
                                                result = (__int64 *)v4;
                                                result = (__int64 *)(-(__int64)result);
                                                if ((0 /* overflow check on (-result) */)) {
                                                    a2 = (size_t *)v_ac;
                                                    dst = (__int64 *)v_b0;
                                                    result = (__int64 *)v_b8;
                                                    v_4c = (__int64)result;
                                                    result = (__int64 *)v_be;
                                                    result = (__int64 *)((__int64)(__int64)result << 16);
                                                    a1 = (int *)v_bc;
                                                    a1 = (int *)((__int64)(__int64)a1 | (__int64)result);
                                                    v_30 = (__int64)a1;
                                                    result = (__int64 *)v_bf;
                                                    v_27 = (__int64)result;
                                                    result = (__int64 *)v_c0;
                                                    v_148 = (__int64)result;
                                                    result = rsp + 200;
                                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                                    _mm_store_si128((__m128i *)&v_230, xmm0);
                                                    result = (__int64 *)v_d8;
                                                    v_74 = (__int64)result;
                                                    a1 = rsp + 257;
                                                    result = (__int64 *)v_15;
                                                    v_220 = (__int64)result;
                                                    xmm0 = _mm_loadu_si128((__m128i *)(a1 - 37));
                                                    _mm_store_si128((__m128i *)&v_210, xmm0);
                                                    v_9c = i2;
                                                    ptr = (struct Struct_1_t *)v_60;
                                                    dst2 = (__int64 *)v_58;
                                                    i = v_50;
                                                    ptr2 = (struct Struct_2_t *)v_a8;
                                                    i2 = v_28;
                                                    if (dst3 == 0) {
                                                        dst3 = (__int64 *)v_68;
                                                        v9 = v_40;
                                                        return v9;
                                                    }
                                                    v_34 = (int)a2;
                                                    dst3 = dst;
                                                    ((__int64 (*)())off_140108030)(a1, a2, dst);
                                                    ((__int64 (*)())off_140108038)(result, 0, v9);
                                                    a2 = (size_t *)v_34;
                                                    return (__int64)a2;
                                                }
                                                a2 = (size_t *)v_ac;
                                                dst = (__int64 *)v_b0;
                                                result = (__int64 *)v_b8;
                                                v_4c = (__int64)result;
                                                result = (__int64 *)v_be;
                                                result = (__int64 *)((__int64)(__int64)result << 16);
                                                a1 = (int *)v_bc;
                                                a1 = (int *)((__int64)(__int64)a1 | (__int64)result);
                                                v_30 = (__int64)a1;
                                                result = (__int64 *)v_bf;
                                                v_27 = (__int64)result;
                                                result = (__int64 *)v_c0;
                                                v_148 = (__int64)result;
                                                result = rsp + 200;
                                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                                _mm_store_si128((__m128i *)&v_230, xmm0);
                                                v_74 = i2;
                                                v4 = 0x8000000000000000;
                                                return v4;
                                            }
                                            if (i == v_78) {
                                                a1 = rsp + 120;
                                                sub_1400FA140(a1, a2, dst, v6);
                                                dst3 = (__int64 *)v_80;
                                            }
                                            v4 += (__int64)dst2;
                                            v6 = v_140;
                                            v6 += (__int64)dst2;
                                            xmm0 = _mm_load_si128((__m128i *)&v_1b0);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 53), xmm0);
                                            xmm0 = _mm_load_si128((__m128i *)&v_1a0);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 69), xmm0);
                                            xmm0 = _mm_load_si128((__m128i *)&v_160);
                                            xmm1 = _mm_load_si128((__m128i *)&v_170);
                                            xmm2 = _mm_load_si128((__m128i *)&v_180);
                                            xmm3 = _mm_load_si128((__m128i *)&v_190);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 85), xmm3);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 101), xmm2);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 117), xmm1);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 133), xmm0);
                                            *(dst3 + v9 - 37) = ptr;
                                            xmm0 = _mm_load_si128((__m128i *)&v_1c0);
                                            xmm1 = _mm_load_si128((__m128i *)&v_1d0);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 36), xmm0);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9 - 20), xmm1);
                                            result = (__int64 *)v_1df;
                                            *(dst3 + v9 - 5) = result;
                                            *(dst3 + v9 - 1) = dst2;
                                            xmm0 = _mm_load_si128((__m128i *)&v_1f0);
                                            _mm_storeu_si128((__m128i *)&*(dst3 + v9), xmm0);
                                            result = (__int64 *)v_1ff;
                                            *(dst3 + v9 + 15) = result;
                                            ++i;
                                            v_88 = i;
                                            v9 += 152;
                                            dst2 = (__int64 *)v_150;
                                            return (__int64)dst2;
                                        }
                                        result = (__int64 *)v_a3;
                                        a1 = (result < 2) ? 1 : 0;
                                        result = (__int64 *)((__int64)(__int64)result & 6);
                                        result = (result == 2) ? 1 : 0;
                                        result = (__int64 *)((__int64)(__int64)result | (__int64)a1);
                                        a2 = (size_t *)v_34;
                                        if ((result == 0)) {
                                            dst2 = (__int64 *)v_a5;
                                            result = (__int64 *)v_a3;
                                            v_30 = (__int64)result;
                                            if (v_78 == 0) {
                                                dst2 = (__int64 *)((__int64)(__int64)dst2 << 16);
                                                v_30 += (__int64)dst2;
                                                ptr2 = 4;
                                                v_4c = i2;
                                                v4 = 0x8000000000000000;
                                                ptr = (struct Struct_1_t *)v_60;
                                                dst2 = (__int64 *)v_58;
                                                i = v_50;
                                                dst3 = (__int64 *)v_68;
                                                v9 = v_40;
                                                i2 = v_28;
                                                dst = (__int64 *)v_140;
                                                return (__int64)dst;
                                            }
                                            v9 = v_80;
                                            ((__int64 (*)())off_140108030)(a1, a2, dst3);
                                            ((__int64 (*)())off_140108038)(result, 0, v9);
                                            a2 = (size_t *)v_34;
                                            return (__int64)a2;
                                        }
                                        return (__int64)a2;
                                    }
                                    if (v_78 == 0) {
                                        dst = (__int64 *)v_38;
                                        a2 = (size_t *)i2;
                                        v4 = 0x8000000000000000;
                                        ptr = (struct Struct_1_t *)v_60;
                                        dst2 = (__int64 *)v_58;
                                        i = v_50;
                                        dst3 = (__int64 *)v_68;
                                        return (__int64)dst3;
                                    }
                                    v9 = v_80;
                                    ptr = (struct Struct_1_t *)v_60;
                                    dst2 = (__int64 *)v_58;
                                    i = v_50;
                                    dst3 = (__int64 *)v_68;
                                    v4 = v_38;
                                    return v4;
                                }
                                sub_1400F3326(8, i);
                                result = (__int64 *)i;
                                result = (__int64 *)((__int64)(__int64)result >> 1);
                                dst = (__int64 *)i;
                                dst = (__int64 *)((__int64)dst - (__int64)result);
                                result = 0x1631D;
                                if (i < 0x1631D) result = i;
                                if (result <= dst) result = dst;
                                dst2 = 48;
                                if (result >= 49) dst2 = result;
                                if (dst >= result) {
                                    sub_1400F3360(0x1745D1745D1745E, a1, a2, dst);
                                }
                                ptr2 = (__int64)(__int64)dst2 * 88;
                                if (ptr2 != 0) {
                                    v4 = (__int64)a1;
                                    i2 = (__int64)a2;
                                    sub_14002EDF0(0, ptr2);
                                    a1 = (int *)v4;
                                    a2 = (size_t *)i2;
                                    v4 = (__int64)result;
                                    if (result == 0) {
                                        sub_1400F3326(8, ptr2);
                                        v4 = 8;
                                        dst2 = 0;
                                    }
                                    v_20 = (a2 < 65) ? 1 : 0;
                                    sub_140071090(a1, a2, v4, dst2);
                                    ((__int64 (*)())off_140108030)();
                                    a1 = (int *)result;
                                    a2 = 0;
                                    dst = (__int64 *)v4;
                                    JUMPOUT(off_140108038);
                                    ptr2 = (struct Struct_2_t *)a1;
                                    v8 = (__int64)(__int64)a2 * 88;
                                    v8 += (__int64)a1;
                                    result = a1 + 88;
                                    a2 = 0;
                                    dst = 2;
                                    v4 = 0;
                                    v_8 = (int)a1;
                                    v_10 = v8;
                                    return sub_140070D2F();
                                }
                                return v_10;
                            }
                            v4 = (__int64)result;
                            if (v9 >= result) {
                                return v4;
                            }
                            return v4;
                        }
                        return v4;
                    } while (ptr != v9);
                    return v4;
                }
                return v4;
            } else {
                v6 >>= 1;
                v_248 = v6;
                v_1c0 = (int)a2;
                v4 -= (__int64)a2;
                if ((v4 < 0)) {
                    return v4;
                } else {
                    result = ptr2->field_10;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if ((result < 0)) {
                        return (__int64)result;
                    } else {
                        a1 = ptr2->field_0;
                        dst = ptr2->field_8;
                        v6 = a2 + (__int64)(__int64)a2*2;
                        v6 = ptr + v6*4;
                        v7 = (__int64)(__int64)a2 * 88;
                        v7 += (__int64)dst;
                        v8 = rsp + 344;
                        v_a0 = v8;
                        v8 = rsp + 448;
                        v_a8 = v8;
                        dst2 = rsp + 584;
                        v_b0 = (__int64)dst2;
                        v_b8 = v6;
                        v_c0 = v4;
                        v_c8 = (int)a1;
                        v_d0 = v7;
                        v_d8 = (__int64)result;
                        v_e0 = v8;
                        v_e8 = (__int64)dst2;
                        v_f0 = (__int64)ptr;
                        v_f8 = (int)a2;
                        v_100 = (int)a1;
                        v_108 = (__int64)dst;
                        v_110 = (int)a2;
                        result = off_14012D270;
                        a1 = __readgsqword(88);
                        result = v_0[(__int64)result];
                        dst = (__int64 *)arg_18;
                        if (dst == 0) {
                            dst2 = result + 24;
                            sub_1400207F0(a1, dst2, dst, v6);
                            a2 = *result;
                            dst = *dst2;
                            if (dst == 0) {
                                return (__int64)dst;
                            } else {
                                if (arg_110 != a2) {
                                    a2 += 128;
                                    a1 = rsp + 352;
                                    v6 = rsp + 160;
                                    sub_1400F8B80(a1, a2, dst, v6);
                                } else {
                                    a1 = rsp + 352;
                                    a2 = rsp + 160;
                                    sub_140073270(a1, a2, dst, 0);
                                }
                            }
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                }
                return (__int64)a2;
            }
            return (__int64)a2;
        } else {
            result = off_14012D270;
            a1 = __readgsqword(88);
            result = v_0[(__int64)result];
            result = (__int64 *)arg_18;
            if (result == 0) {
                dst2 = (__int64 *)a2;
                i2 = v6;
                sub_1400207F0(a1, a2, dst, v6);
                v6 = i2;
            } else {
                result += 272;
            }
            result = *result;
            result = (__int64 *)arg_208;
            v6 >>= 1;
            if (v6 <= result) v6 = result;
        }
        return v6;
    }
    return (__int64)result;
}