// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[144];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 sub_140056CD0();
__int64 sub_140057260();
__int64 sub_1400575F0();
__int64 sub_1400F35E0();
__int64 sub_1400F37D0();
__int64 sub_1400F3869();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400548B0();
__int64 off_140108360();
extern __int64 off_14012D270;
extern __int64 off_14011D5E0;
extern __int64 off_14011D5D0;
extern __int64 off_140116A48;
extern __int64 off_140116A30;
extern __int64 off_14011B42B;
extern __int64 off_140116A18;
extern __int64 off_1401168C8;
extern __int64 off_140116980;
extern __int64 off_140116558;
extern __int64 off_140108660;
extern __int64 off_140108670;

__int64 __fastcall sub_140056810(size_t *a1, size_t *a2, int *a3, size_t *a4) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_28;
    int arg_30;
    int arg_38;
    __int64 arg_40;
    int arg_48;
    __int64 arg_50;
    __int64 arg_58;
    int arg_60;
    __int64 arg_68;
    __int64 arg_70;
    int arg_78;
    __int64 arg_8;
    int arg_80;
    __int64 arg_88;
    int v_100;
    int v_108;
    int v_180;
    int v_188;
    int v_20;
    int v_220;
    int v_27;
    __int64 v_28;
    int v_2a0;
    int v_30;
    int v_38;
    int v_40;
    __int64 v_48;
    __int64 v_50;
    __int64 v_58;
    int v_60;
    __int64 v_68;
    __int64 v_70;
    int v_78;
    int v_80;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    __int64 v_b8;
    int v_c0;
    __int64 v_d0;
    int v_e8;
    __int64 v_e9;
    int v_f0;
    __int64 v_f8;
    __int64 *v_0;
    __int64 v11;
    __int64 *result;
    __int64 v2;
    __int64 v10;
    __int64 *dst;
    struct Struct_1_t *ptr;
    __m128i xmm6;
    __int64 i;
    __int64 v8;
    __int64 *dst2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v6;
    __int64 v5;
    __m128i xmm7;
    __m128i xmm8;

    _mm_store_si128((__m128i *)&v_220, xmm6);
    v11 = (__int64)a2;
    v_20 = (int)a1;
    if (a4 != 0) {
        v_30 = (int)a4;
        result = (__int64 *)a4;
        result = (__int64 *)((__int64)(__int64)result << 4);
        result += (__int64)(__int64)result*8;
        v_28 = (__int64)result;
        v2 = rsp + 96;
        v10 = rsp + 272;
        result = off_14012D270;
        a1 = __readgsqword(88);
        result = v_0[(__int64)result];
        dst = result + 72;
        ptr = -144;
        xmm6 = _mm_setzero_si128();
        i = 1;
        v_38 = (int)a3;
        v8 = (__int64)a3;
        do {
            v11 += 40;
            dst2 = rsp + 400;
            sub_140056CD0(dst2, v8);
            a1 = rsp + 64;
            sub_140057260(a1, v11, dst2);
            a2 = (size_t *)v_40;
            result = (__int64 *)v_48;
            a1 = a2;
            a1 = (size_t *)(-(__int64)a1);
            a1 = (size_t *)v_50;
            a3 = (int *)v_58;
            xmm0 = _mm_loadu_si128((__m128i *)(v2 + 112));
            _mm_storeu_si128((__m128i *)(v10 + 112), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(v2 + 96));
            _mm_storeu_si128((__m128i *)(v10 + 96), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(v2 + 80));
            _mm_storeu_si128((__m128i *)(v10 + 80), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(v2 + 64));
            _mm_storeu_si128((__m128i *)(v10 + 64), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)v2);
            xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
            xmm2 = _mm_loadu_si128((__m128i *)(v2 + 32));
            xmm3 = _mm_loadu_si128((__m128i *)(v2 + 48));
            _mm_storeu_si128((__m128i *)(v10 + 48), xmm3);
            _mm_storeu_si128((__m128i *)(v10 + 32), xmm2);
            _mm_storeu_si128((__m128i *)(v10 + 16), xmm1);
            _mm_storeu_si128((__m128i *)v10, xmm0);
            v_f0 = (int)a2;
            v_f8 = (__int64)result;
            v_100 = (int)a1;
            v_108 = (int)a3;
            if (arg_10 != 1) {
                _mm_store_si128((__m128i *)&v_40, xmm6);
                a1 = rsp + 64;
                off_140108360(a1, 16);
                result = (__int64 *)v_48;
                xmm0 = _mm_load_si128((__m128i *)&v_40);
                arg_8 = (__int64)result;
                arg_10 = 1;
                result = _mm_cvtsi128_si64(xmm0);
                ++result;
                *dst = result;
                v_48 = 0;
                v_58 = 0;
                v_70 = 0;
                v_78 = 8;
                v_80 = 0;
                xmm1 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
                _mm_storeu_si128((__m128i *)(v2 + 56), xmm1);
                xmm1 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
                _mm_storeu_si128((__m128i *)(v2 + 40), xmm1);
                _mm_storeu_si128((__m128i *)&v_a8, xmm0);
                result = 0x8000000000000003;
                v_b8 = (__int64)result;
                v_d0 = (__int64)result;
                v_e8 = 1;
                result = (__int64 *)v_2a0;
                v_e9 = (__int64)result;
                v_40 = 10;
                a1 = (size_t *)v_180;
                a2 = (size_t *)v_188;
                a3 = rsp + 240;
                a4 = rsp + 64;
                sub_1400575F0(a1, a2, a3, a4);
                if (*result == 10) {
                    v11 = (__int64)result;
                    v11 += 8;
                    v8 += 144;
                    ++i;
                    result = (__int64 *)v_28;
                    result = (__int64 *)((__int64)result + (__int64)ptr);
                    result -= 144;
                    ptr -= 144;
                    a1 = (size_t *)v_20;
                    arg_8 = v11;
                    result = 0x8000000000000003;
                    *a1 = result;
                    xmm6 = _mm_load_si128((__m128i *)&v_220);
                    return _mm_cvtsi128_si64(xmm6);
                }
                a1 = &off_140116A48;
                sub_1400F35E0(a1);
                a1 = &off_140116A30;
                sub_1400F35E0(a1);
                a1 = &off_14011B42B;
                a3 = &off_140116A18;
                sub_1400F37D0(a1, 40, a3);
                a1 = &off_1401168C8;
                a3 = &off_140116980;
                sub_1400F37D0(a1, 32, a3);
                a3 = &off_140116558;
                sub_1400F3869(a1, a2, a3);
                sub_1400F3326(8, dst);
                i = arg_10;
                if (i >= 0) {
                    do {
                        dst = (__int64 *)a2;
                        dst2 = (__int64 *)a1;
                        v10 = arg_8;
                        v8 = 1;
                        sub_1400F27F0(v8, v10, i);
                        result = (__int64 *)arg_18;
                        v11 = 0x8000000000000003;
                        a4 = (size_t *)v11;
                        if (result == v11) {
                            result = (__int64 *)arg_30;
                            v6 = v11;
                            if (result == v11) {
                                result = (__int64 *)arg_48;
                                v10 = v11;
                                if (result != v11) {
                                    v10 = 0x8000000000000000;
                                    a1 = (size_t *)result;
                                    a1 = (size_t *)((__int64)(__int64)a1 ^ v10);
                                    /* test result , result */;
                                    result = 1;
                                    if (0 /* unresolved: flags < 0 */) result = a1;
                                    if (result == 0) {
                                        result = (__int64 *)arg_60;
                                        v2 = v11;
                                        if (result == v11) {
                                            result = (__int64 *)arg_78;
                                            if (result != v11) {
                                                v11 = 0x8000000000000000;
                                                a1 = (size_t *)result;
                                                a1 = (size_t *)((__int64)(__int64)a1 ^ v11);
                                                /* test result , result */;
                                                result = 1;
                                                if (0 /* unresolved: flags < 0 */) result = a1;
                                                if (result != 0) {
                                                    if (result != 2) {
                                                        ptr = (struct Struct_1_t *)arg_88;
                                                        if (ptr < 0) {
                                                            sub_1400F3360();
                                                        }
                                                        v_38 = v6;
                                                        v_40 = v5;
                                                        v_28 = (__int64)a4;
                                                        v_30 = (int)a3;
                                                        v_60 = (int)a2;
                                                        dst = (__int64 *)arg_80;
                                                        if ((dst == 0)) {
                                                            v11 = 1;
                                                        } else {
                                                            sub_14002EDF0(0, ptr);
                                                            if (result == 0) {
                                                                sub_1400F3326(1, ptr);
                                                                _mm_store_si128((__m128i *)&v_d0, xmm8);
                                                                _mm_store_si128((__m128i *)&v_c0, xmm7);
                                                                _mm_store_si128((__m128i *)&v_b0, xmm6);
                                                                v2 = (__int64)a3;
                                                                dst2 = (__int64 *)a2;
                                                                ptr = (struct Struct_1_t *)a1;
                                                                a2 = (size_t *)arg_8;
                                                                a3 = a3[2];
                                                                xmm0 = _mm_loadu_si128((__m128i *)(dst2 + 56));
                                                                xmm1 = _mm_shuffle_epi32(xmm0, 68);
                                                                xmm1 = _mm_xor_si128(xmm1, _mm_load_si128((__m128i *)&off_140108660));
                                                                _mm_store_si128((__m128i *)&v_60, xmm1);
                                                                xmm1 = _mm_shuffle_epi32(xmm0, 238);
                                                                xmm1 = _mm_xor_si128(xmm1, _mm_load_si128((__m128i *)&off_140108670));
                                                                _mm_store_si128((__m128i *)&v_70, xmm1);
                                                                _mm_store_si128((__m128i *)&v_80, xmm0);
                                                                xmm0 = _mm_setzero_si128();
                                                                _mm_store_si128((__m128i *)&v_90, xmm0);
                                                                v_a0 = 0;
                                                                dst = rsp + 96;
                                                                sub_1400548B0(dst, a2, a3);
                                                                v_27 = 255;
                                                                a2 = rsp + 39;
                                                                sub_1400548B0(dst, a2, 1);
                                                                result = (__int64 *)v_70;
                                                                a4 = (size_t *)v_90;
                                                                a4 = (size_t *)((__int64)(__int64)a4 << 56);
                                                                a4 = (size_t *)((__int64)(__int64)a4 | v_98);
                                                                a1 = (size_t *)v_78;
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
                                                                a3 = (int *)v_60;
                                                                a3 = (int *)((__int64)a3 + (__int64)result);
                                                                a2 = (size_t *)v_68;
                                                                a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                result = __ROL8__(result, 13);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a3);
                                                                a1 = __ROL8__(a1, 16);
                                                                a3 = __ROL8__(a3, 32);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)result);
                                                                result = __ROL8__(result, 17);
                                                                a3 = (int *)((__int64)a3 + (__int64)a1);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a2);
                                                                a1 = __ROL8__(a1, 21);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a3);
                                                                a2 = __ROL8__(a2, 32);
                                                                a3 = (int *)((__int64)(__int64)a3 ^ (__int64)a4);
                                                                a2 = (size_t *)((__int64)(__int64)a2 ^ 255);
                                                                a3 = (int *)((__int64)a3 + (__int64)result);
                                                                result = __ROL8__(result, 13);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a3);
                                                                a1 = __ROL8__(a1, 16);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                                a3 = __ROL8__(a3, 32);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)result);
                                                                a3 = (int *)((__int64)a3 + (__int64)a1);
                                                                result = __ROL8__(result, 17);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a2);
                                                                a1 = __ROL8__(a1, 21);
                                                                a2 = __ROL8__(a2, 32);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a3);
                                                                a3 = (int *)((__int64)a3 + (__int64)result);
                                                                result = __ROL8__(result, 13);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a3);
                                                                a1 = __ROL8__(a1, 16);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                                a3 = __ROL8__(a3, 32);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)result);
                                                                a3 = (int *)((__int64)a3 + (__int64)a1);
                                                                result = __ROL8__(result, 17);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a2);
                                                                a1 = __ROL8__(a1, 21);
                                                                a2 = __ROL8__(a2, 32);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a3);
                                                                a3 = (int *)((__int64)a3 + (__int64)result);
                                                                result = __ROL8__(result, 13);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)a1);
                                                                result = (__int64 *)((__int64)(__int64)result ^ (__int64)a3);
                                                                a1 = __ROL8__(a1, 16);
                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                                                                a2 = (size_t *)((__int64)a2 + (__int64)result);
                                                                result = __ROL8__(result, 17);
                                                                a1 = __ROL8__(a1, 21);
                                                                v11 = (__int64)a2;
                                                                v11 = __ROL8__(v11, 32);
                                                                v11 ^= (__int64)result;
                                                                v11 ^= (__int64)a1;
                                                                v11 ^= (__int64)a2;
                                                                v6 = arg_8;
                                                                a2 = (size_t *)arg_10;
                                                                result = (__int64 *)v11;
                                                                result = (__int64 *)((__int64)(__int64)result >> 57);
                                                                v5 = arg_20;
                                                                a4 = (size_t *)arg_18;
                                                                xmm0 = _mm_cvtsi32_si128(result);
                                                                xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                                xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                                xmm6 = _mm_shuffle_epi32(xmm0, 68);
                                                                a1 = (size_t *)arg_8;
                                                                v10 = arg_10;
                                                                i = 0;
                                                                xmm7 = _mm_cmpeq_epi32(xmm7, xmm7);
                                                                dst = (__int64 *)v11;
                                                                do {
                                                                    dst = (__int64 *)((__int64)(__int64)dst & v5);
                                                                    xmm8 = _mm_loadu_si128((__m128i *)((__int64)a4 + (__int64)dst));
                                                                    xmm0 = xmm8;
                                                                    xmm0 = _mm_cmpeq_epi8(xmm0, xmm6);
                                                                    result = _mm_movemask_epi8(xmm0);
                                                                    xmm8 = _mm_cmpeq_epi8(xmm8, xmm7);
                                                                    result = _mm_movemask_epi8(xmm8);
                                                                    if (result == 0) {
                                                                        dst += i;
                                                                        dst += 16;
                                                                        i += 16;
                                                                    }
                                                                    sub_1400F27F0(ptr, v2, 144, a4);
                                                                    ptr->field_90 = dst2;
                                                                    ptr->field_98 = v11;
                                                                    xmm6 = _mm_load_si128((__m128i *)&v_b0);
                                                                    xmm7 = _mm_load_si128((__m128i *)&v_c0);
                                                                    xmm8 = _mm_load_si128((__m128i *)&v_d0);
                                                                    return _mm_cvtsi128_si64(xmm8);
                                                                } while (true);
                                                            } else {
                                                                v11 = (__int64)result;
                                                            }
                                                        }
                                                        sub_1400F27F0(v11, dst, ptr, a4);
                                                        a1 = (size_t *)v11;
                                                        v11 = (__int64)ptr;
                                                        a2 = (size_t *)v_60;
                                                        a3 = (int *)v_30;
                                                        a4 = (size_t *)v_28;
                                                        v5 = v_40;
                                                        v6 = v_38;
                                                        *dst2 = i;
                                                        arg_8 = v8;
                                                        arg_10 = i;
                                                        arg_18 = (int)a4;
                                                        arg_20 = (int)a3;
                                                        arg_28 = (int)a2;
                                                        arg_30 = v6;
                                                        arg_38 = v5;
                                                        result = (__int64 *)v_58;
                                                        arg_40 = (__int64)result;
                                                        arg_48 = v10;
                                                        result = (__int64 *)v_70;
                                                        arg_50 = (__int64)result;
                                                        result = (__int64 *)v_50;
                                                        arg_58 = (__int64)result;
                                                        arg_60 = v2;
                                                        result = (__int64 *)v_68;
                                                        arg_68 = (__int64)result;
                                                        result = (__int64 *)v_48;
                                                        arg_70 = (__int64)result;
                                                        arg_78 = v11;
                                                        arg_80 = (int)a1;
                                                        arg_88 = (__int64)ptr;
                                                        return arg_88;
                                                    }
                                                    a1 = (size_t *)arg_80;
                                                    ptr = (struct Struct_1_t *)arg_88;
                                                    v11 = 0x8000000000000002;
                                                    return v11;
                                                }
                                            }
                                            return v11;
                                        }
                                        v2 = 0x8000000000000000;
                                        a1 = (size_t *)result;
                                        a1 = (size_t *)((__int64)(__int64)a1 ^ v2);
                                        /* test result , result */;
                                        result = 1;
                                        if (0 /* unresolved: flags < 0 */) result = a1;
                                        if (result == 2) {
                                            result = (__int64 *)arg_68;
                                            v_68 = (__int64)result;
                                            result = (__int64 *)arg_70;
                                            v_48 = (__int64)result;
                                            v2 = 0x8000000000000002;
                                            result = (__int64 *)arg_78;
                                            if (result != v11) {
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        if (result != 1) {
                                            return (__int64)result;
                                        }
                                        result = (__int64 *)arg_70;
                                        if (result < 0) {
                                            return (__int64)result;
                                        }
                                        v_48 = (__int64)result;
                                        v_38 = v6;
                                        v_40 = v5;
                                        v_28 = (__int64)a4;
                                        v_30 = (int)a3;
                                        v_60 = (int)a2;
                                        ptr = (struct Struct_1_t *)arg_68;
                                        if (result == 0) {
                                            v_68 = (__int64)a1;
                                            v2 = v_48;
                                            sub_1400F27F0(1, ptr, v2, a4);
                                            a2 = (size_t *)v_60;
                                            a3 = (int *)v_30;
                                            a4 = (size_t *)v_28;
                                            v5 = v_40;
                                            v6 = v_38;
                                            result = (__int64 *)arg_78;
                                            if (result != v11) {
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        a2 = (size_t *)v_48;
                                        sub_14002EDF0(0, a2, a1, v2);
                                        if (result != 0) {
                                            a1 = (size_t *)result;
                                            return (__int64)a1;
                                        }
                                        a2 = (size_t *)v_48;
                                        sub_1400F3326(1, a2);
                                        return (__int64)a2;
                                    }
                                    if (result != 2) {
                                        result = (__int64 *)arg_58;
                                        if (result < 0) {
                                            return (__int64)result;
                                        }
                                        v_50 = (__int64)result;
                                        v_38 = v6;
                                        v_40 = v5;
                                        v_28 = (__int64)a4;
                                        v_30 = (int)a3;
                                        v2 = (__int64)a2;
                                        ptr = (struct Struct_1_t *)arg_50;
                                        if (result == 0) {
                                            v_70 = (__int64)a1;
                                            v10 = v_50;
                                            sub_1400F27F0(1, ptr, v10);
                                            a2 = (size_t *)v2;
                                            a3 = (int *)v_30;
                                            a4 = (size_t *)v_28;
                                            v5 = v_40;
                                            v6 = v_38;
                                            return v6;
                                        }
                                        a2 = (size_t *)v_50;
                                        sub_14002EDF0(0, a2, a3, a4);
                                        if (result != 0) {
                                            a1 = (size_t *)result;
                                            return (__int64)a1;
                                        }
                                        a2 = (size_t *)v_50;
                                        sub_1400F3326(1, a2);
                                        return (__int64)a2;
                                    }
                                    result = (__int64 *)arg_50;
                                    v_70 = (__int64)result;
                                    result = (__int64 *)arg_58;
                                    v_50 = (__int64)result;
                                    v10 = 0x8000000000000002;
                                }
                                return v10;
                            }
                            v6 = 0x8000000000000000;
                            a1 = (size_t *)result;
                            a1 = (size_t *)((__int64)(__int64)a1 ^ v6);
                            /* test result , result */;
                            result = 1;
                            if (0 /* unresolved: flags < 0 */) result = a1;
                            if (result == 2) {
                                v5 = arg_38;
                                result = (__int64 *)arg_40;
                                v_58 = (__int64)result;
                                v6 = 0x8000000000000002;
                                result = (__int64 *)arg_48;
                                v10 = v11;
                                if (result == v11) {
                                    return v10;
                                }
                                return v10;
                            }
                            if (result != 1) {
                                result = (__int64 *)arg_48;
                                v10 = v11;
                                if (result == v11) {
                                    return v10;
                                }
                                return v10;
                            }
                            result = (__int64 *)arg_40;
                            if (result < 0) {
                                return (__int64)result;
                            }
                            v_58 = (__int64)result;
                            v_28 = (__int64)a4;
                            v_30 = (int)a3;
                            v2 = (__int64)a2;
                            ptr = (struct Struct_1_t *)arg_38;
                            if (result == 0) {
                                v10 = 1;
                                ptr = (struct Struct_1_t *)v_58;
                                sub_1400F27F0(v10, ptr, ptr);
                                v5 = v10;
                                v6 = (__int64)ptr;
                                a2 = (size_t *)v2;
                                a3 = (int *)v_30;
                                a4 = (size_t *)v_28;
                                result = (__int64 *)arg_48;
                                v10 = v11;
                                if (result == v11) {
                                    return v10;
                                }
                                return v10;
                            }
                            a2 = (size_t *)v_58;
                            sub_14002EDF0(0, a2, a3, 0x8000000000000002);
                            if (result != 0) {
                                v10 = (__int64)result;
                                return v10;
                            }
                            a2 = (size_t *)v_58;
                            sub_1400F3326(1, a2);
                            return (__int64)a2;
                        }
                        a1 = (size_t *)result;
                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a4);
                        /* test result , result */;
                        result = 1;
                        if (0 /* unresolved: flags < 0 */) result = a1;
                        if (result == 2) {
                            a3 = (int *)arg_20;
                            a2 = (size_t *)arg_28;
                            result = (__int64 *)arg_30;
                            v6 = v11;
                            if (result == v11) {
                                return v6;
                            }
                            return v6;
                        }
                        if (result != 1) {
                            return v6;
                        }
                        a2 = (size_t *)arg_28;
                        if (a2 < 0) {
                            return (__int64)a2;
                        }
                        v10 = arg_20;
                        if (a2 == 0) {
                            v2 = (__int64)a2;
                            sub_1400F27F0(1, a1, v2);
                            a2 = (size_t *)v2;
                            result = (__int64 *)arg_30;
                            v6 = v11;
                            if (result != v11) {
                                return v6;
                            }
                            return v6;
                        }
                        v2 = (__int64)a2;
                        sub_14002EDF0(0, a2, a3, 0x8000000000000000);
                        if (result != 0) {
                            a1 = (size_t *)result;
                            return (__int64)a1;
                        }
                        sub_1400F3326(1, v2);
                        return (__int64)a1;
                    } while (true);
                }
                return (__int64)a1;
            }
            xmm0 = _mm_loadu_si128((__m128i *)dst);
            return _mm_cvtsi128_si64(xmm0);
        } while (result != -144);
    }
    return (__int64)result;
}