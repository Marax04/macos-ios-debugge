// inferred from 3 accesses on `i`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `i2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14004F470();
__int64 sub_140054AA0();
__int64 sub_1400F37A0();
__int64 sub_14002EDF0();
__int64 sub_1400F8700();
__int64 sub_140011760();
__int64 sub_1400F5F90();
__int64 sub_1400F3360();
__int64 sub_1400F27F0();
__int64 sub_140017B60();
__int64 sub_14004F700();
__int64 sub_140046190();
__int64 sub_1400556F0();
__int64 sub_140055FA0();
__int64 sub_14004F7E0();
__int64 off_140108030();
__int64 off_140108038();
__int64 off_140108360();
extern __int64 off_14012D270;
extern __int64 off_14011D5D0;
extern __int64 off_14011D5E0;
extern __int64 off_140115100;
extern __int64 off_140115170;
extern __int64 off_14006A220;
extern __int64 off_140116F10;
extern __int64 off_140115C88;
extern __int64 off_14006A360;
extern __int64 off_1401175D8;
extern __int64 off_140010C50;
extern __int64 off_140115058;

__int64 __fastcall sub_140047FC0(int *a1, size_t *a2, size_t *a3) {
    __int64 rsp;
    int arg_1;
    int arg_2;
    int arg_58;
    __int64 arg_8;
    int v_2a0;
    __int64 v_2b0;
    __int64 v_2c0;
    __int64 v_2c8;
    __int64 v_2d0;
    int v_2d8;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    int v_410;
    int v_418;
    int v_420;
    int v_430;
    int v_448;
    int v_450;
    int v_458;
    int v_460;
    int v_470;
    int v_48;
    int v_480;
    int v_488;
    int v_490;
    int v_4a8;
    int v_4c0;
    int v_4c8;
    int v_4e0;
    int v_4f0;
    int v_4f8;
    int v_508;
    int v_510;
    int v_518;
    int v_520;
    int v_530;
    __int64 v_540;
    int v_548;
    int v_550;
    int v_568;
    int v_58;
    int v_580;
    int v_588;
    int v_590;
    int v_598;
    int v_5a0;
    int v_5a8;
    __int64 v_5b0;
    __int64 v_5b8;
    __int64 v_5c0;
    __int64 v_60;
    int v_660;
    int v_68;
    __int64 v_6e0;
    __int64 v_6e8;
    __int64 v_6f0;
    __int64 v_70;
    __int64 v_78;
    int v_8;
    int v_80;
    int v_8c0;
    __int64 v_8d0;
    int v_970;
    int v_980;
    int v_990;
    int v_9a0;
    __int64 v_9b0;
    int v_9c0;
    int v_9d0;
    int v_9d8;
    int v_9e8;
    int v_9f0;
    int v_9f8;
    int v_a0;
    int v_a00;
    int v_a10;
    int v_a18;
    int v_a20;
    int v_a30;
    int v_a40;
    int v_a50;
    int v_a60;
    __int64 v_a8;
    int v_b0;
    int v_b28;
    int v_b30;
    int v_b38;
    int v_b50;
    int v_b60;
    int v_b70;
    int v_b80;
    int v_b90;
    int v_ba0;
    int v_c8;
    __int64 v_d0;
    __int64 v_d8;
    __int64 v_e0;
    int v_e8;
    int v_f0;
    __int64 v_f8;
    __int64 *v_0;
    __int64 v9;
    __int64 *v2;
    __int64 *result;
    struct Struct_1_t *i;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v7;
    __m128i xmm0;
    __int64 v4;
    __int64 v5;
    struct Struct_2_t *i2;
    __int64 v6;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm8;
    __m128i xmm9;
    __m128i xmm10;
    __m128i xmm11;
    __m128i xmm3;

    _mm_store_si128((__m128i *)&v_ba0, xmm11);
    _mm_store_si128((__m128i *)&v_b90, xmm10);
    _mm_store_si128((__m128i *)&v_b80, xmm9);
    _mm_store_si128((__m128i *)&v_b70, xmm8);
    _mm_store_si128((__m128i *)&v_b60, xmm7);
    _mm_store_si128((__m128i *)&v_b50, xmm6);
    v9 = (__int64)a3;
    v2 = (__int64 *)a2;
    v_410 = (int)a1;
    result = off_14012D270;
    a1 = __readgsqword(88);
    result = v_0[(__int64)result];
    i = result + 72;
    if (arg_58 == 1) {
        result = i->field_0;
        a1 = i->field_8;
        a2 = result + 1;
        a3 = result + 2;
        *(__int64 *)i = (__int64)(a3);
        v_420 = 0;
        v_430 = 0;
        v_448 = 0;
        v_450 = 8;
        v_458 = 0;
        xmm1 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
        _mm_storeu_si128((__m128i *)&v_460, xmm1);
        xmm2 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
        _mm_storeu_si128((__m128i *)&v_470, xmm2);
        v_480 = (int)a2;
        v_488 = (int)a1;
        v7 = 0x8000000000000003;
        v_490 = v7;
        v_4a8 = v7;
        v_4c0 = 0;
        v_4c8 = 0;
        v_5a0 = 0;
        v_4e0 = 0;
        v_4f0 = 1;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_4f8, xmm0);
        v_508 = 0;
        v_510 = 8;
        v_518 = 0;
        _mm_storeu_si128((__m128i *)&v_520, xmm1);
        _mm_storeu_si128((__m128i *)&v_530, xmm2);
        v_540 = (__int64)result;
        v_548 = (int)a1;
        v_550 = v7;
        v_568 = v7;
        v_580 = 0;
        v_5a8 = 0;
        v_588 = 0;
        v_590 = 8;
        v_598 = 0;
        v_418 = 0;
        v_60 = (__int64)v2;
        v_68 = v9;
        v_70 = (__int64)v2;
        v_78 = v9;
        v_80 = 0;
        if (v9 == 0) {
            _mm_storeu_si128((__m128i *)&v_e8, xmm0);
            v_d0 = 1;
            v_d8 = 0;
            v_e0 = 8;
            a1 = rsp + 208;
            sub_14004F470(a1, a2, a3);
            i = (struct Struct_1_t *)v2;
            do {
                v4 = rsp + 0x420;
                v_2c0 = 0;
                v_2d0 = 0;
                v_2d8 = 0x920;
                a1 = rsp + 208;
                a2 = rsp + 704;
                a3 = rsp + 96;
                sub_140054AA0(a1, a2, a3);
                result = (__int64 *)v_d0;
                v_40 = (__int64)v2;
                v_c8 = v9;
                a3 = (size_t *)v_d8;
                i = (struct Struct_1_t *)v_e0;
                v5 = v_e8;
                a1 = (int *)v_f0;
                a2 = (size_t *)v_f8;
                if (result == 0) {
                    result = &off_140115100;
                    v_d0 = (__int64)result;
                    v_d8 = 1;
                    v_e0 = 8;
                    xmm0 = _mm_setzero_si128();
                    _mm_storeu_si128((__m128i *)&v_e8, xmm0);
                    a2 = &off_140115170;
                    a1 = rsp + 208;
                    sub_1400F37A0(a1, a2, a3);
                    i = v2 + 3;
                    result = v9 - 3;
                    v_70 = (__int64)i;
                    v_78 = (__int64)result;
                }
                result = (__int64 *)a3;
                result = (__int64 *)(-(__int64)result);
                if ((0 /* overflow check on (-result) */)) {
                    v_b0 = (int)a3;
                    v_48 = (int)a2;
                    v_30 = (int)a1;
                    i2 = (struct Struct_2_t *)v_70;
                    i2 = (struct Struct_2_t *)((__int64)i2 - (__int64)v2);
                    v_2c0 = 0;
                    v_2c8 = 1;
                    v_2d0 = 0;
                    v5 <<= 3;
                    result = v5 + v5*2;
                    v7 = (__int64)i + (__int64)result;
                    a1 = i - 24;
                    v6 = 0;
                    v_38 = (__int64)i2;
                    while (result != 0) {
                        a2 = a1 + 24;
                        result -= 24;
                        /* cmp a1[3] , 3 */;
                        a1 = (int *)a2;
                        a2 += 8;
                        v6 = (__int64)a2;
                    }
                    result = v5 + v5*2;
                    i2 = 0;
                    v_a8 = (__int64)i;
                    while (result != 0) {
                        v4 = (__int64)i;
                        i += 24;
                        result -= 24;
                        sub_14002EDF0(0, 32);
                        if (result == 0) JUMPOUT(0x14004c718);
                        *result = v4;
                        v_d0 = 4;
                        v_d8 = (__int64)result;
                        v_e0 = 1;
                        i2 = 1;
                        v2 = rsp + 208;
                        while (i != v7) {
                            v4 = (__int64)i;
                            i += 24;
                            if (i2 == v_d0) {
                                sub_1400F8700(v2, i2);
                                result = (__int64 *)v_d8;
                            }
                            v_0[(__int64)i2] = v4;
                            ++i2;
                            v_e0 = (__int64)i2;
                        }
                        v7 = v_d8;
                        v5 = (v_d0 == 0) ? 1 : 0;
                        v2 = (__int64 *)v_40;
                        if (v6 != 0) {
                            v_5b0 = v6;
                            result = rsp + 0x5B0;
                            v_6e0 = (__int64)result;
                            result = &off_14006A220;
                            v_6e8 = (__int64)result;
                            result = &off_140116F10;
                            v_d0 = (__int64)result;
                            v_d8 = 1;
                            v_f0 = 0;
                            result = rsp + 0x6E0;
                            v_e0 = (__int64)result;
                            v_e8 = 1;
                            a2 = &off_140115C88;
                            a1 = rsp + 704;
                            a3 = rsp + 208;
                            sub_140011760(a1, a2, a3);
                            a1 = 1;
                            if (result != 0) JUMPOUT(0x14004c6b5);
                            if (i2 != 0) {
                                result = (__int64 *)v_2c0;
                                a2 = (size_t *)v_2d0;
                                if (a1 != 0) {
                                    if (result == a2) JUMPOUT(0x14004c600);
                                    result = (__int64 *)v_2c8;
                                    *(__int64 *)((__int64)result + (__int64)a2) = 10;
                                    ++a2;
                                    v_2d0 = (__int64)a2;
                                    result = (__int64 *)v_2c0;
                                }
                                result = (__int64 *)((__int64)result - (__int64)a2);
                                v_a0 = v5;
                                if (result <= 8) JUMPOUT(0x14004c5b4);
                                result = (__int64 *)v_2c8;
                                a1 = 0x6465746365707865;
                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                *(__int64 *)((__int64)result + (__int64)a2 + 8) = 32;
                                a2 += 9;
                                v_2d0 = (__int64)a2;
                                v_58 = v7;
                                v_5b0 = v7;
                                result = rsp + 0x5B0;
                                v_6e0 = (__int64)result;
                                v4 = &off_14006A360;
                                v_6e8 = v4;
                                v9 = &off_1401175D8;
                                v_d0 = v9;
                                v_d8 = 1;
                                v_f0 = 0;
                                v7 = rsp + 0x6E0;
                                v_e0 = v7;
                                v_e8 = 1;
                                a2 = &off_140115C88;
                                a1 = rsp + 704;
                                a3 = rsp + 208;
                                sub_140011760(a1, a2, a3);
                                if (result != 0) JUMPOUT(0x14004c6a7);
                                a1 = 1;
                                if (i2 != 1) {
                                    i2 = (struct Struct_2_t *)((__int64)(__int64)i2 << 3);
                                    result = (__int64 *)v_58;
                                    i = result + 8;
                                    i2 -= 8;
                                    v6 = rsp + 704;
                                    v5 = &off_140115C88;
                                    v2 = rsp + 208;
                                    do {
                                        v_5b0 = (__int64)i;
                                        result = (__int64 *)v_2c0;
                                        a2 = (size_t *)v_2d0;
                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                        sub_1400F5F90(v6, a2, 2);
                                        a2 = (size_t *)v_2d0;
                                        result = (__int64 *)v_2c8;
                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x202C;
                                        a2 += 2;
                                        v_2d0 = (__int64)a2;
                                        result = rsp + 0x5B0;
                                        v_6e0 = (__int64)result;
                                        v_6e8 = v4;
                                        v_d0 = v9;
                                        v_d8 = 1;
                                        v_f0 = 0;
                                        v_e0 = v7;
                                        v_e8 = 1;
                                        sub_140011760(v6, v5, v2);
                                        if (result != 0) JUMPOUT(0x14004c6a7);
                                        i += 8;
                                        i2 -= 8;
                                    } while ((i2 != 0));
                                    v9 = v_c8;
                                    v2 = (__int64 *)v_40;
                                    v7 = v_58;
                                    v5 = v_a0;
                                    a1 = 1;
                                } else {
                                    v9 = v_c8;
                                    v2 = (__int64 *)v_40;
                                    v7 = v_58;
                                    v5 = v_a0;
                                }
                            } else {
                            }
                            v4 = v_30;
                            i = (struct Struct_1_t *)v_38;
                            i2 = (struct Struct_2_t *)v_48;
                            if (v4 != 0) {
                                v_5b0 = v4;
                                v_5b8 = (__int64)i2;
                                if (a1 != 0) {
                                    a2 = (size_t *)v_2d0;
                                    if (v_2c0 == a2) JUMPOUT(0x14004c620);
                                    result = (__int64 *)v_2c8;
                                    *(__int64 *)((__int64)result + (__int64)a2) = 10;
                                    ++a2;
                                    v_2d0 = (__int64)a2;
                                }
                                result = rsp + 0x5B0;
                                v_6e0 = (__int64)result;
                                result = &off_140010C50;
                                v_6e8 = (__int64)result;
                                result = &off_1401175D8;
                                v_d0 = (__int64)result;
                                v_d8 = 1;
                                v_f0 = 0;
                                result = rsp + 0x6E0;
                                v_e0 = (__int64)result;
                                v_e8 = 1;
                                a2 = &off_140115C88;
                                a1 = rsp + 704;
                                a3 = rsp + 208;
                                sub_140011760(a1, a2, a3);
                                if (result != 0) JUMPOUT(0x14004c6b5);
                            }
                            if (v5 == 0) {
                                off_140108030();
                                off_140108038(result, 0, v7);
                            }
                            result = (__int64 *)v_2d0;
                            v_6f0 = (__int64)result;
                            xmm0 = _mm_loadu_si128((__m128i *)&v_2c0);
                            _mm_store_si128((__m128i *)&v_6e0, xmm0);
                            if (v9 < 0) {
                                sub_1400F3360();
                            }
                            if ((0 /* unresolved: flags == */)) {
                                v_d8 = 1;
                                v_e0 = 0;
                                v7 = 1;
                                v6 = v9;
                                v5 = v9;
                                if (i != v9) {
                                    ++i;
                                    v5 = (__int64)i;
                                    if (v9 < i) i = v9;
                                    if (i != 0) {
                                        --v5;
                                        do {
                                            v5 -= 1;
                                        } while (!((v5 >= 0)));
                                    }
                                    v5 = 0;
                                    if (i < v9) {
                                        do {
                                            ++i;
                                        } while (v9 != i);
                                    }
                                    v6 = v9;
                                }
                            } else {
                                sub_14002EDF0(0, v9);
                                if (result == 0) JUMPOUT(0x14004c727);
                                v7 = (__int64)result;
                                sub_1400F27F0(result, v2, v9);
                                a1 = rsp + 208;
                                sub_140017B60(a1, result, v9);
                                if (v_d0 == 1) JUMPOUT(0x14004c734);
                                v6 = v9;
                                v5 = v9;
                                if (i != v9) {
                                    return v5;
                                } else {
                                }
                            }
                            result = (__int64 *)v_6f0;
                            v_2b0 = (__int64)result;
                            xmm0 = _mm_load_si128((__m128i *)&v_6e0);
                            _mm_store_si128((__m128i *)&v_2a0, xmm0);
                            if (v_b0 != 0) {
                                off_140108030();
                                a3 = (size_t *)v_a8;
                                off_140108038(result, 0, a3);
                            }
                            if (v4 != 0) {
                                result = i2->field_0;
                                if (result != 0) {
                                    ((__int64 (*)())result)(v4);
                                }
                                if (i2->field_8 != 0) {
                                    if (i2->field_10 >= 17) {
                                        v4 = v_8;
                                    }
                                    off_140108030();
                                    off_140108038(result, 0, v4);
                                }
                            }
                            a1 = rsp + 0x420;
                            sub_14004F700(a1);
                            a1 = rsp + 0x4E0;
                            sub_14004F700(a1);
                            v2 = (__int64 *)v_590;
                            i = (struct Struct_1_t *)v_598;
                            if (i != 0) {
                                i2 = (struct Struct_2_t *)v2;
                                do {
                                    sub_140046190(i2);
                                    i2 += 144;
                                    --i;
                                } while ((i != 0));
                            }
                            i = 1;
                            if (v_588 != 0) {
                                off_140108030();
                                off_140108038(result, 0, v2);
                            }
                            result = (__int64 *)v9;
                            a2 = (size_t *)v_410;
                            a2[2] = v5;
                            a2[3] = v6;
                            xmm0 = _mm_load_si128((__m128i *)&v_2a0);
                            _mm_storeu_si128((__m128i *)(a2 + 32), xmm0);
                            a1 = (int *)v_2b0;
                            a2[6] = a1;
                            a2[11] = v7;
                            a2[12] = v9;
                            arg_8 = (__int64)i;
                            a2[7] = 0;
                            a2[8] = 8;
                            a2[9] = 0;
                            a2[10] = result;
                            *a2 = 12;
                            xmm6 = _mm_load_si128((__m128i *)&v_b50);
                            xmm7 = _mm_load_si128((__m128i *)&v_b60);
                            xmm8 = _mm_load_si128((__m128i *)&v_b70);
                            xmm9 = _mm_load_si128((__m128i *)&v_b80);
                            xmm10 = _mm_load_si128((__m128i *)&v_b90);
                            xmm11 = _mm_load_si128((__m128i *)&v_ba0);
                            return _mm_cvtsi128_si64(xmm11);
                        } else {
                            a1 = 0;
                            if (i2 != 0) {
                                return (__int64)a1;
                            }
                            return (__int64)a1;
                        }
                        return (__int64)a1;
                    }
                    v5 = 1;
                    v7 = 8;
                    if (v6 == 0) {
                        return v7;
                    } else {
                        return v7;
                    }
                    return v7;
                } else {
                    v2 = rsp + 0x9C0;
                    sub_1400F27F0(v2, v4, 400);
                    a1 = rsp + 208;
                    sub_1400556F0(a1, v2);
                    i = (struct Struct_1_t *)v_d0;
                    if (i != v7) {
                        xmm6 = _mm_loadu_si128((__m128i *)&v_d8);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_e8);
                        _mm_store_si128((__m128i *)&v_5b0, xmm0);
                        result = (__int64 *)v_f8;
                        v_5c0 = (__int64)result;
                        a1 = rsp + 0x9C0;
                        sub_14004F700(a1);
                        a1 = rsp + 0xA80;
                        sub_14004F700(a1);
                        v2 = (__int64 *)v_b30;
                        v4 = v_b38;
                        if (v4 != 0) {
                            v7 = (__int64)v2;
                            do {
                                sub_140046190(v7);
                                v7 += 144;
                                --v4;
                            } while ((v4 != 0));
                        }
                        if (v_b28 != 0) {
                            off_140108030();
                            off_140108038(result, 0, v2);
                        }
                        _mm_storeu_si128((__m128i *)&v_d8, xmm6);
                        xmm0 = _mm_load_si128((__m128i *)&v_5b0);
                        _mm_storeu_si128((__m128i *)&v_e8, xmm0);
                        result = (__int64 *)v_5c0;
                        v_f8 = (__int64)result;
                        v_d0 = (__int64)i;
                        v_6e0 = 0;
                        v_6e8 = 1;
                        v_6f0 = 0;
                        result = 0xE0000020;
                        v_2d0 = (__int64)result;
                        result = rsp + 0x6E0;
                        v_2c0 = (__int64)result;
                        result = &off_140115058;
                        v_2c8 = (__int64)result;
                        a1 = rsp + 208;
                        a2 = rsp + 704;
                        sub_140055FA0(a1, a2);
                        if (result != 0) JUMPOUT(0x14004c5d4);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_6e0);
                        _mm_store_si128((__m128i *)&v_8c0, xmm0);
                        result = (__int64 *)v_6f0;
                        v_8d0 = (__int64)result;
                        a1 = rsp + 208;
                        sub_14004F7E0(a1);
                        xmm0 = _mm_load_si128((__m128i *)&v_8c0);
                        _mm_store_si128((__m128i *)&v_660, xmm0);
                        result = (__int64 *)v_8d0;
                        _mm_store_si128((__m128i *)&v_2a0, xmm0);
                        v_2b0 = (__int64)result;
                        result = 0x8000000000000000;
                        i = 0;
                        return (__int64)i;
                    } else {
                        xmm6 = _mm_load_si128((__m128i *)&v_9c0);
                        i2 = (struct Struct_2_t *)v_9d0;
                        xmm0 = _mm_loadu_si128((__m128i *)&v_9d8);
                        _mm_store_si128((__m128i *)&v_5b0, xmm0);
                        result = (__int64 *)v_9e8;
                        v_5c0 = (__int64)result;
                        i = (struct Struct_1_t *)v_9f0;
                        v4 = v_9f8;
                        xmm7 = _mm_load_si128((__m128i *)&v_a00);
                        v5 = v_a10;
                        v6 = v_a18;
                        xmm0 = _mm_load_si128((__m128i *)&v_a20);
                        _mm_store_si128((__m128i *)&v_970, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_a30);
                        _mm_store_si128((__m128i *)&v_980, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_a40);
                        _mm_store_si128((__m128i *)&v_990, xmm0);
                        xmm0 = _mm_load_si128((__m128i *)&v_a50);
                        _mm_store_si128((__m128i *)&v_9a0, xmm0);
                        result = (__int64 *)v_a60;
                        v_9b0 = (__int64)result;
                        a1 = rsp + 0xA80;
                        sub_14004F700(a1);
                        v2 = (__int64 *)v_b30;
                        v9 = v_b38;
                        if (v9 != 0) {
                            v7 = (__int64)v2;
                            do {
                                sub_140046190(v7);
                                v7 += 144;
                                --v9;
                            } while ((v9 != 0));
                        }
                        if (v_b28 != 0) {
                            off_140108030();
                            off_140108038(result, 0, v2);
                        }
                        result = (__int64 *)v_5c0;
                        xmm0 = _mm_load_si128((__m128i *)&v_5b0);
                        _mm_store_si128((__m128i *)&v_2a0, xmm0);
                        v_2b0 = (__int64)result;
                        a1 = (int *)v_410;
                        a1[3] = i2;
                        xmm0 = _mm_load_si128((__m128i *)&v_2a0);
                        _mm_storeu_si128((__m128i *)(a1 + 32), xmm0);
                        result = (__int64 *)v_2b0;
                        a1[6] = result;
                        a1[11] = v5;
                        a1[12] = v6;
                        *a1 = 10;
                        _mm_storeu_si128((__m128i *)(a1 + 8), xmm6);
                        a1[7] = i;
                        a1[8] = v4;
                        _mm_storeu_si128((__m128i *)(a1 + 72), xmm7);
                        xmm0 = _mm_load_si128((__m128i *)&v_970);
                        xmm1 = _mm_load_si128((__m128i *)&v_980);
                        xmm2 = _mm_load_si128((__m128i *)&v_990);
                        xmm3 = _mm_load_si128((__m128i *)&v_9a0);
                        _mm_storeu_si128((__m128i *)(a1 + 104), xmm0);
                        _mm_storeu_si128((__m128i *)(a1 + 120), xmm1);
                        _mm_storeu_si128((__m128i *)(a1 + 136), xmm2);
                        _mm_storeu_si128((__m128i *)(a1 + 152), xmm3);
                        result = (__int64 *)v_9b0;
                        a1[21] = result;
                        result = (__int64 *)v_40;
                        a1[22] = result;
                        result = (__int64 *)v_c8;
                        a1[23] = result;
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            } while (true);
        }
        result = (*v2 != 239) ? 1 : 0;
        a1 = (v9 == 1) ? 1 : 0;
        a1 = (int *)((__int64)(__int64)a1 | (__int64)result);
        if ((a1 != 0)) {
            return (__int64)a1;
        }
        result = (arg_1 != 187) ? 1 : 0;
        a1 = (v9 == 2) ? 1 : 0;
        a1 = (int *)((__int64)(__int64)a1 | (__int64)result);
        if ((a1 != 0)) {
            return (__int64)a1;
        }
        result = (arg_2 != 191) ? 1 : 0;
        a1 = (v9 < 3) ? 1 : 0;
        a1 = (int *)((__int64)(__int64)a1 | (__int64)result);
        if ((a1 == 0)) {
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    do {
        xmm0 = _mm_setzero_si128();
        _mm_store_si128((__m128i *)&v_d0, xmm0);
        a1 = rsp + 208;
        off_140108360(a1, 16);
        result = (__int64 *)v_d0;
        a1 = (int *)v_d8;
        i->field_8 = a1;
        i->field_10 = 1;
        return (__int64)result;
    } while (true);
}