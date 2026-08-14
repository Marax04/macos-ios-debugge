// inferred from 5 accesses on `i`
struct Struct_1_t {
    char field_0; // offset 0
    char field_1; // offset 1
    char field_2; // offset 2
    char field_3; // offset 3
    __int64 field_4; // offset 4
};

// inferred from 7 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[16];
    __int64 field_50; // offset 80
};

__int64 sub_140064210();
__int64 sub_14002EDF0();
__int64 sub_1400F8440();
__int64 sub_140065200();
__int64 sub_140055430();
__int64 sub_140065F70();
__int64 sub_14005B1B0();
__int64 sub_1400F27F0();
__int64 sub_14004F470();
__int64 sub_14005B1B7();
__int64 sub_140064480();
__int64 sub_1400F3340();
__int64 sub_140058520();
__int64 sub_140062120();
__int64 sub_140062190();
__int64 sub_140064DC0();
__int64 sub_140064FE0();
__int64 sub_140064450();
__int64 sub_1400F3B80();
__int64 sub_1400F37D0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401159D0;
extern __int64 off_140116E58;
extern __int64 off_140116225;
extern __int64 off_140116C59;
extern __int64 off_14011E6D2;
extern __int64 off_14011E6C8;
extern __int64 off_140116D40;
extern __int64 off_140116E40;
extern __int64 off_140116C89;
extern __int64 off_140115EA0;
extern __int64 off_140116E28;
extern __int64 off_140116E10;
extern __int64 off_1401168C8;
extern __int64 off_140116980;
extern __int64 off_140116D10;

__int64 __fastcall sub_14005C124(size_t *a1, size_t *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    __int64 arg_18;
    int arg_20;
    int arg_4;
    int arg_5;
    int arg_6;
    int arg_7;
    __int64 arg_8;
    int arg_9;
    __int64 arg_d;
    int arg_e;
    int arg_f;
    int v_1e0;
    __int64 v_1e8;
    __int64 v_1f0;
    __int64 v_1f8;
    __int64 v_1fc;
    __int64 v_1fe;
    __int64 v_20;
    __int64 v_200;
    __int64 v_202;
    __int64 v_206;
    __int64 v_208;
    int v_210;
    __int64 v_218;
    int v_220;
    __int64 v_22c;
    __int64 v_230;
    __int64 v_238;
    __int64 v_23c;
    __int64 v_23e;
    __int64 v_240;
    __int64 v_242;
    __int64 v_246;
    int v_28;
    int v_298;
    __int64 v_2a8;
    int v_2b0;
    __int64 v_2c0;
    int v_2c2;
    int v_2c4;
    __int64 v_2d0;
    __int64 v_2d8;
    int v_2d9;
    int v_2da;
    int v_2db;
    int v_2dc;
    int v_2dd;
    __int64 v_2de;
    int v_2df;
    __int64 v_2e0;
    int v_2e1;
    int v_2e2;
    int v_2e4;
    int v_2e5;
    int v_2e6;
    int v_2e7;
    __int64 v_2e8;
    int v_2e9;
    int v_2ea;
    int v_2ec;
    __int64 v_2f0;
    __int64 v_2f8;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    __int64 v_430;
    __int64 v_434;
    __int64 v_438;
    __int64 v_450;
    __int64 v_454;
    __int64 v_460;
    __int64 v_468;
    __int64 v_48;
    __int64 v_488;
    __int64 v_48c;
    int v_490;
    int v_498;
    int v_4a0;
    int v_4a4;
    int v_4a8;
    int v_4b0;
    int v_50;
    int v_540;
    __int64 v_544;
    __int64 v_58;
    __int64 v_580;
    int v_584;
    int v_588;
    int v_58a;
    int v_5f8;
    int v_60;
    int v_600;
    int v_608;
    int v_60c;
    int v_60e;
    int v_610;
    int v_612;
    int v_616;
    int v_618;
    int v_620;
    __int64 v_68;
    __int64 v_70;
    int v_71;
    int v_730;
    __int64 v_738;
    __int64 v_740;
    __int64 v_744;
    __int64 v_746;
    __int64 v_748;
    __int64 v_74a;
    __int64 v_74e;
    int v_75;
    __int64 v_750;
    int v_758;
    int v_77;
    __int64 v_78;
    int v_79;
    int v_7c;
    int v_7d;
    int v_7d0;
    int v_7d4;
    int v_7d8;
    __int64 v_7e;
    int v_7e0;
    int v_7e8;
    int v_7f;
    __int64 v_80;
    int v_81;
    int v_82;
    int v_84;
    __int64 v_86;
    __int64 v_88;
    int v_880;
    int v_888;
    int v_89;
    int v_898;
    int v_8a;
    int v_8a8;
    int v_8c;
    int v_8e;
    __int64 v_90;
    int v_910;
    __int64 v_918;
    __int64 v_920;
    __int64 v_924;
    __int64 v_926;
    __int64 v_928;
    __int64 v_92a;
    __int64 v_92e;
    __int64 v_930;
    int v_938;
    int v_98;
    int v_9c0;
    int v_9c8;
    int v_9d0;
    int v_9d8;
    __int64 *v_0;
    __int64 *v_10;
    __int64 *v_8;
    __int64 *result;
    __int64 *i3;
    __int64 v9;
    __int64 v5;
    struct Struct_1_t *i;
    __int64 v11;
    __int64 *dst;
    __int64 *i2;
    __int64 *v4;
    __m128i xmm0;
    __m128i xmm6;
    __int64 v6;
    __m128i xmm1;
    __int64 v_cap;
    struct Struct_2_t *ptr;

    result += *result;
    *a1 = *a1 + (__int64)i2;
    a1 = rsp + 112;
    a2 = rsp + 720;
    sub_140064210(a1, a2, v11);
    a3 = (size_t *)v_70;
    i3 = (__int64 *)v_78;
    a2 = (size_t *)v_80;
    if (a3 == 3) {
        if (a2 == 1) {
            a2 = *i3;
            if (a2 != 43) {
                result = 1;
                if (a2 != 45) {
                    a1 = 0;
                    a2 = 0;
                    v9 = *(__int64 *)((__int64)i3 + (__int64)a1);
                    v9 += 0xFFFFFFD0;
                    while (v9 <= 9) {
                        a2 = (size_t *)((__int64)a2 + (__int64)a2);
                        a2 += (__int64)(__int64)a2*4;
                        v9 += (__int64)a2;
                        ++a1;
                        a2 = (size_t *)v9;
                        result = v9 - 1;
                        if (result >= 12) {
                            arg_10 = (__int64)i;
                            arg_18 = (__int64)v4;
                            sub_14002EDF0(0, 48);
                            if (result != 0) {
                                a1 = 0x8000000000000001;
                                *result = a1;
                                arg_8 = v9;
                                v5 = 2;
                                a1 = &off_1401159D0;
                                i3 = 0;
                                i = 0;
                                a2 = (size_t *)i3;
                                a2 = (size_t *)((__int64)(__int64)a2 >> 32);
                                v_540 = (int)a2;
                                v_544 = (__int64)dst;
                                a2 = (size_t *)i;
                                a2 = (size_t *)((__int64)(__int64)a2 >> 16);
                                v11 = (__int64)i;
                                v11 >>= 32;
                                a4 = (size_t *)v_540;
                                a3 = (size_t *)dst;
                                a3 = (size_t *)((__int64)(__int64)a3 >> 32);
                                dst = (__int64 *)((__int64)(__int64)dst >> 48);
                                v_430 = (__int64)i3;
                                v_434 = (__int64)a4;
                                v_2c0 = (__int64)a2;
                                v_2c2 = v11;
                                a2 = (size_t *)v_430;
                                a4 = (size_t *)((__int64)(__int64)a4 >> 32);
                                if (v5 == 2) {
                                    v_2d0 = (__int64)a2;
                                    v_2d8 = (__int64)a4;
                                    v_2dc = (int)a3;
                                    v_2de = (__int64)dst;
                                    v_2e0 = (__int64)i;
                                    a3 = (size_t *)v_2c4;
                                    v_2e6 = (int)a3;
                                    a3 = (size_t *)v_2c0;
                                    v_2e2 = (int)a3;
                                    v_2e8 = (__int64)result;
                                    v_2f0 = (__int64)a1;
                                    i2 = (__int64 *)v_2e0;
                                    v11 = v_28;
                                    if (i2 == a2) {
                                        a1 = rsp + 720;
                                        v4 = (__int64 *)v5;
                                        sub_1400F8440(a1, a2);
                                        v5 = (__int64)v4;
                                        a2 = (size_t *)v_2d0;
                                    }
                                    a1 = rsp + 728;
                                    result = (__int64 *)v_2d8;
                                    a3 = i2 + (__int64)(__int64)i2*2;
                                    v_0[(__int64)a3] = 3;
                                    a4 = &off_140116E58;
                                    v_8[(__int64)a3] = a4;
                                    v_10[(__int64)a3] = 9;
                                    ++i2;
                                    v_2e0 = (__int64)i2;
                                } else {
                                    v11 = v_28;
                                    if (v5 != 1) {
                                        dst = 0;
                                    } else {
                                        v_70 = (__int64)a2;
                                        v_78 = (__int64)a4;
                                        v_7c = (int)a3;
                                        v_7e = (__int64)dst;
                                        v_80 = (__int64)i;
                                        a3 = (size_t *)v_2c4;
                                        v_86 = (__int64)a3;
                                        a3 = (size_t *)v_2c0;
                                        v_82 = (int)a3;
                                        v_88 = (__int64)result;
                                        v_90 = (__int64)a1;
                                        i2 = (__int64 *)v_80;
                                        if (i2 == a2) {
                                            a1 = rsp + 112;
                                            v4 = (__int64 *)v5;
                                            sub_1400F8440(a1);
                                            v5 = (__int64)v4;
                                            a2 = (size_t *)v_70;
                                        }
                                        a1 = rsp + 120;
                                        result = (__int64 *)v_78;
                                        a3 = i2 + (__int64)(__int64)i2*2;
                                        v_0[(__int64)a3] = 3;
                                        a4 = &off_140116E58;
                                        v_8[(__int64)a3] = a4;
                                        v_10[(__int64)a3] = 9;
                                        ++i2;
                                        v_80 = (__int64)i2;
                                        i = (struct Struct_1_t *)result;
                                        i = (struct Struct_1_t *)((__int64)(__int64)i >> 32);
                                        v4 = result;
                                        v4 = (__int64 *)((__int64)(__int64)v4 >> 48);
                                        a3 = a1[1];
                                        v_2c4 = (int)a3;
                                        a3 = a1[1];
                                        v_2c0 = (__int64)a3;
                                        i3 = a1[2];
                                        v9 = a1[3];
                                        v_430 = (__int64)a2;
                                        v_438 = (__int64)result;
                                        dst = 2;
                                        if (v5 != 1) {
                                            result = (__int64 *)v_438;
                                            v_468 = (__int64)result;
                                            result = (__int64 *)v_430;
                                            v_460 = (__int64)result;
                                            result = (__int64 *)v_2c0;
                                            v_450 = (__int64)result;
                                            result = (__int64 *)v_2c4;
                                            v_454 = (__int64)result;
                                            if (dst != 3) {
                                                result = (__int64 *)v_468;
                                                v_1f8 = (__int64)result;
                                                result = (__int64 *)v_460;
                                                v_1f0 = (__int64)result;
                                                result = (__int64 *)v_450;
                                                v_202 = (__int64)result;
                                                result = (__int64 *)v_454;
                                                v_206 = (__int64)result;
                                                v_1e8 = (__int64)dst;
                                                v_1fc = (__int64)i;
                                                v_1fe = (__int64)v4;
                                                v_200 = (__int64)i2;
                                                v_208 = (__int64)i3;
                                                v_210 = v9;
                                                v_1e0 = 8;
                                                if (dst == 1) {
                                                    i2 = rsp + 488;
                                                    v9 = v_38;
                                                    arg_10 = v9;
                                                    v4 = (__int64 *)v_40;
                                                    arg_18 = (__int64)v4;
                                                    a1 = rsp + 720;
                                                    sub_140065200(a1, v11);
                                                    if (v_2d0 == 8) {
                                                        if (v_2d8 == 1) {
                                                            a3 = rsp + 728;
                                                            a1 = rsp + 0x6B0;
                                                            sub_140055430(a1, i2, a3);
                                                            arg_10 = v9;
                                                            arg_18 = (__int64)v4;
                                                            a1 = rsp + 112;
                                                            sub_140065F70(a1, v11);
                                                            if (v_70 == 8) {
                                                                if (v_78 == 1) {
                                                                    a3 = rsp + 120;
                                                                    a1 = rsp + 0x880;
                                                                    a2 = rsp + 0x6B0;
                                                                    sub_140055430(a1, a2, a3);
                                                                    result = (__int64 *)v_880;
                                                                    a1 = (size_t *)v_8a8;
                                                                    ptr->field_30 = a1;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_898);
                                                                    _mm_storeu_si128((__m128i *)(ptr + 32), xmm0);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_888);
                                                                    _mm_storeu_si128((__m128i *)(ptr + 16), xmm0);
                                                                    ptr->field_8 = result;
                                                                    return sub_14005B1B0();
                                                                }
                                                            }
                                                            a2 = rsp + 112;
                                                            sub_1400F27F0(ptr, a2, 176);
                                                            a1 = rsp + 0x6B0;
                                                            sub_14004F470(a1);
                                                            return sub_14005B1B7();
                                                        }
                                                    }
                                                    a2 = rsp + 720;
                                                    sub_1400F27F0(ptr, a2, 176);
                                                    sub_14004F470(i2);
                                                    return sub_14005B1B7();
                                                }
                                            } else {
                                                result = (__int64 *)v_468;
                                                v_88 = (__int64)result;
                                                result = (__int64 *)v_460;
                                                v_80 = (__int64)result;
                                                result = (__int64 *)v_450;
                                                v_242 = (__int64)result;
                                                result = (__int64 *)v_454;
                                                v_246 = (__int64)result;
                                                v_1e0 = 6;
                                                result = 0x8000000000000003;
                                                v_1e8 = (__int64)result;
                                                v_200 = (__int64)result;
                                                v_218 = (__int64)result;
                                                xmm0 = _mm_loadu_si128((__m128i *)&v_70);
                                                _mm_storeu_si128((__m128i *)&v_220, xmm0);
                                                result = (__int64 *)v_7c;
                                                v_22c = (__int64)result;
                                                result = (__int64 *)v_80;
                                                v_230 = (__int64)result;
                                                result = (__int64 *)v_88;
                                                v_238 = (__int64)result;
                                                v_23c = (__int64)i;
                                                v_23e = (__int64)v4;
                                                v_240 = (__int64)i2;
                                            }
                                            a2 = rsp + 480;
                                            sub_1400F27F0(ptr, a2, 176);
                                            return sub_14005B1B7();
                                        } else {
                                            v_730 = 1;
                                            result = (__int64 *)v_430;
                                            v_738 = (__int64)result;
                                            result = (__int64 *)v_438;
                                            v_740 = (__int64)result;
                                            v_744 = (__int64)i;
                                            v_746 = (__int64)v4;
                                            v_748 = (__int64)i2;
                                            result = (__int64 *)v_2c0;
                                            v_74a = (__int64)result;
                                            result = (__int64 *)v_2c4;
                                            v_74e = (__int64)result;
                                            v_750 = (__int64)i3;
                                            v_758 = v9;
                                            result = (__int64 *)v_38;
                                            arg_10 = (__int64)result;
                                            result = (__int64 *)v_40;
                                            arg_18 = (__int64)result;
                                            a1 = rsp + 112;
                                            sub_140064480(a1, v11, a3, a4);
                                            v11 = v_70;
                                            if (v11 != 3) {
                                                result = rsp + 120;
                                                a1 = (size_t *)arg_8;
                                                v_490 = (int)a1;
                                                result = *result;
                                                v_488 = (__int64)result;
                                                a3 = (size_t *)v_84;
                                                a2 = (size_t *)v_86;
                                                a1 = (size_t *)v_88;
                                                a4 = (size_t *)v_8a;
                                                v_7d0 = (int)a4;
                                                a4 = (size_t *)v_8e;
                                                v_7d4 = (int)a4;
                                                i3 = (__int64 *)v_90;
                                                v9 = v_98;
                                                if (v11 == 2) {
                                                    dst = rsp + 738;
                                                    v_2d0 = (__int64)result;
                                                    a4 = (size_t *)v_490;
                                                    v_2d8 = (__int64)a4;
                                                    v_2dc = (int)a3;
                                                    v_2de = (__int64)a2;
                                                    v_2e0 = (__int64)a1;
                                                    a1 = (size_t *)v_7d4;
                                                    arg_4 = (int)a1;
                                                    a1 = (size_t *)v_7d0;
                                                    *dst = a1;
                                                    v_2e8 = (__int64)i3;
                                                    v_2f0 = v9;
                                                    i2 = (__int64 *)v_2e0;
                                                    if (i2 == result) {
                                                        a1 = rsp + 720;
                                                        sub_1400F8440(a1);
                                                        result = (__int64 *)v_2d0;
                                                    }
                                                    a1 = (size_t *)v_2d8;
                                                    a2 = i2 + (__int64)(__int64)i2*2;
                                                    v_0[(__int64)a2] = 3;
                                                    a3 = &off_140116225;
                                                    v_8[(__int64)a2] = a3;
                                                    v_10[(__int64)a2] = 4;
                                                    ++i2;
                                                    v_2e0 = (__int64)i2;
                                                } else {
                                                    if (v11 != 1) {
                                                        dst = 0;
                                                    } else {
                                                        dst = rsp + 130;
                                                        v_70 = (__int64)result;
                                                        a4 = (size_t *)v_490;
                                                        v_78 = (__int64)a4;
                                                        v_7c = (int)a3;
                                                        v_7e = (__int64)a2;
                                                        v_80 = (__int64)a1;
                                                        a1 = (size_t *)v_7d4;
                                                        arg_4 = (int)a1;
                                                        a1 = (size_t *)v_7d0;
                                                        *dst = a1;
                                                        v_88 = (__int64)i3;
                                                        v_90 = v9;
                                                        i2 = (__int64 *)v_80;
                                                        if (i2 == result) {
                                                            a1 = rsp + 112;
                                                            sub_1400F8440(a1);
                                                            result = (__int64 *)v_70;
                                                        }
                                                        a1 = (size_t *)v_78;
                                                        a2 = i2 + (__int64)(__int64)i2*2;
                                                        v_0[(__int64)a2] = 3;
                                                        a3 = &off_140116225;
                                                        v_8[(__int64)a2] = a3;
                                                        v_10[(__int64)a2] = 4;
                                                        ++i2;
                                                        v_80 = (__int64)i2;
                                                        i = (struct Struct_1_t *)a1;
                                                        i = (struct Struct_1_t *)((__int64)(__int64)i >> 32);
                                                        v4 = (__int64 *)a1;
                                                        v4 = (__int64 *)((__int64)(__int64)v4 >> 48);
                                                        a2 = (size_t *)arg_4;
                                                        v_7d4 = (int)a2;
                                                        a2 = *dst;
                                                        v_7d0 = (int)a2;
                                                        i3 = (__int64 *)arg_6;
                                                        v9 = arg_e;
                                                        v_488 = (__int64)result;
                                                        v_490 = (int)a1;
                                                        dst = 2;
                                                        if (v11 != 1) {
                                                            v11 = v_28;
                                                            result = (__int64 *)v_490;
                                                            v_468 = (__int64)result;
                                                            result = (__int64 *)v_488;
                                                            v_460 = (__int64)result;
                                                            result = (__int64 *)v_7d0;
                                                            v_450 = (__int64)result;
                                                            result = (__int64 *)v_7d4;
                                                            v_454 = (__int64)result;
                                                            a1 = rsp + 0x730;
                                                            sub_14004F470(a1);
                                                            if (dst != 3) {
                                                                return (__int64)a1;
                                                            } else {
                                                                return (__int64)a1;
                                                            }
                                                            return (__int64)a1;
                                                        } else {
                                                            v_910 = 1;
                                                            result = (__int64 *)v_488;
                                                            v_918 = (__int64)result;
                                                            result = (__int64 *)v_490;
                                                            v_920 = (__int64)result;
                                                            v_924 = (__int64)i;
                                                            v_926 = (__int64)v4;
                                                            v_928 = (__int64)i2;
                                                            result = (__int64 *)v_7d0;
                                                            v_92a = (__int64)result;
                                                            result = (__int64 *)v_7d4;
                                                            v_92e = (__int64)result;
                                                            v_930 = (__int64)i3;
                                                            v_938 = v9;
                                                            a1 = rsp + 0x5F8;
                                                            a2 = rsp + 0x730;
                                                            a3 = rsp + 0x910;
                                                            sub_140055430(a1, a2, a3, a4);
                                                            dst = (__int64 *)v_5f8;
                                                            result = (__int64 *)v_600;
                                                            v_460 = (__int64)result;
                                                            result = (__int64 *)v_608;
                                                            v_468 = (__int64)result;
                                                            i = (struct Struct_1_t *)v_60c;
                                                            v4 = (__int64 *)v_60e;
                                                            i2 = (__int64 *)v_610;
                                                            result = (__int64 *)v_612;
                                                            v_450 = (__int64)result;
                                                            result = (__int64 *)v_616;
                                                            v_454 = (__int64)result;
                                                            i3 = (__int64 *)v_618;
                                                            v9 = v_620;
                                                            v11 = v_28;
                                                        }
                                                        return v11;
                                                    }
                                                    return v11;
                                                }
                                                return v11;
                                            } else {
                                                result = (__int64 *)v_78;
                                                v_488 = 1;
                                                v_48c = (__int64)result;
                                                dst = 3;
                                                i = 2;
                                                i2 = 0;
                                            }
                                            return (__int64)i2;
                                        }
                                        return (__int64)i2;
                                    }
                                    return (__int64)i2;
                                }
                                return (__int64)i2;
                            }
                        } else {
                            v4 = (__int64 *)arg_18;
                            v5 = 2;
                            if (v4 != 0) {
                                i = (struct Struct_1_t *)arg_10;
                                if (i->field_0 != 45) {
                                    i3 = 0;
                                    i = 0;
                                    result = 0;
                                } else {
                                    ++i;
                                    --v4;
                                    arg_10 = (__int64)i;
                                    arg_18 = (__int64)v4;
                                    v_2d0 = 1;
                                    v_2d8 = 2;
                                    v_2e0 = 2;
                                    v_2e8 = 0x3000;
                                    v_2ea = 57;
                                    a1 = rsp + 112;
                                    a2 = rsp + 720;
                                    sub_140064210(a1, a2, v11, a4);
                                    a3 = (size_t *)v_70;
                                    i3 = (__int64 *)v_78;
                                    a2 = (size_t *)v_80;
                                    if (a3 != 3) {
                                        i = (struct Struct_1_t *)v_88;
                                        result = (__int64 *)v_90;
                                        a1 = (size_t *)v_98;
                                        v5 = 2;
                                        if (a3 != 1) v5 = a3;
                                        dst = (__int64 *)a2;
                                    } else {
                                        if (a2 == 1) {
                                            a2 = *i3;
                                            a1 = 1;
                                            if (a2 != 43) {
                                                if (a2 != 45) {
                                                    a1 = 0;
                                                    a2 = 0;
                                                    result = *(__int64 *)((__int64)i3 + (__int64)a1);
                                                    result += 0xFFFFFFD0;
                                                    while (result <= 9) {
                                                        a2 = (size_t *)((__int64)a2 + (__int64)a2);
                                                        a2 += (__int64)(__int64)a2*4;
                                                        result = (__int64 *)((__int64)result + (__int64)a2);
                                                        ++a1;
                                                        a2 = (size_t *)result;
                                                        a1 = result - 1;
                                                        if (a1 >= 31) {
                                                            i2 = result;
                                                            arg_10 = (__int64)i;
                                                            arg_18 = (__int64)v4;
                                                            sub_14002EDF0(0, 48, 31);
                                                            if (result == 0) {
                                                                sub_1400F3340(8, 48);
                                                                xmm0 = _mm_setzero_si128();
                                                                _mm_storeu_si128((__m128i *)v4, xmm0);
                                                                v_70 = 1;
                                                                v_78 = 0;
                                                                v_80 = 8;
                                                                v11 = 0;
                                                                xmm0 = _mm_setzero_si128();
                                                                _mm_storeu_si128((__m128i *)&v_2e8, xmm0);
                                                                a1 = rsp + 112;
                                                                sub_14004F470(a1);
                                                                v_2d0 = 1;
                                                                v_2d8 = 0;
                                                                v_2e0 = 8;
                                                                a1 = rsp + 720;
                                                                sub_14004F470(a1);
                                                                if (v11 == 0) {
                                                                    xmm0 = _mm_setzero_si128();
                                                                    _mm_storeu_si128((__m128i *)&v_88, xmm0);
                                                                    v_70 = 1;
                                                                    v_78 = 0;
                                                                    v_80 = 8;
                                                                } else {
                                                                    result = (i->field_0 != 34) ? 1 : 0;
                                                                    a1 = (v11 == 1) ? 1 : 0;
                                                                    a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                    if (!((a1 != 0))) {
                                                                        if (i->field_1 == 34) {
                                                                            v4 = i + 2;
                                                                            dst = (__int64 *)v11;
                                                                            dst -= 2;
                                                                            result = (__int64 *)v_28;
                                                                            arg_10 = (__int64)v4;
                                                                            arg_18 = (__int64)dst;
                                                                            if (!((dst == 0))) {
                                                                                if (*v4 == 34) {
                                                                                    if (dst != 1) {
                                                                                        if (i->field_3 == 34) {
                                                                                            if (dst != 2) {
                                                                                                if (i->field_4 == 34) {
                                                                                                    i3 = 2;
                                                                                                    if (dst < 3) {
                                                                                                        xmm0 = _mm_setzero_si128();
                                                                                                        _mm_storeu_si128((__m128i *)&v_88, xmm0);
                                                                                                        v_70 = 1;
                                                                                                        v_78 = 0;
                                                                                                        v_80 = 8;
                                                                                                        if (i->field_0 == 34) {
                                                                                                            v4 = i + 1;
                                                                                                            dst = (__int64 *)v11;
                                                                                                            --dst;
                                                                                                            result = (__int64 *)v_28;
                                                                                                            arg_10 = (__int64)v4;
                                                                                                            arg_18 = (__int64)dst;
                                                                                                            if (!((dst == 0))) {
                                                                                                                if (*v4 == 34) {
                                                                                                                    if (dst != 1) {
                                                                                                                        if (i->field_2 == 34) {
                                                                                                                            if (dst != 2) {
                                                                                                                                result = (i->field_3 != 34) ? 1 : 0;
                                                                                                                                a1 = (v11 < 4) ? 1 : 0;
                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                                                                if ((a1 != 0)) {
                                                                                                                                    _mm_storeu_si128((__m128i *)&v_2e8, xmm0);
                                                                                                                                    a1 = rsp + 112;
                                                                                                                                    sub_14004F470(a1);
                                                                                                                                    v_2d0 = 1;
                                                                                                                                    v_2d8 = 0;
                                                                                                                                    v_2e0 = 8;
                                                                                                                                    result = (__int64 *)v_28;
                                                                                                                                    arg_10 = (__int64)i;
                                                                                                                                    arg_18 = v11;
                                                                                                                                    a1 = rsp + 720;
                                                                                                                                    sub_14004F470(a1);
                                                                                                                                    i3 = (__int64 *)v_1e0;
                                                                                                                                    if (v11 != 0) {
                                                                                                                                        if (i->field_0 == 34) {
                                                                                                                                            if (v11 != 1) {
                                                                                                                                                if (i->field_1 == 34) {
                                                                                                                                                    if (v11 != 2) {
                                                                                                                                                        if (i->field_2 == 34) {
                                                                                                                                                            if (v11 > 2) {
                                                                                                                                                                i += 3;
                                                                                                                                                                v11 -= 3;
                                                                                                                                                                result = (__int64 *)v_28;
                                                                                                                                                                arg_10 = (__int64)i;
                                                                                                                                                                arg_18 = v11;
                                                                                                                                                                i2 = (__int64 *)v_40;
                                                                                                                                                                result = i3;
                                                                                                                                                                result = (__int64 *)(-(__int64)result);
                                                                                                                                                                if ((0 /* overflow check on (-result) */)) {
                                                                                                                                                                    a1 = rsp + 112;
                                                                                                                                                                    sub_140058520(a1, i2, v9);
                                                                                                                                                                    i3 = (__int64 *)v_70;
                                                                                                                                                                    i2 = (__int64 *)v_78;
                                                                                                                                                                    v9 = v_80;
                                                                                                                                                                } else {
                                                                                                                                                                }
                                                                                                                                                                *(__int64 *)ptr = (__int64)(2);
                                                                                                                                                                ptr->field_8 = i3;
                                                                                                                                                                ptr->field_10 = i2;
                                                                                                                                                                ptr->field_18 = v9;
                                                                                                                                                                result = 0x8000000000000003;
                                                                                                                                                                ptr->field_20 = result;
                                                                                                                                                                ptr->field_38 = result;
                                                                                                                                                                ptr->field_50 = result;
                                                                                                                                                                return sub_14005B1B7();
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                } else {
                                                                                                                                    a1 = rsp + 112;
                                                                                                                                    sub_14004F470(a1);
                                                                                                                                    i3 = 1;
                                                                                                                                    i2 = rsp + 480;
                                                                                                                                    sub_140062120(i2);
                                                                                                                                    i3 = (__int64 *)((__int64)i3 + (__int64)i);
                                                                                                                                    sub_140062190(i2, i, i3);
                                                                                                                                    i3 = (__int64 *)v_1e0;
                                                                                                                                    result = (__int64 *)v_1e8;
                                                                                                                                    v_40 = (__int64)result;
                                                                                                                                    v9 = v_1f0;
                                                                                                                                    i = (struct Struct_1_t *)v4;
                                                                                                                                    v11 = (__int64)dst;
                                                                                                                                    return v11;
                                                                                                                                }
                                                                                                                                v_78 = 8;
                                                                                                                                xmm0 = _mm_setzero_si128();
                                                                                                                                _mm_storeu_si128((__m128i *)&v_80, xmm0);
                                                                                                                                v_70 = 0;
                                                                                                                                a1 = rsp + 112;
                                                                                                                                sub_1400F8440(a1);
                                                                                                                                v11 = v_70;
                                                                                                                                i2 = (__int64 *)v_78;
                                                                                                                                *i2 = 3;
                                                                                                                                result = &off_140116C59;
                                                                                                                                arg_8 = (__int64)result;
                                                                                                                                arg_10 = 22;
                                                                                                                                xmm6 = _mm_loadu_si128((__m128i *)&v_88);
                                                                                                                                v9 = 1;
                                                                                                                                dst = 2;
                                                                                                                                i3 = (__int64 *)((__int64)(__int64)i3 << 1);
                                                                                                                                if (i3 != 0) {
                                                                                                                                    off_140108030();
                                                                                                                                    a3 = (size_t *)v_40;
                                                                                                                                    off_140108038(result, 0, a3);
                                                                                                                                }
                                                                                                                                i3 = (__int64 *)v11;
                                                                                                                                ptr->field_8 = dst;
                                                                                                                                ptr->field_10 = i3;
                                                                                                                                ptr->field_18 = i2;
                                                                                                                                ptr->field_20 = v9;
                                                                                                                                _mm_storeu_si128((__m128i *)(ptr + 40), xmm6);
                                                                                                                                return sub_14005B1B0();
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                        return (__int64)i3;
                                                                                                    }
                                                                                                    return (__int64)i3;
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    return (__int64)i3;
                                                                }
                                                                return (__int64)i3;
                                                            } else {
                                                                a1 = 0x8000000000000001;
                                                                *result = a1;
                                                                arg_8 = (__int64)i2;
                                                            }
                                                        } else {
                                                            if (((__int64)i2 & 3) == 0) {
                                                                a1 = (__int64)(__int64)i2 * 0x5C29;
                                                                a1 = __ROR2__(a1, 2);
                                                                if (a1 < 656) {
                                                                    a3 = 31;
                                                                    if (v9 <= 11) {
                                                                        a1 = (size_t *)v9;
                                                                        if ((!(((__int64)a2 >> v9) & 1))) {
                                                                            if (a1 == 2) {
                                                                                a1 = (__int64)(__int64)i2 * 0x5C29;
                                                                                a1 = __ROR2__(a1, 4);
                                                                                a3 = (a1 < 164) ? 1 : 0;
                                                                                a3 = (size_t *)((__int64)(__int64)a3 | 28);
                                                                            }
                                                                        } else {
                                                                        }
                                                                    }
                                                                } else {
                                                                    a1 = v9 - 2;
                                                                    a3 = 31;
                                                                    if (a1 < 10) {
                                                                        a1 = &off_14011E6D2;
                                                                        a3 = *(__int64 *)((__int64)a2 + (__int64)a1);
                                                                    }
                                                                }
                                                            } else {
                                                                a1 = v9 - 2;
                                                                if (a1 < 10) {
                                                                    a2 = a1;
                                                                    a1 = &off_14011E6C8;
                                                                    return (__int64)a1;
                                                                }
                                                            }
                                                            if (a3 >= result) {
                                                                v_30 = (__int64)result;
                                                                a3 = (size_t *)arg_10;
                                                                a2 = (size_t *)arg_18;
                                                                result = 8;
                                                                v_48 = 0;
                                                                v_50 = (int)a3;
                                                                v_60 = (int)a2;
                                                                if (a2 != 0) {
                                                                    a1 = *a3;
                                                                    --a2;
                                                                    ++a3;
                                                                    arg_10 = (__int64)a3;
                                                                    arg_18 = (__int64)a2;
                                                                    if (a1 != 32) {
                                                                        if (a1 != 116) {
                                                                            if (a1 != 84) {
                                                                                v6 = 0;
                                                                                v11 = 0;
                                                                                a2 = 0;
                                                                                i = 0;
                                                                                v5 = 0;
                                                                                a4 = 0;
                                                                                a3 = 0;
                                                                                v4 = 0;
                                                                                i3 = 0;
                                                                                dst = 0;
                                                                            } else {
                                                                                a1 = rsp + 112;
                                                                                sub_140064480(a1, v11, a3);
                                                                                a1 = (size_t *)v_70;
                                                                                i3 = (__int64 *)v_78;
                                                                                v_58 = (__int64)a1;
                                                                                if (a1 != 3) {
                                                                                    result = (__int64 *)v_80;
                                                                                    v5 = v_81;
                                                                                    a4 = (size_t *)v_82;
                                                                                    a3 = (size_t *)v_84;
                                                                                    dst = (__int64 *)v_86;
                                                                                    i = (struct Struct_1_t *)v_88;
                                                                                    a2 = (size_t *)v_8a;
                                                                                    v11 = v_8c;
                                                                                    a1 = (size_t *)v_90;
                                                                                    v_68 = (__int64)a1;
                                                                                    a1 = (size_t *)v_98;
                                                                                } else {
                                                                                    a3 = (size_t *)v_28;
                                                                                    a4 = (size_t *)arg_10;
                                                                                    v5 = arg_18;
                                                                                    if (v5 != 0) {
                                                                                        result = *a4;
                                                                                        a1 = v5 - 1;
                                                                                        a2 = a4 + 1;
                                                                                        arg_10 = (__int64)a2;
                                                                                        arg_18 = (__int64)a1;
                                                                                        result = (__int64 *)((__int64)(__int64)result & 223);
                                                                                        if (result != 90) {
                                                                                            xmm6 = _mm_setzero_si128();
                                                                                            _mm_storeu_si128((__m128i *)&v_9d8, xmm6);
                                                                                            v_9c0 = 1;
                                                                                            v_9c8 = 0;
                                                                                            v_9d0 = 8;
                                                                                            v_298 = (int)a4;
                                                                                            arg_10 = (__int64)a4;
                                                                                            arg_18 = v5;
                                                                                            v_2b0 = v5;
                                                                                            if (v5 != 0) {
                                                                                                a1 = (size_t *)v_298;
                                                                                                v4 = *a1;
                                                                                                result = (__int64 *)v_2b0;
                                                                                                --result;
                                                                                                ++a1;
                                                                                                a2 = (size_t *)v_28;
                                                                                                a2[2] = a1;
                                                                                                a2[3] = result;
                                                                                                if (v4 != 45) {
                                                                                                    if (v4 == 43) {
                                                                                                        a1 = rsp + 112;
                                                                                                        a2 = (size_t *)v_28;
                                                                                                        sub_140064DC0(a1, a2);
                                                                                                        a1 = (size_t *)v_70;
                                                                                                        v11 = v_78;
                                                                                                        if (a1 != 3) {
                                                                                                            result = (__int64 *)v_98;
                                                                                                            v_2f8 = (__int64)result;
                                                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_79);
                                                                                                            xmm1 = _mm_loadu_si128((__m128i *)&v_89);
                                                                                                            _mm_storeu_si128((__m128i *)&v_2e9, xmm1);
                                                                                                            _mm_storeu_si128((__m128i *)&v_2d9, xmm0);
                                                                                                        } else {
                                                                                                            result = (__int64 *)v_28;
                                                                                                            result = (__int64 *)arg_18;
                                                                                                            if (result != 0) {
                                                                                                                a1 = (size_t *)v_28;
                                                                                                                a1 = a1[2];
                                                                                                                if (*a1 != 58) {
                                                                                                                    xmm0 = _mm_setzero_si128();
                                                                                                                    _mm_storeu_si128((__m128i *)&v_2e8, xmm0);
                                                                                                                    result = rsp + 728;
                                                                                                                    v_2d8 = 0;
                                                                                                                    v_2df = 0;
                                                                                                                    v_2dd = 0;
                                                                                                                    v_2d9 = 0;
                                                                                                                    v_2e0 = 8;
                                                                                                                    a1 = (size_t *)v_2f8;
                                                                                                                    v_90 = (__int64)a1;
                                                                                                                    _mm_store_si128((__m128i *)&v_80, xmm0);
                                                                                                                    a1 = (size_t *)v_2d8;
                                                                                                                    v_70 = (__int64)a1;
                                                                                                                    a1 = (size_t *)v_2d9;
                                                                                                                    v_71 = (int)a1;
                                                                                                                    a1 = (size_t *)v_2dd;
                                                                                                                    v_75 = (int)a1;
                                                                                                                    a1 = (size_t *)v_2df;
                                                                                                                    v_77 = (int)a1;
                                                                                                                    a1 = (size_t *)v_2e0;
                                                                                                                    v_78 = (__int64)a1;
                                                                                                                    a1 = 2;
                                                                                                                    v_58 = (__int64)a1;
                                                                                                                } else {
                                                                                                                    ++a1;
                                                                                                                    --result;
                                                                                                                    a2 = (size_t *)v_28;
                                                                                                                    a2[2] = a1;
                                                                                                                    a2[3] = result;
                                                                                                                    a1 = rsp + 112;
                                                                                                                    sub_140064FE0(a1, a2);
                                                                                                                    a1 = (size_t *)v_70;
                                                                                                                    result = (__int64 *)v_78;
                                                                                                                    if (a1 != 3) {
                                                                                                                        v_cap = v_98;
                                                                                                                        v_2f8 = v_cap;
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&v_79);
                                                                                                                        xmm1 = _mm_loadu_si128((__m128i *)&v_89);
                                                                                                                        _mm_storeu_si128((__m128i *)&v_2e9, xmm1);
                                                                                                                        _mm_storeu_si128((__m128i *)&v_2d9, xmm0);
                                                                                                                        v11 = (__int64)result;
                                                                                                                        result = rsp + 728;
                                                                                                                        v_2d8 = v11;
                                                                                                                        a2 = (size_t *)v_2f8;
                                                                                                                        v_90 = (__int64)a2;
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&v_2e8);
                                                                                                                        _mm_store_si128((__m128i *)&v_80, xmm0);
                                                                                                                        a2 = (size_t *)v_2d8;
                                                                                                                        v_70 = (__int64)a2;
                                                                                                                        a2 = (size_t *)v_2d9;
                                                                                                                        v_71 = (int)a2;
                                                                                                                        a2 = (size_t *)v_2e1;
                                                                                                                        v_79 = (int)a2;
                                                                                                                        a2 = (size_t *)v_2e5;
                                                                                                                        v_7d = (int)a2;
                                                                                                                        a2 = (size_t *)v_2e7;
                                                                                                                        v_7f = (int)a2;
                                                                                                                        v_cap = 2;
                                                                                                                        if (a1 != 2) v_cap = a1;
                                                                                                                        v_58 = v_cap;
                                                                                                                        a1 = (size_t *)v_90;
                                                                                                                        arg_20 = (int)a1;
                                                                                                                        a1 = (size_t *)v_70;
                                                                                                                        v_cap = v_71;
                                                                                                                        a3 = (size_t *)v_75;
                                                                                                                        a4 = (size_t *)v_77;
                                                                                                                        v5 = v_78;
                                                                                                                        v6 = v_79;
                                                                                                                        v4 = (__int64 *)v_7d;
                                                                                                                        v11 = v_7f;
                                                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_80);
                                                                                                                        _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                                                                                                                        *result = a1;
                                                                                                                        arg_1 = v_cap;
                                                                                                                        arg_5 = (int)a3;
                                                                                                                        arg_7 = (int)a4;
                                                                                                                        arg_8 = v5;
                                                                                                                        arg_9 = v6;
                                                                                                                        arg_d = (__int64)v4;
                                                                                                                        arg_f = v11;
                                                                                                                        result = (__int64 *)v_2da;
                                                                                                                        result = (__int64 *)((__int64)(__int64)result << 16);
                                                                                                                        a1 = (size_t *)v_2d8;
                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                                                        dst = (__int64 *)v_2e0;
                                                                                                                        xmm6 = _mm_loadl_epi64((__m128i *)&v_2e8);
                                                                                                                        v11 = v_2ec;
                                                                                                                        result = (__int64 *)v_2f0;
                                                                                                                        v_68 = (__int64)result;
                                                                                                                        result = (__int64 *)v_2f8;
                                                                                                                        v_2a8 = (__int64)result;
                                                                                                                        result = (__int64 *)v_2db;
                                                                                                                        v_cap = (__int64)a1;
                                                                                                                        v4 = (__int64 *)a1;
                                                                                                                        v4 = (__int64 *)((__int64)(__int64)v4 << 8);
                                                                                                                        /* shrd $16, %(__int64)result, %(__int64)v4 */;
                                                                                                                        result = (__int64 *)v_2dc;
                                                                                                                        a1 = (size_t *)v4;
                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 << 8);
                                                                                                                        result = (__int64 *)((__int64)(__int64)result << 32);
                                                                                                                        v4 = (__int64 *)((__int64)(__int64)v4 >> 8);
                                                                                                                        i = (struct Struct_1_t *)a1;
                                                                                                                        i = (struct Struct_1_t *)((__int64)(__int64)i | v_cap);
                                                                                                                        i = (struct Struct_1_t *)((__int64)(__int64)i | (__int64)result);
                                                                                                                    } else {
                                                                                                                        v_2d8 = v11;
                                                                                                                        v_2d9 = 58;
                                                                                                                        a1 = (size_t *)v_2d8;
                                                                                                                        a2 = 1;
                                                                                                                        if (v4 != 43) {
                                                                                                                            if (v4 != 45) JUMPOUT(0x140061763);
                                                                                                                            a2 = 0xFFFF;
                                                                                                                        }
                                                                                                                        result = (__int64 *)((__int64)(__int64)result << 16);
                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                                                        result = (__int64 *)a1;
                                                                                                                        result = (__int64 *)((__int64)(__int64)result >> 16);
                                                                                                                        a1 = (size_t *)((__int64)(__int64)(__int64)a1 * 60);
                                                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                                                                                        v4 = (__int64 *)a2;
                                                                                                                        v4 = (__int64 *)((__int64)(__int64)(__int64)v4 * (__int64)a1);
                                                                                                                        result = v4 + 0x5A0;
                                                                                                                        if (result >= 0xB41) {
                                                                                                                            result = (__int64 *)v_28;
                                                                                                                            a1 = (size_t *)v_298;
                                                                                                                            arg_10 = (__int64)a1;
                                                                                                                            a1 = (size_t *)v_2b0;
                                                                                                                            arg_18 = (__int64)a1;
                                                                                                                            v_7d0 = 1;
                                                                                                                            v_7d8 = 0;
                                                                                                                            v_7e0 = 8;
                                                                                                                            _mm_storeu_si128((__m128i *)&v_7e8, xmm6);
                                                                                                                            a1 = rsp + 0x488;
                                                                                                                            a2 = rsp + 0x9C0;
                                                                                                                            a3 = rsp + 0x7D0;
                                                                                                                            sub_140055430(a1, a2, a3);
                                                                                                                            result = (__int64 *)v_488;
                                                                                                                            v_58 = (__int64)result;
                                                                                                                            v4 = (__int64 *)v_490;
                                                                                                                            dst = (__int64 *)v_498;
                                                                                                                            xmm6 = _mm_loadl_epi64((__m128i *)&v_4a0);
                                                                                                                            v11 = v_4a4;
                                                                                                                            result = (__int64 *)v_4a8;
                                                                                                                            v_68 = (__int64)result;
                                                                                                                            result = (__int64 *)v_4b0;
                                                                                                                            v_2a8 = (__int64)result;
                                                                                                                        } else {
                                                                                                                            i = 1;
                                                                                                                            result = 3;
                                                                                                                            v_58 = (__int64)result;
                                                                                                                            v4 = (__int64 *)((__int64)(__int64)v4 << 16);
                                                                                                                            v4 = (__int64 *)((__int64)v4 + (__int64)i);
                                                                                                                            a1 = rsp + 0x9C0;
                                                                                                                            sub_14004F470(a1, a2, a3, a4);
                                                                                                                            if (v_58 != 3) {
                                                                                                                                if (v_58 == 2) {
                                                                                                                                    v_2d0 = (__int64)v4;
                                                                                                                                    v_2d8 = (__int64)dst;
                                                                                                                                    v_2e0 = _mm_cvtsi128_si64(xmm6);
                                                                                                                                    v_2e4 = v11;
                                                                                                                                    result = (__int64 *)v_68;
                                                                                                                                    v_2e8 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_2a8;
                                                                                                                                    v_2f0 = (__int64)result;
                                                                                                                                    i = (struct Struct_1_t *)v_2e0;
                                                                                                                                    if (i == v4) {
                                                                                                                                        a1 = rsp + 720;
                                                                                                                                        sub_1400F8440(a1);
                                                                                                                                        v4 = (__int64 *)v_2d0;
                                                                                                                                        dst = (__int64 *)v_2d8;
                                                                                                                                    }
                                                                                                                                    result = i + (__int64)(__int64)i*2;
                                                                                                                                    v_0[(__int64)result] = 3;
                                                                                                                                    a1 = &off_140116D40;
                                                                                                                                    v_8[(__int64)result] = a1;
                                                                                                                                    v_10[(__int64)result] = 11;
                                                                                                                                    ++i;
                                                                                                                                    v_cap = (__int64)i;
                                                                                                                                    v_cap >>= 16;
                                                                                                                                    v11 = (__int64)i;
                                                                                                                                    v11 >>= 32;
                                                                                                                                    result = (__int64 *)v_2d8;
                                                                                                                                    a1 = (size_t *)v_2e8;
                                                                                                                                    v_68 = (__int64)a1;
                                                                                                                                    a1 = (size_t *)v_2f0;
                                                                                                                                } else {
                                                                                                                                    if (v_58 != 1) {
                                                                                                                                        i = _mm_cvtsi128_si32(xmm6);
                                                                                                                                        /* pextrw $1, %xmm6, %v_cap */;
                                                                                                                                        v5 = (__int64)result;
                                                                                                                                        v5 >>= 8;
                                                                                                                                        a4 = (size_t *)result;
                                                                                                                                        a4 = (size_t *)((__int64)(__int64)a4 >> 16);
                                                                                                                                        a3 = (size_t *)result;
                                                                                                                                        a3 = (size_t *)((__int64)(__int64)a3 >> 32);
                                                                                                                                        dst = result;
                                                                                                                                        dst = (__int64 *)((__int64)(__int64)dst >> 48);
                                                                                                                                        i3 = v4;
                                                                                                                                        if (v_58 != 1) {
                                                                                                                                            v5 <<= 8;
                                                                                                                                            v5 |= (__int64)result;
                                                                                                                                            v_580 = (__int64)i3;
                                                                                                                                            v_588 = v5;
                                                                                                                                            v_58a = (int)a4;
                                                                                                                                            a4 = (size_t *)v_584;
                                                                                                                                            result = (__int64 *)v_68;
                                                                                                                                            v5 = v_58;
                                                                                                                                            return v5;
                                                                                                                                        } else {
                                                                                                                                            v4 = 0xFFFFFFFF00000000;
                                                                                                                                            v4 = (__int64 *)((__int64)(__int64)v4 & (__int64)i3);
                                                                                                                                            v_70 = 1;
                                                                                                                                            i3 = (__int64 *)((__int64)(__int64)i3 | (__int64)v4);
                                                                                                                                            v_78 = (__int64)i3;
                                                                                                                                            v_80 = (__int64)result;
                                                                                                                                            v_81 = v5;
                                                                                                                                            v_82 = (int)a4;
                                                                                                                                            v_84 = (int)a3;
                                                                                                                                            v_86 = (__int64)dst;
                                                                                                                                            v_88 = (__int64)i;
                                                                                                                                            v_8a = v_cap;
                                                                                                                                            v_8c = v11;
                                                                                                                                            v_90 = v_68;
                                                                                                                                            v_98 = (int)a1;
                                                                                                                                            v11 = v_28;
                                                                                                                                            result = (__int64 *)v_50;
                                                                                                                                            arg_10 = (__int64)result;
                                                                                                                                            result = (__int64 *)v_60;
                                                                                                                                            arg_18 = (__int64)result;
                                                                                                                                            a1 = rsp + 112;
                                                                                                                                            sub_14004F470(a1, a2, a3, a4);
                                                                                                                                            i = 2;
                                                                                                                                            result = i2;
                                                                                                                                            a1 = (size_t *)v9;
                                                                                                                                            a1 = (size_t *)((__int64)(__int64)a1 << 16);
                                                                                                                                            a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                                                                            result = (__int64 *)v_30;
                                                                                                                                            result = (__int64 *)((__int64)(__int64)result << 24);
                                                                                                                                            result = (__int64 *)((__int64)(__int64)result | (__int64)a1);
                                                                                                                                            a1 = (size_t *)v_48;
                                                                                                                                            v_430 = (__int64)a1;
                                                                                                                                            v_434 = (__int64)i3;
                                                                                                                                            v_2c0 = (__int64)result;
                                                                                                                                            dst = 3;
                                                                                                                                            i2 = 1;
                                                                                                                                        }
                                                                                                                                        return (__int64)i2;
                                                                                                                                    } else {
                                                                                                                                        v_70 = (__int64)v4;
                                                                                                                                        v_78 = (__int64)dst;
                                                                                                                                        v_80 = _mm_cvtsi128_si64(xmm6);
                                                                                                                                        v_84 = v11;
                                                                                                                                        result = (__int64 *)v_68;
                                                                                                                                        v_88 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_2a8;
                                                                                                                                        v_90 = (__int64)result;
                                                                                                                                        i = (struct Struct_1_t *)v_80;
                                                                                                                                        if (i == v4) {
                                                                                                                                            a1 = rsp + 112;
                                                                                                                                            sub_1400F8440(a1);
                                                                                                                                            v4 = (__int64 *)v_70;
                                                                                                                                            dst = (__int64 *)v_78;
                                                                                                                                        }
                                                                                                                                        result = i + (__int64)(__int64)i*2;
                                                                                                                                        v_0[(__int64)result] = 3;
                                                                                                                                        a1 = &off_140116D40;
                                                                                                                                        v_8[(__int64)result] = a1;
                                                                                                                                        v_10[(__int64)result] = 11;
                                                                                                                                        ++i;
                                                                                                                                        result = (__int64 *)v_78;
                                                                                                                                        a1 = (size_t *)i;
                                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 >> 16);
                                                                                                                                        v_cap = (__int64)i;
                                                                                                                                        v_cap >>= 32;
                                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&v_88);
                                                                                                                                        v_70 = 1;
                                                                                                                                        v_78 = (__int64)v4;
                                                                                                                                        v_80 = (__int64)result;
                                                                                                                                        v_88 = (__int64)i;
                                                                                                                                        v_8a = (int)a1;
                                                                                                                                        v_8c = v_cap;
                                                                                                                                        _mm_storeu_si128((__m128i *)&v_90, xmm0);
                                                                                                                                        result = (__int64 *)v_28;
                                                                                                                                        a1 = (size_t *)v_298;
                                                                                                                                        arg_10 = (__int64)a1;
                                                                                                                                        a1 = (size_t *)v_2b0;
                                                                                                                                        arg_18 = (__int64)a1;
                                                                                                                                        a1 = rsp + 112;
                                                                                                                                        sub_14004F470(a1);
                                                                                                                                        i = 2;
                                                                                                                                        result = 1;
                                                                                                                                        v_48 = (__int64)result;
                                                                                                                                        v4 = 0;
                                                                                                                                        v11 = v_28;
                                                                                                                                    }
                                                                                                                                    return v11;
                                                                                                                                }
                                                                                                                                return v11;
                                                                                                                            } else {
                                                                                                                                if (i != 3) {
                                                                                                                                    v4 = (__int64 *)((__int64)(__int64)v4 >> 16);
                                                                                                                                    result = 1;
                                                                                                                                    v_48 = (__int64)result;
                                                                                                                                } else {
                                                                                                                                    i = 2;
                                                                                                                                    v_48 = 0;
                                                                                                                                }
                                                                                                                            }
                                                                                                                            return v_48;
                                                                                                                        }
                                                                                                                        return v_48;
                                                                                                                    }
                                                                                                                    return v_48;
                                                                                                                }
                                                                                                                return v_48;
                                                                                                            }
                                                                                                            return v_48;
                                                                                                        }
                                                                                                        return v_48;
                                                                                                    }
                                                                                                    return v_48;
                                                                                                }
                                                                                                return v_48;
                                                                                            }
                                                                                            return v_48;
                                                                                        } else {
                                                                                            i = 0;
                                                                                        }
                                                                                        return (__int64)i;
                                                                                    }
                                                                                    return (__int64)i;
                                                                                }
                                                                                return (__int64)i;
                                                                            }
                                                                            return (__int64)i;
                                                                        }
                                                                    }
                                                                    return (__int64)i;
                                                                }
                                                                return (__int64)i;
                                                            } else {
                                                                arg_10 = (__int64)i;
                                                                arg_18 = (__int64)v4;
                                                                sub_140064450(a1, a1, a3);
                                                                a1 = 0x8000000000000001;
                                                                *result = a1;
                                                                a1 = &off_1401159D0;
                                                                i3 = 0;
                                                                i = 0;
                                                                v5 = 2;
                                                                return v5;
                                                            }
                                                            return v5;
                                                        }
                                                        return v5;
                                                    }
                                                    a1 = 1;
                                                } else {
                                                }
                                            }
                                        } else {
                                            if (a2 == 0) JUMPOUT(0x14006175f);
                                            if (*i3 != 43) {
                                                a3 = 2;
                                                if (a2 >= 3) {
                                                    a1 = 0;
                                                    result = 0;
                                                    while (a2 != a1) {
                                                        a4 = *(__int64 *)((__int64)i3 + (__int64)a1);
                                                        a4 += 0xFFFFFFD0;
                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a3); /* unsigned; high half in a2 */;
                                                        if (!((0 /* overflow check on (a4 + 0xFFFFFFD0) */))) {
                                                            if (a4 <= 9) {
                                                                ++a1;
                                                                result = (__int64 *)((__int64)result + (__int64)a4);
                                                                a1 = 2;
                                                                v_70 = (__int64)a1;
                                                                result = &off_140116E40;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_140116C89;
                                                                a4 = &off_140115EA0;
                                                                a3 = rsp + 112;
                                                                v_cap = 22;
                                                                sub_1400F3B80(v_cap, a2, a3, a4);
                                                                v_70 = (__int64)result;
                                                                result = &off_140116E28;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_140116E10;
                                                                a4 = &off_140115EA0;
                                                                a3 = rsp + 112;
                                                                v_cap = 22;
                                                                sub_1400F3B80(v_cap, a2, a3, a4);
                                                                a1 = &off_1401168C8;
                                                                a3 = &off_140116980;
                                                                v_cap = 32;
                                                                sub_1400F37D0(v_cap, a2, a3);
                                                                v_cap = 16;
                                                                sub_1400F3340(8);
                                                                a1 = 1;
                                                            }
                                                        }
                                                        a1 = 0;
                                                        ++a1;
                                                        return (__int64)a1;
                                                    }
                                                } else {
                                                    return (__int64)a1;
                                                }
                                                return (__int64)a1;
                                            } else {
                                                ++i3;
                                                a3 = a2 - 1;
                                                a2 = a3;
                                                if ((a2 < 4)) {
                                                    return (__int64)a2;
                                                } else {
                                                    return (__int64)a2;
                                                }
                                                return (__int64)a2;
                                            }
                                            return (__int64)a2;
                                        }
                                        return (__int64)a2;
                                    }
                                }
                                return (__int64)a2;
                            }
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    }
                } else {
                    do {
                        v_70 = (__int64)a1;
                        result = &off_140116D10;
                        return (__int64)result;
                    } while (true);
                }
                return (__int64)result;
            }
        } else {
            if (a2 == 0) {
                a1 = 0;
            } else {
                if (*i3 != 43) {
                    result = 2;
                    if (a2 >= 3) {
                        a1 = 0;
                        v9 = 0;
                        while (a2 != a1) {
                            a4 = *(__int64 *)((__int64)i3 + (__int64)a1);
                            a4 += 0xFFFFFFD0;
                            result = (__int64 *)v9;
                            result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a3); /* unsigned; high half in a2 */;
                            if (!((0 /* overflow check on (a4 + 0xFFFFFFD0) */))) {
                                if (a4 <= 9) {
                                    v9 = (__int64)result;
                                    ++a1;
                                    v9 += (__int64)a4;
                                    a1 = 2;
                                    return (__int64)a1;
                                }
                            }
                            a1 = 0;
                            ++a1;
                            return (__int64)a1;
                        }
                    } else {
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                } else {
                    ++i3;
                    result = a2 - 1;
                    a2 = (size_t *)result;
                    if ((a2 < 4)) {
                        return (__int64)a2;
                    } else {
                        return (__int64)a2;
                    }
                    return (__int64)a2;
                }
                return (__int64)a2;
            }
        }
        return (__int64)a2;
    }
    return (__int64)result;
}