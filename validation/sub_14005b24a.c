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
__int64 sub_140061701();
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
extern __int64 off_140116D10;
extern __int64 off_140116C89;
extern __int64 off_140115EA0;
extern __int64 off_140116E28;
extern __int64 off_140116E10;
extern __int64 off_1401168C8;
extern __int64 off_140116980;

__int64 __fastcall sub_14005B24A(size_t *a1, size_t *a2) {
    __int64 rsp;
    int arg_1;
    __int64 arg_10;
    __int64 arg_18;
    int arg_20;
    int arg_4;
    __int64 arg_5;
    int arg_6;
    __int64 arg_7;
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
    __int64 v_298;
    __int64 v_2a8;
    int v_2b0;
    __int64 v_2c0;
    int v_2c2;
    __int64 v_2c4;
    __int64 v_2d0;
    __int64 v_2d8;
    int v_2d9;
    int v_2da;
    int v_2db;
    __int64 v_2dc;
    int v_2dd;
    __int64 v_2de;
    int v_2df;
    __int64 v_2e0;
    int v_2e1;
    __int64 v_2e2;
    int v_2e4;
    int v_2e5;
    __int64 v_2e6;
    int v_2e7;
    __int64 v_2e8;
    int v_2e9;
    int v_2ea;
    int v_2ec;
    __int64 v_2f0;
    __int64 v_2f8;
    __int64 v_30;
    __int64 v_38;
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
    __int64 v_50;
    int v_540;
    __int64 v_544;
    __int64 v_58;
    __int64 v_580;
    int v_584;
    int v_588;
    __int64 v_58a;
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
    __int64 v_7c;
    int v_7d;
    __int64 v_7d0;
    __int64 v_7d4;
    int v_7d8;
    __int64 v_7e;
    int v_7e0;
    int v_7e8;
    int v_7f;
    __int64 v_80;
    int v_81;
    __int64 v_82;
    __int64 v_84;
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
    __int64 v7;
    __int64 *i3;
    __int64 *dst;
    struct Struct_1_t *i;
    __int64 *i2;
    __int64 *v4;
    __int64 *i4;
    __int64 v11;
    __int64 v13;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm6;
    __int64 v8;
    __m128i xmm1;
    __int64 v_cap;
    struct Struct_2_t *ptr;

    result += *result;
    *a1 = *a1 + (__int64)i2;
    a1 = rsp + 112;
    a2 = rsp + 720;
    sub_140064210(a1, a2, v13);
    v7 = v_70;
    i3 = (__int64 *)v_78;
    dst = (__int64 *)v_80;
    v_28 = v13;
    v_40 = v11;
    v_38 = (__int64)i;
    if (v7 != 3) {
        i = (struct Struct_1_t *)v_88;
        result = (__int64 *)v_90;
        a1 = (size_t *)v_98;
    } else {
        if (dst == 1) {
            a1 = *i3;
            result = 1;
            if (a1 != 43) {
                dst = 1;
                if (a1 != 45) {
                    result = 0;
                    i2 = 0;
                    a1 = *(__int64 *)((__int64)i3 + (__int64)result);
                    a1 += 0xFFFFFFD0;
                    while (a1 <= 9) {
                        i2 = (__int64 *)((__int64)i2 + (__int64)i2);
                        i2 += (__int64)(__int64)i2*4;
                        i2 = (__int64 *)((__int64)i2 + (__int64)a1);
                        ++result;
                        v4 = (__int64 *)arg_18;
                        v7 = 1;
                        dst = 8;
                        if (v4 != 0) {
                            i = (struct Struct_1_t *)arg_10;
                            if (i->field_0 == 45) {
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
                                sub_140064210(a1, a2, v13);
                                i4 = (__int64 *)v_70;
                                i3 = (__int64 *)v_78;
                                a2 = (size_t *)v_80;
                                if (i4 == 3) {
                                    if (a2 == 1) {
                                        a2 = *i3;
                                        if (a2 != 43) {
                                            result = 1;
                                            if (a2 != 45) {
                                                a1 = 0;
                                                a2 = 0;
                                                v11 = *(__int64 *)((__int64)i3 + (__int64)a1);
                                                v11 += 0xFFFFFFD0;
                                                while (v11 <= 9) {
                                                    a2 = (size_t *)((__int64)a2 + (__int64)a2);
                                                    a2 += (__int64)(__int64)a2*4;
                                                    v11 += (__int64)a2;
                                                    ++a1;
                                                    a2 = (size_t *)v11;
                                                    result = v11 - 1;
                                                    if (result >= 12) {
                                                        arg_10 = (__int64)i;
                                                        arg_18 = (__int64)v4;
                                                        sub_14002EDF0(0, 48);
                                                        if (result != 0) {
                                                            a1 = 0x8000000000000001;
                                                            *result = a1;
                                                            arg_8 = v11;
                                                            v7 = 2;
                                                            a1 = &off_1401159D0;
                                                            i3 = 0;
                                                            i = 0;
                                                            a2 = (size_t *)i3;
                                                            a2 = (size_t *)((__int64)(__int64)a2 >> 32);
                                                            v_540 = (int)a2;
                                                            v_544 = (__int64)dst;
                                                            a2 = (size_t *)i;
                                                            a2 = (size_t *)((__int64)(__int64)a2 >> 16);
                                                            v13 = (__int64)i;
                                                            v13 >>= 32;
                                                            src = (__int64 *)v_540;
                                                            i4 = dst;
                                                            i4 = (__int64 *)((__int64)(__int64)i4 >> 32);
                                                            dst = (__int64 *)((__int64)(__int64)dst >> 48);
                                                            v_430 = (__int64)i3;
                                                            v_434 = (__int64)src;
                                                            v_2c0 = (__int64)a2;
                                                            v_2c2 = v13;
                                                            a2 = (size_t *)v_430;
                                                            src = (__int64 *)((__int64)(__int64)src >> 32);
                                                            if (v7 == 2) {
                                                                v_2d0 = (__int64)a2;
                                                                v_2d8 = (__int64)src;
                                                                v_2dc = (__int64)i4;
                                                                v_2de = (__int64)dst;
                                                                v_2e0 = (__int64)i;
                                                                i4 = (__int64 *)v_2c4;
                                                                v_2e6 = (__int64)i4;
                                                                i4 = (__int64 *)v_2c0;
                                                                v_2e2 = (__int64)i4;
                                                                v_2e8 = (__int64)result;
                                                                v_2f0 = (__int64)a1;
                                                                i2 = (__int64 *)v_2e0;
                                                                v13 = v_28;
                                                                if (i2 == a2) {
                                                                    a1 = rsp + 720;
                                                                    v4 = (__int64 *)v7;
                                                                    sub_1400F8440(a1, a2);
                                                                    v7 = (__int64)v4;
                                                                    a2 = (size_t *)v_2d0;
                                                                }
                                                                a1 = rsp + 728;
                                                                result = (__int64 *)v_2d8;
                                                                i4 = i2 + (__int64)(__int64)i2*2;
                                                                v_0[(__int64)i4] = 3;
                                                                src = &off_140116E58;
                                                                v_8[(__int64)i4] = src;
                                                                v_10[(__int64)i4] = 9;
                                                                ++i2;
                                                                v_2e0 = (__int64)i2;
                                                            } else {
                                                                v13 = v_28;
                                                                if (v7 != 1) {
                                                                    dst = 0;
                                                                } else {
                                                                    v_70 = (__int64)a2;
                                                                    v_78 = (__int64)src;
                                                                    v_7c = (__int64)i4;
                                                                    v_7e = (__int64)dst;
                                                                    v_80 = (__int64)i;
                                                                    i4 = (__int64 *)v_2c4;
                                                                    v_86 = (__int64)i4;
                                                                    i4 = (__int64 *)v_2c0;
                                                                    v_82 = (__int64)i4;
                                                                    v_88 = (__int64)result;
                                                                    v_90 = (__int64)a1;
                                                                    i2 = (__int64 *)v_80;
                                                                    if (i2 == a2) {
                                                                        a1 = rsp + 112;
                                                                        v4 = (__int64 *)v7;
                                                                        sub_1400F8440(a1);
                                                                        v7 = (__int64)v4;
                                                                        a2 = (size_t *)v_70;
                                                                    }
                                                                    a1 = rsp + 120;
                                                                    result = (__int64 *)v_78;
                                                                    i4 = i2 + (__int64)(__int64)i2*2;
                                                                    v_0[(__int64)i4] = 3;
                                                                    src = &off_140116E58;
                                                                    v_8[(__int64)i4] = src;
                                                                    v_10[(__int64)i4] = 9;
                                                                    ++i2;
                                                                    v_80 = (__int64)i2;
                                                                    i = (struct Struct_1_t *)result;
                                                                    i = (struct Struct_1_t *)((__int64)(__int64)i >> 32);
                                                                    v4 = result;
                                                                    v4 = (__int64 *)((__int64)(__int64)v4 >> 48);
                                                                    i4 = a1[1];
                                                                    v_2c4 = (__int64)i4;
                                                                    i4 = a1[1];
                                                                    v_2c0 = (__int64)i4;
                                                                    i3 = a1[2];
                                                                    v11 = a1[3];
                                                                    v_430 = (__int64)a2;
                                                                    v_438 = (__int64)result;
                                                                    dst = 2;
                                                                    if (v7 != 1) {
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
                                                                            v_210 = v11;
                                                                            v_1e0 = 8;
                                                                            if (dst == 1) {
                                                                                i2 = rsp + 488;
                                                                                v11 = v_38;
                                                                                arg_10 = v11;
                                                                                v4 = (__int64 *)v_40;
                                                                                arg_18 = (__int64)v4;
                                                                                a1 = rsp + 720;
                                                                                sub_140065200(a1, v13);
                                                                                if (v_2d0 == 8) {
                                                                                    if (v_2d8 == 1) {
                                                                                        i4 = rsp + 728;
                                                                                        a1 = rsp + 0x6B0;
                                                                                        sub_140055430(a1, i2, i4);
                                                                                        arg_10 = v11;
                                                                                        arg_18 = (__int64)v4;
                                                                                        a1 = rsp + 112;
                                                                                        sub_140065F70(a1, v13);
                                                                                        if (v_70 == 8) {
                                                                                            if (v_78 == 1) {
                                                                                                i4 = rsp + 120;
                                                                                                a1 = rsp + 0x880;
                                                                                                a2 = rsp + 0x6B0;
                                                                                                sub_140055430(a1, a2, i4);
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
                                                                        v_758 = v11;
                                                                        result = (__int64 *)v_38;
                                                                        arg_10 = (__int64)result;
                                                                        result = (__int64 *)v_40;
                                                                        arg_18 = (__int64)result;
                                                                        a1 = rsp + 112;
                                                                        sub_140064480(a1, v13, i4, src);
                                                                        v13 = v_70;
                                                                        if (v13 != 3) {
                                                                            result = rsp + 120;
                                                                            a1 = (size_t *)arg_8;
                                                                            v_490 = (int)a1;
                                                                            result = *result;
                                                                            v_488 = (__int64)result;
                                                                            i4 = (__int64 *)v_84;
                                                                            a2 = (size_t *)v_86;
                                                                            a1 = (size_t *)v_88;
                                                                            src = (__int64 *)v_8a;
                                                                            v_7d0 = (__int64)src;
                                                                            src = (__int64 *)v_8e;
                                                                            v_7d4 = (__int64)src;
                                                                            i3 = (__int64 *)v_90;
                                                                            v11 = v_98;
                                                                            if (v13 == 2) {
                                                                                dst = rsp + 738;
                                                                                v_2d0 = (__int64)result;
                                                                                src = (__int64 *)v_490;
                                                                                v_2d8 = (__int64)src;
                                                                                v_2dc = (__int64)i4;
                                                                                v_2de = (__int64)a2;
                                                                                v_2e0 = (__int64)a1;
                                                                                a1 = (size_t *)v_7d4;
                                                                                arg_4 = (int)a1;
                                                                                a1 = (size_t *)v_7d0;
                                                                                *dst = a1;
                                                                                v_2e8 = (__int64)i3;
                                                                                v_2f0 = v11;
                                                                                i2 = (__int64 *)v_2e0;
                                                                                if (i2 == result) {
                                                                                    a1 = rsp + 720;
                                                                                    sub_1400F8440(a1);
                                                                                    result = (__int64 *)v_2d0;
                                                                                }
                                                                                a1 = (size_t *)v_2d8;
                                                                                a2 = i2 + (__int64)(__int64)i2*2;
                                                                                v_0[(__int64)a2] = 3;
                                                                                i4 = &off_140116225;
                                                                                v_8[(__int64)a2] = i4;
                                                                                v_10[(__int64)a2] = 4;
                                                                                ++i2;
                                                                                v_2e0 = (__int64)i2;
                                                                            } else {
                                                                                if (v13 != 1) {
                                                                                    dst = 0;
                                                                                } else {
                                                                                    dst = rsp + 130;
                                                                                    v_70 = (__int64)result;
                                                                                    src = (__int64 *)v_490;
                                                                                    v_78 = (__int64)src;
                                                                                    v_7c = (__int64)i4;
                                                                                    v_7e = (__int64)a2;
                                                                                    v_80 = (__int64)a1;
                                                                                    a1 = (size_t *)v_7d4;
                                                                                    arg_4 = (int)a1;
                                                                                    a1 = (size_t *)v_7d0;
                                                                                    *dst = a1;
                                                                                    v_88 = (__int64)i3;
                                                                                    v_90 = v11;
                                                                                    i2 = (__int64 *)v_80;
                                                                                    if (i2 == result) {
                                                                                        a1 = rsp + 112;
                                                                                        sub_1400F8440(a1);
                                                                                        result = (__int64 *)v_70;
                                                                                    }
                                                                                    a1 = (size_t *)v_78;
                                                                                    a2 = i2 + (__int64)(__int64)i2*2;
                                                                                    v_0[(__int64)a2] = 3;
                                                                                    i4 = &off_140116225;
                                                                                    v_8[(__int64)a2] = i4;
                                                                                    v_10[(__int64)a2] = 4;
                                                                                    ++i2;
                                                                                    v_80 = (__int64)i2;
                                                                                    i = (struct Struct_1_t *)a1;
                                                                                    i = (struct Struct_1_t *)((__int64)(__int64)i >> 32);
                                                                                    v4 = (__int64 *)a1;
                                                                                    v4 = (__int64 *)((__int64)(__int64)v4 >> 48);
                                                                                    a2 = (size_t *)arg_4;
                                                                                    v_7d4 = (__int64)a2;
                                                                                    a2 = *dst;
                                                                                    v_7d0 = (__int64)a2;
                                                                                    i3 = (__int64 *)arg_6;
                                                                                    v11 = arg_e;
                                                                                    v_488 = (__int64)result;
                                                                                    v_490 = (int)a1;
                                                                                    dst = 2;
                                                                                    if (v13 != 1) {
                                                                                        v13 = v_28;
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
                                                                                        v_938 = v11;
                                                                                        a1 = rsp + 0x5F8;
                                                                                        a2 = rsp + 0x730;
                                                                                        i4 = rsp + 0x910;
                                                                                        sub_140055430(a1, a2, i4, src);
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
                                                                                        v11 = v_620;
                                                                                        v13 = v_28;
                                                                                    }
                                                                                    return v13;
                                                                                }
                                                                                return v13;
                                                                            }
                                                                            return v13;
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
                                                        v7 = 2;
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
                                                                sub_140064210(a1, a2, v13, src);
                                                                i4 = (__int64 *)v_70;
                                                                i3 = (__int64 *)v_78;
                                                                a2 = (size_t *)v_80;
                                                                if (i4 != 3) {
                                                                    i = (struct Struct_1_t *)v_88;
                                                                    result = (__int64 *)v_90;
                                                                    a1 = (size_t *)v_98;
                                                                    v7 = 2;
                                                                    if (i4 != 1) v7 = i4;
                                                                    dst = (__int64 *)a2;
                                                                } else {
                                                                    if (a2 == 1) {
                                                                        a2 = *i3;
                                                                        a1 = 1;
                                                                        if (a2 == 43) JUMPOUT(0x140061701);
                                                                        if (a2 == 45) {
                                                                            return sub_140061701();
                                                                        }
                                                                    } else {
                                                                        if (a2 == 0) JUMPOUT(0x14006175f);
                                                                        if (*i3 != 43) {
                                                                            i4 = 2;
                                                                            if (a2 >= 3) {
                                                                                a1 = 0;
                                                                                result = 0;
                                                                                while (a2 != a1) {
                                                                                    src = *(__int64 *)((__int64)i3 + (__int64)a1);
                                                                                    src += 0xFFFFFFD0;
                                                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)i4); /* unsigned; high half in a2 */;
                                                                                    if ((0 /* overflow check on (src + 0xFFFFFFD0) */)) JUMPOUT(0x1400616f8);
                                                                                    if (src > 9) JUMPOUT(0x1400616f8);
                                                                                    ++a1;
                                                                                    result = (__int64 *)((__int64)result + (__int64)src);
                                                                                    a1 = 2;
                                                                                    return sub_140061701();
                                                                                }
                                                                            } else {
                                                                                a1 = 0;
                                                                                a2 = 0;
                                                                                do {
                                                                                    result = *(__int64 *)((__int64)i3 + (__int64)a1);
                                                                                    result += 0xFFFFFFD0;
                                                                                    if (result > 9) JUMPOUT(0x14006168d);
                                                                                    a2 = (size_t *)((__int64)a2 + (__int64)a2);
                                                                                    a2 += (__int64)(__int64)a2*4;
                                                                                    result = (__int64 *)((__int64)result + (__int64)a2);
                                                                                    ++a1;
                                                                                    a2 = (size_t *)result;
                                                                                } while (i4 != a1);
                                                                            }
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
                                                                                    v13 = 0;
                                                                                    xmm0 = _mm_setzero_si128();
                                                                                    _mm_storeu_si128((__m128i *)&v_2e8, xmm0);
                                                                                    a1 = rsp + 112;
                                                                                    sub_14004F470(a1);
                                                                                    v_2d0 = 1;
                                                                                    v_2d8 = 0;
                                                                                    v_2e0 = 8;
                                                                                    a1 = rsp + 720;
                                                                                    sub_14004F470(a1);
                                                                                    if (v13 == 0) {
                                                                                        xmm0 = _mm_setzero_si128();
                                                                                        _mm_storeu_si128((__m128i *)&v_88, xmm0);
                                                                                        v_70 = 1;
                                                                                        v_78 = 0;
                                                                                        v_80 = 8;
                                                                                    } else {
                                                                                        result = (i->field_0 != 34) ? 1 : 0;
                                                                                        a1 = (v13 == 1) ? 1 : 0;
                                                                                        a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                        if (!((a1 != 0))) {
                                                                                            if (i->field_1 == 34) {
                                                                                                v4 = i + 2;
                                                                                                dst = (__int64 *)v13;
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
                                                                                                                                dst = (__int64 *)v13;
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
                                                                                                                                                    a1 = (v13 < 4) ? 1 : 0;
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
                                                                                                                                                        arg_18 = v13;
                                                                                                                                                        a1 = rsp + 720;
                                                                                                                                                        sub_14004F470(a1);
                                                                                                                                                        i3 = (__int64 *)v_1e0;
                                                                                                                                                        if (v13 != 0) {
                                                                                                                                                            if (i->field_0 == 34) {
                                                                                                                                                                if (v13 != 1) {
                                                                                                                                                                    if (i->field_1 == 34) {
                                                                                                                                                                        if (v13 != 2) {
                                                                                                                                                                            if (i->field_2 == 34) {
                                                                                                                                                                                if (v13 > 2) {
                                                                                                                                                                                    i += 3;
                                                                                                                                                                                    v13 -= 3;
                                                                                                                                                                                    result = (__int64 *)v_28;
                                                                                                                                                                                    arg_10 = (__int64)i;
                                                                                                                                                                                    arg_18 = v13;
                                                                                                                                                                                    i2 = (__int64 *)v_40;
                                                                                                                                                                                    result = i3;
                                                                                                                                                                                    result = (__int64 *)(-(__int64)result);
                                                                                                                                                                                    if ((0 /* overflow check on (-result) */)) {
                                                                                                                                                                                        a1 = rsp + 112;
                                                                                                                                                                                        sub_140058520(a1, i2, v11);
                                                                                                                                                                                        i3 = (__int64 *)v_70;
                                                                                                                                                                                        i2 = (__int64 *)v_78;
                                                                                                                                                                                        v11 = v_80;
                                                                                                                                                                                    } else {
                                                                                                                                                                                    }
                                                                                                                                                                                    *(__int64 *)ptr = (__int64)(2);
                                                                                                                                                                                    ptr->field_8 = i3;
                                                                                                                                                                                    ptr->field_10 = i2;
                                                                                                                                                                                    ptr->field_18 = v11;
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
                                                                                                                                                        v11 = v_1f0;
                                                                                                                                                        i = (struct Struct_1_t *)v4;
                                                                                                                                                        v13 = (__int64)dst;
                                                                                                                                                        return v13;
                                                                                                                                                    }
                                                                                                                                                    v_78 = 8;
                                                                                                                                                    xmm0 = _mm_setzero_si128();
                                                                                                                                                    _mm_storeu_si128((__m128i *)&v_80, xmm0);
                                                                                                                                                    v_70 = 0;
                                                                                                                                                    a1 = rsp + 112;
                                                                                                                                                    sub_1400F8440(a1);
                                                                                                                                                    v13 = v_70;
                                                                                                                                                    i2 = (__int64 *)v_78;
                                                                                                                                                    *i2 = 3;
                                                                                                                                                    result = &off_140116C59;
                                                                                                                                                    arg_8 = (__int64)result;
                                                                                                                                                    arg_10 = 22;
                                                                                                                                                    xmm6 = _mm_loadu_si128((__m128i *)&v_88);
                                                                                                                                                    v11 = 1;
                                                                                                                                                    dst = 2;
                                                                                                                                                    i3 = (__int64 *)((__int64)(__int64)i3 << 1);
                                                                                                                                                    if (i3 != 0) {
                                                                                                                                                        off_140108030();
                                                                                                                                                        i4 = (__int64 *)v_40;
                                                                                                                                                        off_140108038(result, 0, i4);
                                                                                                                                                    }
                                                                                                                                                    i3 = (__int64 *)v13;
                                                                                                                                                    ptr->field_8 = dst;
                                                                                                                                                    ptr->field_10 = i3;
                                                                                                                                                    ptr->field_18 = i2;
                                                                                                                                                    ptr->field_20 = v11;
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
                                                                                        i4 = 31;
                                                                                        if (v11 <= 11) {
                                                                                            a1 = (size_t *)v11;
                                                                                            if ((!(((__int64)a2 >> v11) & 1))) {
                                                                                                if (a1 == 2) {
                                                                                                    a1 = (__int64)(__int64)i2 * 0x5C29;
                                                                                                    a1 = __ROR2__(a1, 4);
                                                                                                    i4 = (a1 < 164) ? 1 : 0;
                                                                                                    i4 = (__int64 *)((__int64)(__int64)i4 | 28);
                                                                                                }
                                                                                            } else {
                                                                                            }
                                                                                        }
                                                                                    } else {
                                                                                        a1 = v11 - 2;
                                                                                        i4 = 31;
                                                                                        if (a1 < 10) {
                                                                                            a1 = &off_14011E6D2;
                                                                                            i4 = *(__int64 *)((__int64)a2 + (__int64)a1);
                                                                                        }
                                                                                    }
                                                                                } else {
                                                                                    a1 = v11 - 2;
                                                                                    if (a1 < 10) {
                                                                                        a2 = a1;
                                                                                        a1 = &off_14011E6C8;
                                                                                        return (__int64)a1;
                                                                                    }
                                                                                }
                                                                                if (i4 >= result) {
                                                                                    v_30 = (__int64)result;
                                                                                    i4 = (__int64 *)arg_10;
                                                                                    a2 = (size_t *)arg_18;
                                                                                    result = 8;
                                                                                    v_48 = 0;
                                                                                    v_50 = (__int64)i4;
                                                                                    v_60 = (int)a2;
                                                                                    if (a2 != 0) {
                                                                                        a1 = *i4;
                                                                                        --a2;
                                                                                        ++i4;
                                                                                        arg_10 = (__int64)i4;
                                                                                        arg_18 = (__int64)a2;
                                                                                        if (a1 != 32) {
                                                                                            if (a1 != 116) {
                                                                                                if (a1 != 84) {
                                                                                                    v8 = 0;
                                                                                                    v13 = 0;
                                                                                                    a2 = 0;
                                                                                                    i = 0;
                                                                                                    v7 = 0;
                                                                                                    src = 0;
                                                                                                    i4 = 0;
                                                                                                    v4 = 0;
                                                                                                    i3 = 0;
                                                                                                    dst = 0;
                                                                                                } else {
                                                                                                    a1 = rsp + 112;
                                                                                                    sub_140064480(a1, v13, i4);
                                                                                                    a1 = (size_t *)v_70;
                                                                                                    i3 = (__int64 *)v_78;
                                                                                                    v_58 = (__int64)a1;
                                                                                                    if (a1 != 3) {
                                                                                                        result = (__int64 *)v_80;
                                                                                                        v7 = v_81;
                                                                                                        src = (__int64 *)v_82;
                                                                                                        i4 = (__int64 *)v_84;
                                                                                                        dst = (__int64 *)v_86;
                                                                                                        i = (struct Struct_1_t *)v_88;
                                                                                                        a2 = (size_t *)v_8a;
                                                                                                        v13 = v_8c;
                                                                                                        a1 = (size_t *)v_90;
                                                                                                        v_68 = (__int64)a1;
                                                                                                        a1 = (size_t *)v_98;
                                                                                                    } else {
                                                                                                        i4 = (__int64 *)v_28;
                                                                                                        src = (__int64 *)arg_10;
                                                                                                        v7 = arg_18;
                                                                                                        if (v7 != 0) {
                                                                                                            result = *src;
                                                                                                            a1 = v7 - 1;
                                                                                                            a2 = src + 1;
                                                                                                            arg_10 = (__int64)a2;
                                                                                                            arg_18 = (__int64)a1;
                                                                                                            result = (__int64 *)((__int64)(__int64)result & 223);
                                                                                                            if (result != 90) {
                                                                                                                xmm6 = _mm_setzero_si128();
                                                                                                                _mm_storeu_si128((__m128i *)&v_9d8, xmm6);
                                                                                                                v_9c0 = 1;
                                                                                                                v_9c8 = 0;
                                                                                                                v_9d0 = 8;
                                                                                                                v_298 = (__int64)src;
                                                                                                                arg_10 = (__int64)src;
                                                                                                                arg_18 = v7;
                                                                                                                v_2b0 = v7;
                                                                                                                if (v7 != 0) {
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
                                                                                                                            v13 = v_78;
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
                                                                                                                                            v13 = (__int64)result;
                                                                                                                                            result = rsp + 728;
                                                                                                                                            v_2d8 = v13;
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
                                                                                                                                            i4 = (__int64 *)v_75;
                                                                                                                                            src = (__int64 *)v_77;
                                                                                                                                            v7 = v_78;
                                                                                                                                            v8 = v_79;
                                                                                                                                            v4 = (__int64 *)v_7d;
                                                                                                                                            v13 = v_7f;
                                                                                                                                            xmm0 = _mm_load_si128((__m128i *)&v_80);
                                                                                                                                            _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                                                                                                                                            *result = a1;
                                                                                                                                            arg_1 = v_cap;
                                                                                                                                            arg_5 = (__int64)i4;
                                                                                                                                            arg_7 = (__int64)src;
                                                                                                                                            arg_8 = v7;
                                                                                                                                            arg_9 = v8;
                                                                                                                                            arg_d = (__int64)v4;
                                                                                                                                            arg_f = v13;
                                                                                                                                            result = (__int64 *)v_2da;
                                                                                                                                            result = (__int64 *)((__int64)(__int64)result << 16);
                                                                                                                                            a1 = (size_t *)v_2d8;
                                                                                                                                            a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                                                                                                            dst = (__int64 *)v_2e0;
                                                                                                                                            xmm6 = _mm_loadl_epi64((__m128i *)&v_2e8);
                                                                                                                                            v13 = v_2ec;
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
                                                                                                                                            v_2d8 = v13;
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
                                                                                                                                                i4 = rsp + 0x7D0;
                                                                                                                                                sub_140055430(a1, a2, i4);
                                                                                                                                                result = (__int64 *)v_488;
                                                                                                                                                v_58 = (__int64)result;
                                                                                                                                                v4 = (__int64 *)v_490;
                                                                                                                                                dst = (__int64 *)v_498;
                                                                                                                                                xmm6 = _mm_loadl_epi64((__m128i *)&v_4a0);
                                                                                                                                                v13 = v_4a4;
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
                                                                                                                                                sub_14004F470(a1, a2, i4, src);
                                                                                                                                                if (v_58 != 3) {
                                                                                                                                                    if (v_58 == 2) {
                                                                                                                                                        v_2d0 = (__int64)v4;
                                                                                                                                                        v_2d8 = (__int64)dst;
                                                                                                                                                        v_2e0 = _mm_cvtsi128_si64(xmm6);
                                                                                                                                                        v_2e4 = v13;
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
                                                                                                                                                        v13 = (__int64)i;
                                                                                                                                                        v13 >>= 32;
                                                                                                                                                        result = (__int64 *)v_2d8;
                                                                                                                                                        a1 = (size_t *)v_2e8;
                                                                                                                                                        v_68 = (__int64)a1;
                                                                                                                                                        a1 = (size_t *)v_2f0;
                                                                                                                                                    } else {
                                                                                                                                                        if (v_58 != 1) {
                                                                                                                                                            i = _mm_cvtsi128_si32(xmm6);
                                                                                                                                                            /* pextrw $1, %xmm6, %v_cap */;
                                                                                                                                                            v7 = (__int64)result;
                                                                                                                                                            v7 >>= 8;
                                                                                                                                                            src = result;
                                                                                                                                                            src = (__int64 *)((__int64)(__int64)src >> 16);
                                                                                                                                                            i4 = result;
                                                                                                                                                            i4 = (__int64 *)((__int64)(__int64)i4 >> 32);
                                                                                                                                                            dst = result;
                                                                                                                                                            dst = (__int64 *)((__int64)(__int64)dst >> 48);
                                                                                                                                                            i3 = v4;
                                                                                                                                                            if (v_58 != 1) {
                                                                                                                                                                v7 <<= 8;
                                                                                                                                                                v7 |= (__int64)result;
                                                                                                                                                                v_580 = (__int64)i3;
                                                                                                                                                                v_588 = v7;
                                                                                                                                                                v_58a = (__int64)src;
                                                                                                                                                                src = (__int64 *)v_584;
                                                                                                                                                                result = (__int64 *)v_68;
                                                                                                                                                                v7 = v_58;
                                                                                                                                                                return v7;
                                                                                                                                                            } else {
                                                                                                                                                                v4 = 0xFFFFFFFF00000000;
                                                                                                                                                                v4 = (__int64 *)((__int64)(__int64)v4 & (__int64)i3);
                                                                                                                                                                v_70 = 1;
                                                                                                                                                                i3 = (__int64 *)((__int64)(__int64)i3 | (__int64)v4);
                                                                                                                                                                v_78 = (__int64)i3;
                                                                                                                                                                v_80 = (__int64)result;
                                                                                                                                                                v_81 = v7;
                                                                                                                                                                v_82 = (__int64)src;
                                                                                                                                                                v_84 = (__int64)i4;
                                                                                                                                                                v_86 = (__int64)dst;
                                                                                                                                                                v_88 = (__int64)i;
                                                                                                                                                                v_8a = v_cap;
                                                                                                                                                                v_8c = v13;
                                                                                                                                                                v_90 = v_68;
                                                                                                                                                                v_98 = (int)a1;
                                                                                                                                                                v13 = v_28;
                                                                                                                                                                result = (__int64 *)v_50;
                                                                                                                                                                arg_10 = (__int64)result;
                                                                                                                                                                result = (__int64 *)v_60;
                                                                                                                                                                arg_18 = (__int64)result;
                                                                                                                                                                a1 = rsp + 112;
                                                                                                                                                                sub_14004F470(a1, a2, i4, src);
                                                                                                                                                                i = 2;
                                                                                                                                                                result = i2;
                                                                                                                                                                a1 = (size_t *)v11;
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
                                                                                                                                                            v_84 = v13;
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
                                                                                                                                                            v13 = v_28;
                                                                                                                                                        }
                                                                                                                                                        return v13;
                                                                                                                                                    }
                                                                                                                                                    return v13;
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
                                                                                    sub_140064450(a1, a1, i4);
                                                                                    a1 = 0x8000000000000001;
                                                                                    *result = a1;
                                                                                    a1 = &off_1401159D0;
                                                                                    i3 = 0;
                                                                                    i = 0;
                                                                                    v7 = 2;
                                                                                    return v7;
                                                                                }
                                                                                return v7;
                                                                            }
                                                                            return v7;
                                                                        } else {
                                                                            ++i3;
                                                                            i4 = a2 - 1;
                                                                            a2 = (size_t *)i4;
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
                                                v_70 = (__int64)a1;
                                                result = &off_140116D10;
                                                v_20 = (__int64)result;
                                                a1 = &off_140116C89;
                                                src = &off_140115EA0;
                                                i4 = rsp + 112;
                                                v_cap = 22;
                                                sub_1400F3B80(v_cap, a2, i4, src);
                                                result = 0;
                                            }
                                            a1 = 1;
                                        }
                                    } else {
                                        if (a2 == 0) JUMPOUT(0x140061711);
                                        if (*i3 != 43) {
                                            result = 2;
                                            if (a2 >= 3) {
                                                a1 = 0;
                                                v11 = 0;
                                                while (a2 != a1) {
                                                    src = *(__int64 *)((__int64)i3 + (__int64)a1);
                                                    src += 0xFFFFFFD0;
                                                    result = (__int64 *)v11;
                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)i4); /* unsigned; high half in a2 */;
                                                    if (!((0 /* overflow check on (src + 0xFFFFFFD0) */))) {
                                                        if (src <= 9) {
                                                            v11 = (__int64)result;
                                                            ++a1;
                                                            v11 += (__int64)src;
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
                                    return (__int64)a2;
                                }
                                return (__int64)a2;
                            }
                        }
                        return (__int64)a2;
                    }
                    result = 1;
                } else {
                }
            }
        } else {
            if (dst != 0) {
                if (*i3 != 43) {
                    if (dst >= 5) {
                        a1 = 0;
                        i2 = 0;
                        while (dst != a1) {
                            src = *(__int64 *)((__int64)i3 + (__int64)a1);
                            src += 0xFFFFFFD0;
                            result = i2;
                            result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)i4); /* unsigned; high half in a2 */;
                            if (!((0 /* overflow check on (src + 0xFFFFFFD0) */))) {
                                if (src <= 9) {
                                    i2 = result;
                                    ++a1;
                                    i2 = (__int64 *)((__int64)i2 + (__int64)src);
                                    result = 2;
                                    do {
                                        v_70 = (__int64)result;
                                        result = &off_140116E28;
                                        v_20 = (__int64)result;
                                        a1 = &off_140116E10;
                                        src = &off_140115EA0;
                                        i4 = rsp + 112;
                                        v_cap = 22;
                                        sub_1400F3B80(v_cap, a2, i4, src);
                                        a1 = &off_1401168C8;
                                        i4 = &off_140116980;
                                        v_cap = 32;
                                        sub_1400F37D0(v_cap, a2, i4);
                                        v_cap = 16;
                                        sub_1400F3340(8);
                                        return v_cap;
                                    } while (true);
                                }
                            }
                            result = 0;
                            ++result;
                            return (__int64)result;
                        }
                    } else {
                        return (__int64)result;
                    }
                    return (__int64)result;
                } else {
                    ++i3;
                    --dst;
                    if ((dst < 0)) {
                        return (__int64)dst;
                    } else {
                        return (__int64)dst;
                    }
                    return (__int64)dst;
                }
                return (__int64)dst;
            }
            return (__int64)dst;
        }
        return (__int64)dst;
    }
    return (__int64)result;
}