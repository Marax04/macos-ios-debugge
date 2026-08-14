// inferred from 5 accesses on `i`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[250];
    __int64 field_112; // offset 274
    char _pad_112[78];
    __int16 field_168; // offset 360
    __int64 field_16A; // offset 362
};

// inferred from 3 accesses on `i2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[338];
    __int64 field_16A; // offset 362
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 4 accesses on `i3`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3B20();
__int64 sub_1400EF750();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400EE456();
__int64 sub_1400EB6FB();
__int64 sub_1400F27F0();
__int64 sub_1400F27FC();
__int64 sub_1400F27F6();
__int64 sub_1400F1090();
__int64 sub_1400F1290();
__int64 sub_1400EF530();
__int64 sub_140106EC0();
__int64 sub_14000EFE0();
__int64 sub_14006B9D0();
__int64 sub_14006C940();
__int64 sub_140106960();
__int64 sub_1400F9B90();
extern __int64 off_14011D608;
extern __int64 off_14011D680;
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14011D5E0;
extern __int64 off_14011D5D0;
extern __int64 off_140108850;
extern __int64 off_140018400;
extern __int64 off_14011D6A8;

__int64 __fastcall sub_1400EB70F(size_t *a1, int *a2, int *a3, size_t *a4) {
    __int64 rsp;
    __int64 arg_10;
    __int64 arg_112;
    __int64 arg_120;
    __int64 arg_128;
    int arg_168;
    __int64 arg_16a;
    __int64 arg_18;
    int arg_210;
    __int64 arg_8;
    int v_100;
    int v_108;
    int v_118;
    __int64 v_140;
    int v_148;
    int i4;
    __int64 v_158;
    int v_168;
    __int64 v_190;
    __int64 v_1a0;
    __int64 v_1a8;
    __int64 v_20;
    __int64 v_28;
    int v_2b8;
    int v_2c0;
    __int64 v_2c8;
    __int64 v_2f8;
    __int64 v_30;
    int v_300;
    __int64 v_308;
    int v_310;
    __int64 v_320;
    __int64 v_330;
    __int64 v_338;
    int v_340;
    int i5;
    __int64 v_44;
    __int64 v_45;
    __int64 v_46;
    __int64 v_47;
    __int64 v_48;
    __int64 v_49;
    __int64 v_4a;
    __int64 v_4b;
    __int64 v_4c;
    __int64 v_4d;
    __int64 v_4e;
    __int64 v_4f;
    __int64 v_50;
    __int64 v_51;
    __int64 v_52;
    __int64 v_53;
    __int64 v_54;
    __int64 v_55;
    __int64 v_56;
    __int64 v_57;
    __int64 v_58;
    __int64 v_59;
    __int64 v_5a;
    __int64 v_5b;
    __int64 v_5b0;
    int v_5b1;
    int v_5b2;
    int v_5b3;
    int v_5b4;
    int v_5b5;
    int v_5b6;
    int v_5b7;
    int v_5b8;
    int v_5b9;
    int v_5ba;
    int v_5bb;
    int v_5bc;
    int v_5bd;
    int v_5be;
    int v_5bf;
    __int64 v_5c;
    __int64 v_5c0;
    int v_5c1;
    int v_5c2;
    int v_5c3;
    int v_5c4;
    int v_5c5;
    int v_5c6;
    int v_5c7;
    int v_5c8;
    int v_5c9;
    int v_5ca;
    int v_5cb;
    int v_5cc;
    int v_5cd;
    int v_5ce;
    int v_5cf;
    __int64 v_5d;
    int v_5d0;
    int v_5d8;
    __int64 v_5e;
    int v_5e0;
    int v_5e8;
    __int64 v_5f;
    int v_5f0;
    int v_5f8;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    int v_7b;
    int v_8;
    __int64 v_80;
    __int64 v_88;
    __int64 v_90;
    __int64 v_98;
    __int64 v_99;
    __int64 v_9a;
    __int64 v_9b;
    __int64 v_9c;
    __int64 v_9d;
    __int64 v_9e;
    __int64 v_9f;
    __int64 v_a0;
    __int64 v_a1;
    __int64 v_a2;
    __int64 v_a3;
    __int64 v_a4;
    __int64 v_a5;
    __int64 v_a6;
    __int64 v_a7;
    __int64 v_a8;
    __int64 v_a9;
    __int64 v_aa;
    __int64 v_ab;
    __int64 v_ac;
    __int64 v_ad;
    __int64 v_ae;
    __int64 v_af;
    __int64 v_b0;
    __int64 v_b1;
    __int64 v_b2;
    __int64 v_b3;
    __int64 v_b8;
    __int64 v_bf8;
    __int64 v_c0;
    __int64 v_c8;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_f8;
    __int64 *arg_110;
    __int64 *arg_114;
    __int64 *arg_170;
    __int64 *arg_178;
    __int64 *arg_180;
    __int64 *arg_188;
    __int64 *v_0;
    __int64 *v_110;
    __int64 *v_114;
    __int64 *v_120;
    __int64 *v_128;
    __int64 *v_130;
    __int64 *i6;
    __int64 *v_170;
    __int64 *v_178;
    __int64 *v_180;
    __int64 *v_188;
    struct Struct_3_t *ptr;
    struct Struct_2_t *i2;
    __int64 *i7;
    __int64 i8;
    __m128i xmm1;
    __int64 *result;
    struct Struct_1_t *i;
    struct Struct_4_t *i3;
    __int64 *i9;
    __int64 *i10;
    __int64 *i12;
    __int64 *i11;
    __m128i xmm0;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm8;
    __m128i xmm9;

    v_7b = __ROL1__(v_7b, a1);
    *(__int64 *)((__int64)i + (__int64)i7 + 76) = *(__int64 *)((__int64)i + (__int64)i7 + 76) << (__int64)a1;
    v_70 = (__int64)i;
    ptr = __builtin_ctz(i8);
    ptr = (struct Struct_3_t *)((__int64)ptr + (__int64)a2);
    ptr = (struct Struct_3_t *)((__int64)(__int64)ptr & (__int64)a3);
    i2 =  + (__int64)(__int64)ptr*8;
    i7 = result;
    i7 = (__int64 *)((__int64)i7 - (__int64)i2);
    while (a1 != v_8) {
        ptr = i8 - 1;
        ptr = (struct Struct_3_t *)((__int64)(__int64)ptr & i8);
        i8 = (__int64)ptr;
        ptr = (struct Struct_3_t *)v_70;
        xmm1 = _mm_cmpeq_epi8(xmm1, xmm6);
        i8 = _mm_movemask_epi8(xmm1);
        if (i8 != 0) {
            a1 = &off_14011D608;
            a3 = &off_14011D680;
            sub_1400F3B20(a1, 22, a3);
            result = (__int64 *)i3;
            result = (__int64 *)((__int64)result - (__int64)i);
            result = (__int64 *)((__int64)(__int64)result >> 3);
            a1 = 0x239E0D5B450239E1;
            result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
            if (i3 != i) {
                i2 = (struct Struct_2_t *)a2;
                i2 = (struct Struct_2_t *)((__int64)(__int64)i2 >> 4);
                do {
                    sub_1400EF750(i);
                    i += 920;
                    --i2;
                } while ((i2 != 0));
            }
            if (v_20 != 0) {
                ((__int64 (*)())off_140108030)();
                a3 = (int *)v_80;
                ((__int64 (*)())off_140108038)(result, 0, a3);
            }
            i2 = (struct Struct_2_t *)v_120;
            if (i2 >= result) {
                sub_1400F3360(0x1D77B654B82C34);
            }
            a1 = (size_t *)v_110;
            i3 = (struct Struct_4_t *)v_118;
            if (i2 == 0) JUMPOUT(0x1400eeb01);
            v_80 = (__int64)a1;
            i7 = (__int64)(__int64)i2 * 0x458;
            sub_14002EDF0(0, i7);
            v_c8 = (__int64)result;
            if (result == 0) JUMPOUT(0x1400ef504);
            v_70 = (__int64)i2;
            result = i2 + (__int64)(__int64)i2*4;
            result = (__int64 *)((__int64)(__int64)result << 7);
            result = (__int64 *)((__int64)result + (__int64)i3);
            v_20 = (__int64)result;
            i9 = 0;
            i10 = off_140108030;
            i7 = off_140108038;
            v_90 = (__int64)i3;
            return sub_1400EE456();
        } else {
            a2 = (int *)((__int64)a2 + (__int64)a4);
            a2 += 16;
            a4 += 16;
            return sub_1400EB6FB();
        }
    }
    v_90 = (__int64)i10;
    ptr = (struct Struct_3_t *)(-(__int64)ptr);
    a1 = (size_t *)v_60;
    i10 = a1[2];
    if (i10 >= 0) {
        result = *(result + (__int64)(__int64)ptr*8 - 4);
        v_c0 = (__int64)result;
        i2 = (struct Struct_2_t *)arg_8;
        if (i10 == 0) {
            i7 = 1;
        } else {
            sub_14002EDF0(0, i10, a3, a4);
            if (result == 0) JUMPOUT(0x1400ef4eb);
            i7 = result;
        }
        sub_1400F27F0(i7, i2, i10);
        result = v_128;
        v_80 = (__int64)i11;
        v_78 = (__int64)i3;
        if (result == 0) {
            sub_14002EDF0(0, 288);
            if (result == 0) JUMPOUT(0x1400ef40c);
            *result = 0;
            v_128 = result;
            v_130 = 0;
            arg_112 = 1;
            arg_8 = (__int64)i10;
            arg_10 = (__int64)i7;
            arg_18 = (__int64)i10;
            a1 = (size_t *)i5;
            arg_114 = (__int64 *)a1;
        } else {
            i = (struct Struct_1_t *)result;
            v_30 = (__int64)i2;
            i9 = v_130;
            do {
                a1 = i + 8;
                v_20 = (__int64)i;
                result = i->field_112;
                v_28 = (__int64)result;
                result =  + (__int64)(__int64)result*8;
                i12 = result + (__int64)(__int64)result*2;
                i3 = -1;
                i2 = (struct Struct_2_t *)a1;
                while (i12 != 0) {
                    i = a1 + 24;
                    a2 = (int *)arg_8;
                    a3 = a1[2];
                    i11 = i10;
                    i11 = (__int64 *)((__int64)i11 - (__int64)a3);
                    if (i11 < 0) a3 = i10;
                    sub_1400F27FC(i7, a2, a3);
                    if (result != 0) i11 = result;
                    a1 = (i11 < 0) ? 1 : 0;
                    result = (i11 > 0) ? 1 : 0;
                    result = (__int64 *)((__int64)result - (__int64)a1);
                    i12 -= 24;
                    ++i3;
                    if (result != 0) {
                        i12 = (__int64 *)v_28;
                        --i9;
                        i11 = (__int64 *)v_80;
                        i = (struct Struct_1_t *)v_20;
                        if (!((i9 < 0))) {
                            i = *(__int64 *)(i + (__int64)(__int64)i3*8 + 288);
                        }
                        if (i12 >= 11) {
                            sub_14002EDF0(0, 288);
                            i12 = result;
                            if (i3 >= 5) {
                                i2 = (struct Struct_2_t *)v_30;
                                if ((i12 == 0)) {
                                    if (i12 == 0) JUMPOUT(0x1400ef40c);
                                    *i12 = 0;
                                    i = (struct Struct_1_t *)v_20;
                                    i9 = i->field_112;
                                    i9 -= 6;
                                    arg_112 = (__int64)i9;
                                    if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                    i3 = 5;
                                    result = 136;
                                    v_28 = (__int64)result;
                                    v_60 = 5;
                                    result = 282;
                                    v_88 = (__int64)result;
                                    a2 = 152;
                                    result = 281;
                                    a1 = 128;
                                    v_b8 = (__int64)a1;
                                    v_68 = (__int64)i;
                                } else {
                                    if (i3 != 6) {
                                        if (i12 == 0) JUMPOUT(0x1400ef40c);
                                        *i12 = 0;
                                        result = (__int64 *)v_20;
                                        i9 = (__int64 *)arg_112;
                                        i9 -= 7;
                                        arg_112 = (__int64)i9;
                                        if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                        i3 -= 7;
                                        result = 160;
                                        v_28 = (__int64)result;
                                        v_60 = 6;
                                        result = 283;
                                        v_88 = (__int64)result;
                                        a2 = 176;
                                        result = 282;
                                        a1 = 152;
                                        v_b8 = (__int64)a1;
                                        v_68 = (__int64)i12;
                                    } else {
                                        if (i12 == 0) JUMPOUT(0x1400ef40c);
                                        *i12 = 0;
                                        result = (__int64 *)v_20;
                                        i9 = (__int64 *)arg_112;
                                        i9 -= 6;
                                        arg_112 = (__int64)i9;
                                        if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                        result = 136;
                                        v_28 = (__int64)result;
                                        v_60 = 5;
                                        result = 282;
                                        v_88 = (__int64)result;
                                        a2 = 152;
                                        result = 281;
                                        a1 = 128;
                                        v_b8 = (__int64)a1;
                                        v_68 = (__int64)i12;
                                        i3 = 0;
                                    }
                                    i = (struct Struct_1_t *)v_20;
                                }
                                result = *(__int64 *)((__int64)i + (__int64)result);
                                v_30 = (__int64)result;
                                a1 = i12 + 8;
                                a2 = (int *)((__int64)a2 + (__int64)i);
                                result =  + (__int64)(__int64)i9*8;
                                a3 = result + (__int64)(__int64)result*2;
                                sub_1400F27F0(a1, a2, a3);
                                a1 = (size_t *)i12;
                                a1 += 276;
                                a2 = (int *)v_88;
                                a2 = (int *)((__int64)a2 + (__int64)i);
                                sub_1400F27F0(a1, a2, i9);
                                result = (__int64 *)v_60;
                                i->field_112 = result;
                                result = (__int64 *)v_b8;
                                a3 = *(__int64 *)((__int64)i + (__int64)result);
                                result = (__int64 *)v_28;
                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)i + (__int64)result));
                                _mm_store_si128((__m128i *)&v_5b0, xmm0);
                                i = (struct Struct_1_t *)v_68;
                                i9 = i->field_112;
                                a4 = (size_t *)i9;
                                result =  + (__int64)(__int64)i3*2;
                                result = (__int64 *)((__int64)result + (__int64)i3);
                                a2 = i + (__int64)(__int64)result*8;
                                a2 += 8;
                                a4 = (size_t *)((__int64)a4 - (__int64)i3);
                                if ((a4 <= 0)) {
                                    *a2 = i10;
                                    arg_8 = (__int64)i7;
                                    a2[2] = i10;
                                } else {
                                    result = i + 8;
                                    v_68 = (__int64)i;
                                    a1 =  + (__int64)(__int64)i3*2 + 3;
                                    a1 = (size_t *)((__int64)a1 + (__int64)i3);
                                    a1 = result + (__int64)(__int64)a1*8;
                                    result =  + (__int64)(__int64)a4*8;
                                    v_28 = (__int64)a3;
                                    a3 = result + (__int64)(__int64)result*2;
                                    v_60 = (__int64)a4;
                                    i = (struct Struct_1_t *)a2;
                                    sub_1400F27F6(a1, a2, a3, a4);
                                    *(__int64 *)i = (__int64)(i10);
                                    i->field_8 = i7;
                                    i->field_10 = i10;
                                    result = (__int64 *)v_68;
                                    a2 = (__int64)result + (__int64)i3 + 276;
                                    result = (__int64 *)v_68;
                                    a1 = (__int64)result + (__int64)i3;
                                    a1 += 277;
                                    a3 = (int *)v_60;
                                    sub_1400F27F6(a1, a2, a3);
                                    i = (struct Struct_1_t *)v_68;
                                    a3 = (int *)v_28;
                                }
                                result = (__int64 *)i5;
                                ++i9;
                                *(__int64 *)((__int64)i + (__int64)i3 + 276) = result;
                                i->field_112 = i9;
                                xmm0 = _mm_load_si128((__m128i *)&v_5b0);
                                _mm_store_si128((__m128i *)&v_330, xmm0);
                                result = (__int64 *)a3;
                                result = (__int64 *)(-(__int64)result);
                                i9 = off_140108030;
                                if ((0 /* overflow check on (-result) */)) {
                                    xmm0 = _mm_load_si128((__m128i *)&v_330);
                                    _mm_store_si128((__m128i *)&v_d0, xmm0);
                                    result = (__int64 *)v_20;
                                    i7 = *result;
                                    i3 = (struct Struct_4_t *)v_78;
                                    if (i7 == 0) {
                                        i9 = 0;
                                    } else {
                                        result = 0;
                                        a2 = (int *)i12;
                                        i9 = 0;
                                        do {
                                            if (i9 != result) JUMPOUT(0x1400ef439);
                                            a1 = (size_t *)v_20;
                                            i9 = a1[34];
                                            ptr = (struct Struct_3_t *)i9;
                                            i = (struct Struct_1_t *)arg_112;
                                            v_28 = (__int64)a3;
                                            v_68 = (__int64)a2;
                                            if (i >= 11) {
                                                ++result;
                                                a1 = 4;
                                                if (i9 < 5) {
                                                    v_330 = (__int64)i7;
                                                    v_338 = (__int64)result;
                                                    v_340 = (int)a1;
                                                    a1 = rsp + 0x5B0;
                                                    a2 = rsp + 816;
                                                    v_20 = (__int64)ptr;
                                                    sub_1400F1090(a1, a2, a3);
                                                    ptr = (struct Struct_3_t *)v_20;
                                                    i12 = (__int64 *)v_5d0;
                                                    i7 = (__int64 *)arg_112;
                                                    i3 = ptr + 1;
                                                    result = ptr + (__int64)(__int64)ptr*2;
                                                    i = i12 + (__int64)(__int64)result*8;
                                                    i += 8;
                                                    if (i9 >= i7) {
                                                        result = (__int64 *)v_28;
                                                        *(__int64 *)i = (__int64)(result);
                                                        xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                        _mm_storeu_si128((__m128i *)(i + 8), xmm0);
                                                        result = (__int64 *)v_30;
                                                        *(__int64 *)((__int64)i12 + (__int64)ptr + 276) = result;
                                                        i9 = off_140108030;
                                                        a2 = (int *)v_68;
                                                        a1 = i7 + 1;
                                                        result = i7 + 2;
                                                        v_128[(__int64)ptr] = a2;
                                                        arg_112 = (__int64)a1;
                                                        if (i3 >= result) {
                                                            v_20 = (__int64)i12;
                                                            a3 = (int *)v_5b0;
                                                            result = rsp + 0x5B8;
                                                            xmm0 = _mm_loadu_si128((__m128i *)result);
                                                            _mm_store_si128((__m128i *)&v_1a0, xmm0);
                                                            a2 = (int *)v_5c8;
                                                            result = (__int64 *)v_5d8;
                                                            i12 = (__int64 *)v_5e0;
                                                            a1 = (size_t *)a3;
                                                            a1 = (size_t *)(-(__int64)a1);
                                                            i3 = (struct Struct_4_t *)v_78;
                                                            if (!((0 /* overflow check on (-a1) */))) {
                                                                v_30 = (__int64)a2;
                                                                i9 = (__int64 *)v_5e8;
                                                                xmm0 = _mm_load_si128((__m128i *)&v_1a0);
                                                                _mm_store_si128((__m128i *)&v_d0, xmm0);
                                                                a1 = (size_t *)v_20;
                                                                i7 = *a1;
                                                                a2 = (int *)i12;
                                                                v_28 = (__int64)a3;
                                                                i7 = v_128;
                                                                if (i7 == 0) JUMPOUT(0x1400ef481);
                                                                i = (struct Struct_1_t *)v_130;
                                                                sub_14002EDF0(0, 384, a3, a4);
                                                                if (result == 0) JUMPOUT(0x1400ef4cd);
                                                                *result = 0;
                                                                arg_112 = 0;
                                                                arg_120 = (__int64)i7;
                                                                a1 = (size_t *)i;
                                                                ++a1;
                                                                a2 = (int *)v_28;
                                                                if ((a1 == 0)) JUMPOUT(0x1400ef48d);
                                                                *i7 = result;
                                                                arg_110 = 0;
                                                                v_128 = result;
                                                                v_130 = (__int64 *)a1;
                                                                if (i9 != i) JUMPOUT(0x1400ef499);
                                                                arg_112 = 1;
                                                                arg_8 = (__int64)a2;
                                                                xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                                                                a1 = (size_t *)v_30;
                                                                arg_114 = (__int64 *)a1;
                                                                arg_128 = (__int64)i12;
                                                                *i12 = result;
                                                                arg_110 = 1;
                                                                i9 = off_140108030;
                                                                i12 = off_140108038;
                                                                ++i6;
                                                                if (i10 != 0) {
                                                                    sub_14002EDF0(0, i10);
                                                                    if (result == 0) JUMPOUT(0x1400ef4eb);
                                                                    i7 = result;
                                                                } else {
                                                                    i7 = 1;
                                                                }
                                                                sub_1400F27F0(i7, i2, i10);
                                                                result = (__int64 *)v_140;
                                                                if (result == 0) {
                                                                    sub_14002EDF0(0, 368);
                                                                    if (result == 0) JUMPOUT(0x1400ef41b);
                                                                    *result = 0;
                                                                    v_140 = (__int64)result;
                                                                    v_148 = 0;
                                                                    arg_16a = 1;
                                                                    arg_8 = (__int64)i10;
                                                                    arg_10 = (__int64)i7;
                                                                    arg_18 = (__int64)i10;
                                                                    a1 = (size_t *)i5;
                                                                    arg_110 = (__int64 *)a1;
                                                                    a1 = (size_t *)v_c0;
                                                                    arg_114 = (__int64 *)a1;
                                                                    i10 = (__int64 *)v_90;
                                                                    i7 = 0xF1357AEA2E62A9C5;
                                                                    ptr = (struct Struct_3_t *)v_70;
                                                                } else {
                                                                    i2 = (struct Struct_2_t *)result;
                                                                    i9 = (__int64 *)v_148;
                                                                    do {
                                                                        a1 = i2 + 8;
                                                                        v_20 = (__int64)i2;
                                                                        result = i2->field_16A;
                                                                        v_28 = (__int64)result;
                                                                        result =  + (__int64)(__int64)result*8;
                                                                        i12 = result + (__int64)(__int64)result*2;
                                                                        i3 = -1;
                                                                        i11 = (__int64 *)a1;
                                                                        while (i12 != 0) {
                                                                            i = a1 + 24;
                                                                            a2 = (int *)arg_8;
                                                                            a3 = a1[2];
                                                                            i2 = (struct Struct_2_t *)i10;
                                                                            i2 = (struct Struct_2_t *)((__int64)i2 - (__int64)a3);
                                                                            if (i2 < 0) a3 = i10;
                                                                            sub_1400F27FC(i7, a2, a3);
                                                                            if (result != 0) i2 = result;
                                                                            a1 = (i2 < 0) ? 1 : 0;
                                                                            result = (i2 > 0) ? 1 : 0;
                                                                            result = (__int64 *)((__int64)result - (__int64)a1);
                                                                            i12 -= 24;
                                                                            ++i3;
                                                                            if (result != 0) {
                                                                                i = (struct Struct_1_t *)v_28;
                                                                                --i9;
                                                                                i2 = (struct Struct_2_t *)v_20;
                                                                                if (!((i9 < 0))) {
                                                                                    i2 = *(__int64 *)(i2 + (__int64)(__int64)i3*8 + 368);
                                                                                }
                                                                                if (i >= 11) {
                                                                                    sub_14002EDF0(0, 368);
                                                                                    i12 = result;
                                                                                    if (i3 >= 5) {
                                                                                        i11 = (__int64 *)v_80;
                                                                                        if ((i == 0)) {
                                                                                            if (i12 == 0) JUMPOUT(0x1400ef41b);
                                                                                            *i12 = 0;
                                                                                            i2 = (struct Struct_2_t *)v_20;
                                                                                            i9 = i2->field_16A;
                                                                                            i9 -= 6;
                                                                                            arg_16a = (__int64)i9;
                                                                                            if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                                                                            i3 = 5;
                                                                                            result = 136;
                                                                                            v_68 = (__int64)result;
                                                                                            v_60 = 5;
                                                                                            result = 320;
                                                                                            v_88 = (__int64)result;
                                                                                            a2 = 152;
                                                                                            result = 316;
                                                                                            a1 = 312;
                                                                                            a3 = 128;
                                                                                            v_b8 = (__int64)a3;
                                                                                            i = (struct Struct_1_t *)i2;
                                                                                        } else {
                                                                                            if (i3 != 6) {
                                                                                                if (i12 == 0) JUMPOUT(0x1400ef41b);
                                                                                                *i12 = 0;
                                                                                                result = (__int64 *)v_20;
                                                                                                i9 = (__int64 *)arg_16a;
                                                                                                i9 -= 7;
                                                                                                arg_16a = (__int64)i9;
                                                                                                if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                                                                                i3 -= 7;
                                                                                                result = 160;
                                                                                                v_68 = (__int64)result;
                                                                                                v_60 = 6;
                                                                                                result = 328;
                                                                                                v_88 = (__int64)result;
                                                                                                a2 = 176;
                                                                                                result = 324;
                                                                                                a1 = 320;
                                                                                                a3 = 152;
                                                                                                v_b8 = (__int64)a3;
                                                                                                i = (struct Struct_1_t *)i12;
                                                                                            } else {
                                                                                                if (i12 == 0) JUMPOUT(0x1400ef41b);
                                                                                                *i12 = 0;
                                                                                                result = (__int64 *)v_20;
                                                                                                i9 = (__int64 *)arg_16a;
                                                                                                i9 -= 6;
                                                                                                arg_16a = (__int64)i9;
                                                                                                if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                                                                                result = 136;
                                                                                                v_68 = (__int64)result;
                                                                                                v_60 = 5;
                                                                                                result = 320;
                                                                                                v_88 = (__int64)result;
                                                                                                a2 = 152;
                                                                                                result = 316;
                                                                                                a1 = 312;
                                                                                                a3 = 128;
                                                                                                v_b8 = (__int64)a3;
                                                                                                i = (struct Struct_1_t *)i12;
                                                                                                i3 = 0;
                                                                                            }
                                                                                            i2 = (struct Struct_2_t *)v_20;
                                                                                        }
                                                                                        result = *(__int64 *)((__int64)i2 + (__int64)result);
                                                                                        v_30 = (__int64)result;
                                                                                        result = *(__int64 *)((__int64)i2 + (__int64)a1);
                                                                                        v_28 = (__int64)result;
                                                                                        a1 = i12 + 8;
                                                                                        a2 = (int *)((__int64)a2 + (__int64)i2);
                                                                                        i9 = (__int64 *)((__int64)(__int64)i9 << 3);
                                                                                        a3 = i9 + (__int64)(__int64)i9*2;
                                                                                        sub_1400F27F0(a1, a2, a3);
                                                                                        a1 = (size_t *)i12;
                                                                                        a1 += 272;
                                                                                        a2 = (int *)v_88;
                                                                                        a2 = (int *)((__int64)a2 + (__int64)i2);
                                                                                        sub_1400F27F0(a1, a2, i9);
                                                                                        result = (__int64 *)v_60;
                                                                                        i2->field_16A = result;
                                                                                        result = (__int64 *)v_b8;
                                                                                        a3 = *(__int64 *)((__int64)i2 + (__int64)result);
                                                                                        result = (__int64 *)v_68;
                                                                                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)i2 + (__int64)result));
                                                                                        _mm_store_si128((__m128i *)&v_5b0, xmm0);
                                                                                        i9 = i->field_16A;
                                                                                        a4 = (size_t *)i9;
                                                                                        result =  + (__int64)(__int64)i3*2;
                                                                                        result = (__int64 *)((__int64)result + (__int64)i3);
                                                                                        i2 = i + (__int64)(__int64)result*8;
                                                                                        i2 += 8;
                                                                                        if (a4 <= i3) {
                                                                                            *(__int64 *)i2 = (__int64)(i10);
                                                                                            i2->field_8 = i7;
                                                                                            i2->field_10 = i10;
                                                                                        } else {
                                                                                            result = i + 8;
                                                                                            a1 =  + (__int64)(__int64)i3*2 + 3;
                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)i3);
                                                                                            a1 = result + (__int64)(__int64)a1*8;
                                                                                            a4 = (size_t *)((__int64)a4 - (__int64)i3);
                                                                                            a4 = (size_t *)((__int64)(__int64)a4 << 3);
                                                                                            v_60 = (__int64)a4;
                                                                                            v_68 = (__int64)a3;
                                                                                            a3 = a4 + (__int64)(__int64)a4*2;
                                                                                            sub_1400F27F6(a1, i2, a3, a4);
                                                                                            *(__int64 *)i2 = (__int64)(i10);
                                                                                            i2->field_8 = i7;
                                                                                            i2->field_10 = i10;
                                                                                            a2 = i + (__int64)(__int64)i3*8;
                                                                                            a2 += 272;
                                                                                            a1 = i + (__int64)(__int64)i3*8;
                                                                                            a1 += 280;
                                                                                            a3 = (int *)v_60;
                                                                                            sub_1400F27F6(a1, a2, a3);
                                                                                            a3 = (int *)v_68;
                                                                                        }
                                                                                        ptr = (struct Struct_3_t *)v_70;
                                                                                        result = (__int64 *)i5;
                                                                                        ++i9;
                                                                                        *(__int64 *)(i + (__int64)(__int64)i3*8 + 272) = (__int64)(result);
                                                                                        result = (__int64 *)v_c0;
                                                                                        *(__int64 *)(i + (__int64)(__int64)i3*8 + 276) = (__int64)(result);
                                                                                        i->field_16A = i9;
                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_5b0);
                                                                                        _mm_store_si128((__m128i *)&v_330, xmm0);
                                                                                        result = (__int64 *)a3;
                                                                                        result = (__int64 *)(-(__int64)result);
                                                                                        i9 = off_140108030;
                                                                                        i10 = (__int64 *)v_90;
                                                                                        i7 = 0xF1357AEA2E62A9C5;
                                                                                        if ((0 /* overflow check on (-result) */)) {
                                                                                            xmm0 = _mm_load_si128((__m128i *)&v_330);
                                                                                            _mm_store_si128((__m128i *)&v_d0, xmm0);
                                                                                            result = (__int64 *)v_20;
                                                                                            i11 = *result;
                                                                                            i3 = (struct Struct_4_t *)v_78;
                                                                                            if (i11 == 0) {
                                                                                                i7 = 0;
                                                                                                i = (struct Struct_1_t *)v_30;
                                                                                            } else {
                                                                                                result = 0;
                                                                                                a2 = (int *)i12;
                                                                                                i7 = 0;
                                                                                                i = (struct Struct_1_t *)v_30;
                                                                                                do {
                                                                                                    if (i7 != result) JUMPOUT(0x1400ef439);
                                                                                                    a1 = (size_t *)v_20;
                                                                                                    i9 = a1[45];
                                                                                                    i3 = (struct Struct_4_t *)i9;
                                                                                                    i2 = (struct Struct_2_t *)arg_16a;
                                                                                                    i5 = (int)a2;
                                                                                                    if (i2 >= 11) {
                                                                                                        ++result;
                                                                                                        a1 = 4;
                                                                                                        if (i9 < 5) {
                                                                                                            v_30 = (__int64)i;
                                                                                                            i = (struct Struct_1_t *)a3;
                                                                                                            v_330 = (__int64)i11;
                                                                                                            v_338 = (__int64)result;
                                                                                                            v_340 = (int)a1;
                                                                                                            a1 = rsp + 0x5B0;
                                                                                                            a2 = rsp + 816;
                                                                                                            sub_1400F1290(a1, a2, a3);
                                                                                                            i12 = (__int64 *)v_5d0;
                                                                                                            i10 = (__int64 *)arg_16a;
                                                                                                            i11 = i3 + 1;
                                                                                                            result =  + (__int64)(__int64)i3*2;
                                                                                                            result = (__int64 *)((__int64)result + (__int64)i3);
                                                                                                            i7 = i12 + (__int64)(__int64)result*8;
                                                                                                            i7 += 8;
                                                                                                            if (i9 >= i10) {
                                                                                                                *i7 = i;
                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                                _mm_storeu_si128((__m128i *)(i7 + 8), xmm0);
                                                                                                                result = (__int64 *)v_28;
                                                                                                                v_110[(__int64)i3] = result;
                                                                                                                result = (__int64 *)v_30;
                                                                                                                v_114[(__int64)i3] = result;
                                                                                                                i9 = off_140108030;
                                                                                                                ptr = (struct Struct_3_t *)v_70;
                                                                                                                a2 = (int *)i5;
                                                                                                                a1 = i10 + 1;
                                                                                                                result = i10 + 2;
                                                                                                                v_178[(__int64)i3] = a2;
                                                                                                                arg_16a = (__int64)a1;
                                                                                                                i7 = 0xF1357AEA2E62A9C5;
                                                                                                                if (i11 >= result) {
                                                                                                                    v_20 = (__int64)i12;
                                                                                                                    a3 = (int *)v_5b0;
                                                                                                                    result = rsp + 0x5B8;
                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                                                                    _mm_store_si128((__m128i *)&v_1a0, xmm0);
                                                                                                                    a2 = (int *)v_5c8;
                                                                                                                    i = (struct Struct_1_t *)v_5cc;
                                                                                                                    result = (__int64 *)v_5d8;
                                                                                                                    i12 = (__int64 *)v_5e0;
                                                                                                                    a1 = (size_t *)a3;
                                                                                                                    a1 = (size_t *)(-(__int64)a1);
                                                                                                                    i3 = (struct Struct_4_t *)v_78;
                                                                                                                    i10 = (__int64 *)v_90;
                                                                                                                    if (!((0 /* overflow check on (-a1) */))) {
                                                                                                                        v_28 = (__int64)a2;
                                                                                                                        i7 = (__int64 *)v_5e8;
                                                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_1a0);
                                                                                                                        _mm_store_si128((__m128i *)&v_d0, xmm0);
                                                                                                                        a1 = (size_t *)v_20;
                                                                                                                        i11 = *a1;
                                                                                                                        a2 = (int *)i12;
                                                                                                                        v_30 = (__int64)i;
                                                                                                                        i = (struct Struct_1_t *)v_140;
                                                                                                                        if (i == 0) JUMPOUT(0x1400ef481);
                                                                                                                        i2 = (struct Struct_2_t *)a3;
                                                                                                                        i9 = (__int64 *)v_148;
                                                                                                                        sub_14002EDF0(0, 464, a3, a4);
                                                                                                                        i11 = (__int64 *)v_80;
                                                                                                                        if (result == 0) JUMPOUT(0x1400ef4dc);
                                                                                                                        *result = 0;
                                                                                                                        arg_16a = 0;
                                                                                                                        arg_170 = (__int64 *)i;
                                                                                                                        a1 = (size_t *)i9;
                                                                                                                        ++a1;
                                                                                                                        ptr = (struct Struct_3_t *)v_70;
                                                                                                                        if ((a1 == 0)) JUMPOUT(0x1400ef48d);
                                                                                                                        *(__int64 *)i = (__int64)(result);
                                                                                                                        i->field_168 = 0;
                                                                                                                        v_140 = (__int64)result;
                                                                                                                        v_148 = (int)a1;
                                                                                                                        if (i7 != i9) JUMPOUT(0x1400ef499);
                                                                                                                        arg_16a = 1;
                                                                                                                        arg_8 = (__int64)i2;
                                                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                                        _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                                                                                                                        a1 = (size_t *)v_28;
                                                                                                                        arg_110 = (__int64 *)a1;
                                                                                                                        a1 = (size_t *)v_30;
                                                                                                                        arg_114 = (__int64 *)a1;
                                                                                                                        arg_178 = i12;
                                                                                                                        *i12 = result;
                                                                                                                        arg_168 = 1;
                                                                                                                        i9 = off_140108030;
                                                                                                                        i12 = off_140108038;
                                                                                                                        i7 = 0xF1357AEA2E62A9C5;
                                                                                                                        ++i4;
                                                                                                                        v_60 = (__int64)ptr;
                                                                                                                        a4 = (size_t *)v_c8;
                                                                                                                        if (ptr != i10) JUMPOUT(0x1400eb64b);
                                                                                                                        v_2b8 = 0;
                                                                                                                        v_2c0 = 8;
                                                                                                                        v_2c8 = 0;
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
                                                                                                                        _mm_store_si128((__m128i *)&v_e0, xmm0);
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
                                                                                                                        _mm_store_si128((__m128i *)&v_d0, xmm0);
                                                                                                                        result = (__int64 *)v_f8;
                                                                                                                        v_20 = (__int64)result;
                                                                                                                        a1 = (size_t *)v_100;
                                                                                                                        result = (__int64 *)v_108;
                                                                                                                        i3 = (__int64)(__int64)result * 920;
                                                                                                                        i3 = (struct Struct_4_t *)((__int64)i3 + (__int64)a1);
                                                                                                                        i = (struct Struct_1_t *)a1;
                                                                                                                        v_80 = (__int64)a1;
                                                                                                                        if (result != 0) {
                                                                                                                            i7 = rsp + 0xC00;
                                                                                                                            result = (__int64 *)v_158;
                                                                                                                            result = (__int64 *)arg_210;
                                                                                                                            v_c8 = (__int64)result;
                                                                                                                            result = 8;
                                                                                                                            v_68 = (__int64)result;
                                                                                                                            v_30 = 0;
                                                                                                                            i9 = rsp + 0x5B0;
                                                                                                                            i12 = rsp + 0xBF8;
                                                                                                                            xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
                                                                                                                            xmm7 = _mm_load_si128((__m128i *)&off_140108850);
                                                                                                                            i11 = 0x243F6A8885A308D3;
                                                                                                                            i5 = 0;
                                                                                                                            i = (struct Struct_1_t *)a1;
                                                                                                                            a2 = (int *)i;
                                                                                                                            i += 920;
                                                                                                                            i2 = *a2;
                                                                                                                            result = (__int64 *)i2;
                                                                                                                            result = (__int64 *)(-(__int64)result);
                                                                                                                            while (!((0 /* overflow check on (-result) */))) {
                                                                                                                                a2 += 8;
                                                                                                                                sub_1400F27F0(i7, a2, 912, a4);
                                                                                                                                result = (__int64 *)i5;
                                                                                                                                v_308 = (__int64)result;
                                                                                                                                v_bf8 = (__int64)i2;
                                                                                                                                sub_1400EF530(i9, i12);
                                                                                                                                result = (__int64 *)v_5c0;
                                                                                                                                v_320 = (__int64)result;
                                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)&v_5b0);
                                                                                                                                _mm_store_si128((__m128i *)&v_310, xmm0);
                                                                                                                                result = (__int64 *)v_5c8;
                                                                                                                                v_28 = (__int64)result;
                                                                                                                                a1 = (size_t *)v_5d0;
                                                                                                                                a2 = (int *)v_5e8;
                                                                                                                                i10 = (__int64 *)v_5f0;
                                                                                                                                i7 = (__int64 *)v_5f8;
                                                                                                                                if (i7 == 0) {
                                                                                                                                    v_90 = (__int64)i7;
                                                                                                                                    i11 = (__int64 *)a2;
                                                                                                                                    v_70 = (__int64)a1;
                                                                                                                                    a2 = (int *)v_170;
                                                                                                                                    a1 = (size_t *)i5;
                                                                                                                                    if (a1 >= a2) JUMPOUT(0x1400ef4f8);
                                                                                                                                    i2 = (struct Struct_2_t *)v_168;
                                                                                                                                    result = (__int64 *)a1;
                                                                                                                                    result = (__int64 *)((__int64)(__int64)result << 9);
                                                                                                                                    i7 = result + (__int64)(__int64)a1*8;
                                                                                                                                    a2 = (__int64)i2 + (__int64)i7;
                                                                                                                                    a1 = rsp + 0xF90;
                                                                                                                                    sub_1400F27F0(a1, a2, 512, a4);
                                                                                                                                    result = *(__int64 *)((__int64)i2 + (__int64)i7 + 512);
                                                                                                                                    v_c0 = (__int64)result;
                                                                                                                                    if (v_c8 == 0) {
                                                                                                                                        i2 = (struct Struct_2_t *)v_120;
                                                                                                                                        if (i2 == v_110) {
                                                                                                                                            a1 = rsp + 272;
                                                                                                                                            sub_140106EC0(a1);
                                                                                                                                        }
                                                                                                                                        i7 = (__int64 *)v_118;
                                                                                                                                        i12 = i2 + (__int64)(__int64)i2*4;
                                                                                                                                        i12 = (__int64 *)((__int64)(__int64)i12 << 7);
                                                                                                                                        result = (__int64 *)v_320;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 16) = result;
                                                                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_310);
                                                                                                                                        _mm_storeu_si128((__m128i *)((__int64)i7 + (__int64)i12), xmm0);
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 24) = i11;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 32) = i10;
                                                                                                                                        result = (__int64 *)v_90;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 40) = result;
                                                                                                                                        a1 = (__int64)i7 + (__int64)i12;
                                                                                                                                        a1 += 48;
                                                                                                                                        a2 = rsp + 0xF90;
                                                                                                                                        sub_1400F27F0(a1, a2, 512);
                                                                                                                                        result = (__int64 *)v_c0;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 560) = result;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 568) = 0;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 584) = 0;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 592) = 0;
                                                                                                                                        *(__int64 *)((__int64)i7 + (__int64)i12 + 625) = 0;
                                                                                                                                        ++i2;
                                                                                                                                        v_120 = (__int64 *)i2;
                                                                                                                                        result = (__int64 *)v_ad;
                                                                                                                                        v_5b0 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_ae;
                                                                                                                                        v_330 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_af;
                                                                                                                                        v_1a0 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_b0;
                                                                                                                                        v_190 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_b1;
                                                                                                                                        v_5f = (__int64)result;
                                                                                                                                        result = (__int64 *)v_b2;
                                                                                                                                        v_5e = (__int64)result;
                                                                                                                                        result = (__int64 *)v_b3;
                                                                                                                                        v_5d = (__int64)result;
                                                                                                                                        result = (__int64 *)v_b8;
                                                                                                                                        v_5c = (__int64)result;
                                                                                                                                        result = (__int64 *)v_158;
                                                                                                                                        v_5b = (__int64)result;
                                                                                                                                        result = (__int64 *)v_88;
                                                                                                                                        v_5a = (__int64)result;
                                                                                                                                        result = (__int64 *)v_60;
                                                                                                                                        v_59 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_ac;
                                                                                                                                        v_58 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_ab;
                                                                                                                                        v_57 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_aa;
                                                                                                                                        v_56 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a9;
                                                                                                                                        v_55 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a8;
                                                                                                                                        v_54 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a7;
                                                                                                                                        v_53 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a6;
                                                                                                                                        v_52 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a5;
                                                                                                                                        v_51 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a4;
                                                                                                                                        v_50 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a3;
                                                                                                                                        v_4f = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a2;
                                                                                                                                        v_4e = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a1;
                                                                                                                                        v_4d = (__int64)result;
                                                                                                                                        result = (__int64 *)v_a0;
                                                                                                                                        v_4c = (__int64)result;
                                                                                                                                        result = (__int64 *)v_9f;
                                                                                                                                        v_4b = (__int64)result;
                                                                                                                                        result = (__int64 *)v_9e;
                                                                                                                                        v_4a = (__int64)result;
                                                                                                                                        result = (__int64 *)v_9d;
                                                                                                                                        v_49 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_9c;
                                                                                                                                        v_48 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_9b;
                                                                                                                                        v_47 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_9a;
                                                                                                                                        v_46 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_99;
                                                                                                                                        v_45 = (__int64)result;
                                                                                                                                        result = (__int64 *)v_98;
                                                                                                                                        v_44 = (__int64)result;
                                                                                                                                        if (v_c8 == 0) {
                                                                                                                                            a1 = (size_t *)v_70;
                                                                                                                                            i7 = rsp + 0xC00;
                                                                                                                                            if (a1 == 0) {
                                                                                                                                                ++i5;
                                                                                                                                                i12 = rsp + 0xBF8;
                                                                                                                                                i11 = 0x243F6A8885A308D3;
                                                                                                                                                return (__int64)i11;
                                                                                                                                            }
                                                                                                                                            result =  + (__int64)(__int64)a1*8 + 23;
                                                                                                                                            result = (__int64 *)((__int64)(__int64)result & -16);
                                                                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)result);
                                                                                                                                            if (a1 == -17) {
                                                                                                                                                return (__int64)a1;
                                                                                                                                            }
                                                                                                                                            i2 = (struct Struct_2_t *)v_28;
                                                                                                                                            i2 = (struct Struct_2_t *)((__int64)i2 - (__int64)result);
                                                                                                                                            ((__int64 (*)())off_140108030)(a1);
                                                                                                                                            ((__int64 (*)())off_140108038)(result, 0, i2);
                                                                                                                                            return (__int64)i2;
                                                                                                                                        }
                                                                                                                                        v_5b0 = 0;
                                                                                                                                        v_330 = 0;
                                                                                                                                        v_1a0 = 0;
                                                                                                                                        v_190 = 0;
                                                                                                                                        v_5f = 0;
                                                                                                                                        v_5e = 0;
                                                                                                                                        v_5d = 0;
                                                                                                                                        v_5c = 0;
                                                                                                                                        v_5b = 0;
                                                                                                                                        v_5a = 0;
                                                                                                                                        v_59 = 0;
                                                                                                                                        v_58 = 0;
                                                                                                                                        v_57 = 0;
                                                                                                                                        v_56 = 0;
                                                                                                                                        v_55 = 0;
                                                                                                                                        v_54 = 0;
                                                                                                                                        v_53 = 0;
                                                                                                                                        v_52 = 0;
                                                                                                                                        v_51 = 0;
                                                                                                                                        v_50 = 0;
                                                                                                                                        v_4f = 0;
                                                                                                                                        v_4e = 0;
                                                                                                                                        v_4d = 0;
                                                                                                                                        v_4c = 0;
                                                                                                                                        v_4b = 0;
                                                                                                                                        v_4a = 0;
                                                                                                                                        v_49 = 0;
                                                                                                                                        v_48 = 0;
                                                                                                                                        v_47 = 0;
                                                                                                                                        v_46 = 0;
                                                                                                                                        v_45 = 0;
                                                                                                                                        v_44 = 0;
                                                                                                                                        return v_44;
                                                                                                                                    }
                                                                                                                                    result = rsp + 776;
                                                                                                                                    v_1a0 = (__int64)result;
                                                                                                                                    result = &off_140018400;
                                                                                                                                    v_1a8 = (__int64)result;
                                                                                                                                    result = &off_14011D6A8;
                                                                                                                                    v_5b0 = (__int64)result;
                                                                                                                                    v_5b8 = 1;
                                                                                                                                    result = rsp + 416;
                                                                                                                                    v_5c0 = (__int64)result;
                                                                                                                                    v_5c8 = 1;
                                                                                                                                    v_5d0 = 0;
                                                                                                                                    a1 = rsp + 816;
                                                                                                                                    sub_14000EFE0(a1, i9);
                                                                                                                                    i2 = (struct Struct_2_t *)v_338;
                                                                                                                                    i7 = (__int64 *)v_340;
                                                                                                                                    i12 = (__int64 *)v_330;
                                                                                                                                    i9 = (__int64 *)v_c8;
                                                                                                                                    sub_14006B9D0(i9, i9, i2, i7);
                                                                                                                                    a1 = rsp + 0x9EC;
                                                                                                                                    sub_14006C940(a1, i9, i2, i7);
                                                                                                                                    result = (__int64 *)v_5b0;
                                                                                                                                    v_ad = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b1;
                                                                                                                                    v_ae = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b2;
                                                                                                                                    v_af = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b3;
                                                                                                                                    v_b0 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b4;
                                                                                                                                    v_b1 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b5;
                                                                                                                                    v_b2 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b6;
                                                                                                                                    v_b3 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b7;
                                                                                                                                    v_b8 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b8;
                                                                                                                                    v_158 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5b9;
                                                                                                                                    v_88 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5ba;
                                                                                                                                    v_60 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5bb;
                                                                                                                                    v_ac = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5bc;
                                                                                                                                    v_ab = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5bd;
                                                                                                                                    v_aa = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5be;
                                                                                                                                    v_a9 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5bf;
                                                                                                                                    v_a8 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c0;
                                                                                                                                    v_a7 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c1;
                                                                                                                                    v_a6 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c2;
                                                                                                                                    v_a5 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c3;
                                                                                                                                    v_a4 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c4;
                                                                                                                                    v_a3 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c5;
                                                                                                                                    v_a2 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c6;
                                                                                                                                    v_a1 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c7;
                                                                                                                                    v_a0 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c8;
                                                                                                                                    v_9f = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5c9;
                                                                                                                                    v_9e = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5ca;
                                                                                                                                    v_9d = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5cb;
                                                                                                                                    v_9c = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5cc;
                                                                                                                                    v_9b = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5cd;
                                                                                                                                    v_9a = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5ce;
                                                                                                                                    v_99 = (__int64)result;
                                                                                                                                    result = (__int64 *)v_5cf;
                                                                                                                                    v_98 = (__int64)result;
                                                                                                                                    if (i12 == 0) {
                                                                                                                                        i9 = rsp + 0x5B0;
                                                                                                                                        return (__int64)i9;
                                                                                                                                    }
                                                                                                                                    ((__int64 (*)())off_140108030)();
                                                                                                                                    ((__int64 (*)())off_140108038)(result, 0, i2);
                                                                                                                                    return (__int64)i9;
                                                                                                                                }
                                                                                                                                i12 = i7 + (__int64)(__int64)i7*2;
                                                                                                                                i12 = (__int64 *)((__int64)(__int64)i12 << 4);
                                                                                                                                i12 = (__int64 *)((__int64)i12 + (__int64)i10);
                                                                                                                                result = i10 + 48;
                                                                                                                                v_78 = (__int64)i3;
                                                                                                                                i2 = a3[2];
                                                                                                                                while (i2 >= 0) {
                                                                                                                                    i3 = (struct Struct_4_t *)a3;
                                                                                                                                    v_2f8 = (__int64)result;
                                                                                                                                    v_90 = (__int64)i7;
                                                                                                                                    v_c0 = (__int64)i10;
                                                                                                                                    v_300 = (int)a2;
                                                                                                                                    v_70 = (__int64)a1;
                                                                                                                                    i7 = *(a3 + 8);
                                                                                                                                    v_188 = i12;
                                                                                                                                    if (i2 == 0) {
                                                                                                                                        i9 = 1;
                                                                                                                                        sub_1400F27F0(i9, i7, i2);
                                                                                                                                        i12 = i3->field_28;
                                                                                                                                        if (i12 >= 0) {
                                                                                                                                            i7 = i3->field_20;
                                                                                                                                            if (i12 == 0) {
                                                                                                                                                i10 = 1;
                                                                                                                                                sub_1400F27F0(i10, i7, i12);
                                                                                                                                                if (i2 > 16) {
                                                                                                                                                    a4 = i2 - 17;
                                                                                                                                                    a1 = (size_t *)i11;
                                                                                                                                                    a3 = 0x13198A2E03707344;
                                                                                                                                                    ptr = (struct Struct_3_t *)i9;
                                                                                                                                                    if (a4 < 16) {
                                                                                                                                                        if (((__int64)a4 & 16) != 0) {
                                                                                                                                                            a1 = (size_t *)((__int64)(__int64)a1 ^ *(__int64 *)((__int64)i9 + (__int64)i2 - 16));
                                                                                                                                                            a3 = (int *)((__int64)(__int64)a3 ^ *(__int64 *)((__int64)i9 + (__int64)i2 - 8));
                                                                                                                                                            v_180 = i9;
                                                                                                                                                            if (i12 > 16) {
                                                                                                                                                                ptr = i12 - 17;
                                                                                                                                                                a4 = (size_t *)i11;
                                                                                                                                                                i8 = 0x13198A2E03707344;
                                                                                                                                                                i9 = i10;
                                                                                                                                                                if (ptr < 16) {
                                                                                                                                                                    if (((__int64)ptr & 16) != 0) {
                                                                                                                                                                        a4 = (size_t *)((__int64)(__int64)a4 ^ *(__int64 *)((__int64)i10 + (__int64)i12 - 16));
                                                                                                                                                                        i8 ^= *(__int64 *)((__int64)i10 + (__int64)i12 - 8);
                                                                                                                                                                        v_178 = i10;
                                                                                                                                                                        result = (__int64 *)a1;
                                                                                                                                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a3); /* unsigned; high half in a2 */;
                                                                                                                                                                        i9 = (__int64 *)a2;
                                                                                                                                                                        i10 = result;
                                                                                                                                                                        result = (__int64 *)a4;
                                                                                                                                                                        a4 = (size_t *)((__int64)(__int64)(__int64)a4 * i8); /* unsigned; high half in a2 */;
                                                                                                                                                                        i11 = (__int64 *)a4;
                                                                                                                                                                        i7 = (__int64 *)a2;
                                                                                                                                                                        if (v_e0 == 0) {
                                                                                                                                                                            a1 = rsp + 208;
                                                                                                                                                                            a2 = rsp + 240;
                                                                                                                                                                            sub_140106960(a1, a2);
                                                                                                                                                                        }
                                                                                                                                                                        i9 = (__int64 *)((__int64)(__int64)i9 ^ (__int64)i10);
                                                                                                                                                                        i9 = (__int64 *)((__int64)(__int64)i9 ^ (__int64)i2);
                                                                                                                                                                        result = 0x1427BB2D3769B199;
                                                                                                                                                                        i9 = (__int64 *)((__int64)(__int64)(__int64)i9 * (__int64)result);
                                                                                                                                                                        i7 = (__int64 *)((__int64)(__int64)i7 ^ (__int64)i12);
                                                                                                                                                                        i7 = (__int64 *)((__int64)(__int64)i7 ^ (__int64)i11);
                                                                                                                                                                        i7 = (__int64 *)((__int64)i7 + (__int64)i9);
                                                                                                                                                                        i7 = (__int64 *)((__int64)(__int64)(__int64)i7 * (__int64)result);
                                                                                                                                                                        result = 0x4148B18F74CD2C7E;
                                                                                                                                                                        i7 = (__int64 *)((__int64)i7 + (__int64)result);
                                                                                                                                                                        i7 = __ROL8__(i7, 26);
                                                                                                                                                                        i9 = (__int64 *)v_d0;
                                                                                                                                                                        a3 = (int *)v_d8;
                                                                                                                                                                        a2 = (int *)i7;
                                                                                                                                                                        a2 = (int *)((__int64)(__int64)a2 >> 57);
                                                                                                                                                                        xmm0 = _mm_cvtsi32_si128(a2);
                                                                                                                                                                        xmm0 = _mm_unpacklo_epi8(xmm0, xmm0);
                                                                                                                                                                        xmm0 = _mm_shufflelo_epi16(xmm0, 0);
                                                                                                                                                                        xmm8 = _mm_shuffle_epi32(xmm0, 68);
                                                                                                                                                                        result = 0;
                                                                                                                                                                        a1 = 0;
                                                                                                                                                                        do {
                                                                                                                                                                            i7 = (__int64 *)((__int64)(__int64)i7 & (__int64)a3);
                                                                                                                                                                            xmm9 = _mm_loadu_si128((__m128i *)((__int64)i9 + (__int64)i7));
                                                                                                                                                                            xmm0 = xmm9;
                                                                                                                                                                            xmm0 = _mm_cmpeq_epi8(xmm0, xmm8);
                                                                                                                                                                            i11 = _mm_movemask_epi8(xmm0);
                                                                                                                                                                            i11 = 0x243F6A8885A308D3;
                                                                                                                                                                            if (result == 1) {
                                                                                                                                                                                xmm9 = _mm_cmpeq_epi8(xmm9, xmm6);
                                                                                                                                                                                result = _mm_movemask_epi8(xmm9);
                                                                                                                                                                                if (result != 0) {
                                                                                                                                                                                    result = *(__int64 *)((__int64)i9 + (__int64)a4);
                                                                                                                                                                                    if (result >= 0) {
                                                                                                                                                                                        xmm0 = _mm_load_si128((__m128i *)i9);
                                                                                                                                                                                        result = _mm_movemask_epi8(xmm0);
                                                                                                                                                                                        a4 = __builtin_ctz(result);
                                                                                                                                                                                        result = *(__int64 *)((__int64)i9 + (__int64)a4);
                                                                                                                                                                                    }
                                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result & 1);
                                                                                                                                                                                    a1 = a4 - 16;
                                                                                                                                                                                    a1 = (size_t *)((__int64)(__int64)a1 & (__int64)a3);
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)a4) = a2;
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)a1 + 16) = a2;
                                                                                                                                                                                    xmm0 = _mm_load_si128((__m128i *)&v_e0);
                                                                                                                                                                                    xmm1 = _mm_cvtsi32_si128(result);
                                                                                                                                                                                    /* shufps $228, %xmm7, %xmm1 */;
                                                                                                                                                                                    xmm0 = _mm_sub_epi64(xmm0, xmm1);
                                                                                                                                                                                    _mm_store_si128((__m128i *)&v_e0, xmm0);
                                                                                                                                                                                    a4 = (size_t *)(-(__int64)a4);
                                                                                                                                                                                    result = a4 + (__int64)(__int64)a4*2;
                                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result << 4);
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)result - 48) = i2;
                                                                                                                                                                                    a1 = (size_t *)v_180;
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)result - 40) = a1;
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)result - 32) = i2;
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)result - 24) = i12;
                                                                                                                                                                                    a1 = (size_t *)v_178;
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)result - 16) = a1;
                                                                                                                                                                                    *(__int64 *)((__int64)i9 + (__int64)result - 8) = i12;
                                                                                                                                                                                    i2 = i3->field_10;
                                                                                                                                                                                    if (i2 >= 0) {
                                                                                                                                                                                        i9 = i3->field_8;
                                                                                                                                                                                        if (i2 == 0) {
                                                                                                                                                                                            i7 = 1;
                                                                                                                                                                                            sub_1400F27F0(i7, i9, i2);
                                                                                                                                                                                            i9 = i3->field_28;
                                                                                                                                                                                            if (i9 >= 0) {
                                                                                                                                                                                                i10 = i3->field_20;
                                                                                                                                                                                                if (i9 == 0) {
                                                                                                                                                                                                    i12 = 1;
                                                                                                                                                                                                    i3 = (struct Struct_4_t *)v_78;
                                                                                                                                                                                                    sub_1400F27F0(i12, i10, i9);
                                                                                                                                                                                                    i10 = (__int64 *)v_30;
                                                                                                                                                                                                    if (i10 == v_2b8) {
                                                                                                                                                                                                        a1 = rsp + 696;
                                                                                                                                                                                                        sub_1400F9B90(a1, a2, a3);
                                                                                                                                                                                                        result = (__int64 *)v_2c0;
                                                                                                                                                                                                        v_68 = (__int64)result;
                                                                                                                                                                                                    }
                                                                                                                                                                                                    result = i10 + (__int64)(__int64)i10*2;
                                                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result << 4);
                                                                                                                                                                                                    a1 = (size_t *)v_68;
                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result) = i2;
                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result + 8) = i7;
                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result + 16) = i2;
                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result + 24) = i9;
                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result + 32) = i12;
                                                                                                                                                                                                    *(__int64 *)((__int64)a1 + (__int64)result + 40) = i9;
                                                                                                                                                                                                    ++i10;
                                                                                                                                                                                                    v_30 = (__int64)i10;
                                                                                                                                                                                                    v_2c8 = (__int64)i10;
                                                                                                                                                                                                    i9 = rsp + 0x5B0;
                                                                                                                                                                                                    a1 = (size_t *)v_70;
                                                                                                                                                                                                    i10 = (__int64 *)v_c0;
                                                                                                                                                                                                    i7 = (__int64 *)v_90;
                                                                                                                                                                                                    i12 = v_188;
                                                                                                                                                                                                    a3 = (int *)v_2f8;
                                                                                                                                                                                                    result = a3 + 48;
                                                                                                                                                                                                    if (a3 == i12) result = a3;
                                                                                                                                                                                                    a2 = (int *)v_300;
                                                                                                                                                                                                    return (__int64)a2;
                                                                                                                                                                                                }
                                                                                                                                                                                                sub_14002EDF0(0, i9);
                                                                                                                                                                                                i3 = (struct Struct_4_t *)v_78;
                                                                                                                                                                                                if (result == 0) JUMPOUT(0x1400ef51e);
                                                                                                                                                                                                i12 = result;
                                                                                                                                                                                                return (__int64)i12;
                                                                                                                                                                                            }
                                                                                                                                                                                            return (__int64)i12;
                                                                                                                                                                                        }
                                                                                                                                                                                        sub_14002EDF0(0, i2, a3, a4);
                                                                                                                                                                                        if (result == 0) JUMPOUT(0x1400ea8c0);
                                                                                                                                                                                        i7 = result;
                                                                                                                                                                                        return (__int64)i7;
                                                                                                                                                                                    }
                                                                                                                                                                                    return (__int64)i7;
                                                                                                                                                                                }
                                                                                                                                                                                result = 1;
                                                                                                                                                                                i7 = (__int64 *)((__int64)i7 + (__int64)a1);
                                                                                                                                                                                i7 += 16;
                                                                                                                                                                                a1 += 16;
                                                                                                                                                                            }
                                                                                                                                                                            result = _mm_movemask_epi8(xmm9);
                                                                                                                                                                            if (result == 0) {
                                                                                                                                                                                result = 0;
                                                                                                                                                                                return (__int64)result;
                                                                                                                                                                            }
                                                                                                                                                                            a4 = __builtin_ctz(result);
                                                                                                                                                                            a4 = (size_t *)((__int64)a4 + (__int64)i7);
                                                                                                                                                                            a4 = (size_t *)((__int64)(__int64)a4 & (__int64)a3);
                                                                                                                                                                            return (__int64)a4;
                                                                                                                                                                        } while (true);
                                                                                                                                                                    }
                                                                                                                                                                    a4 = (size_t *)((__int64)(__int64)a4 ^ *i9);
                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                    a2 = 0xA4093822299F31D0;
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result ^ (__int64)a2);
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a4); /* unsigned; high half in a2 */;
                                                                                                                                                                    a4 = (size_t *)i8;
                                                                                                                                                                    i8 = (__int64)a2;
                                                                                                                                                                    i8 ^= (__int64)result;
                                                                                                                                                                    return i8;
                                                                                                                                                                }
                                                                                                                                                                i7 = (__int64 *)ptr;
                                                                                                                                                                i7 = (__int64 *)((__int64)(__int64)i7 >> 4);
                                                                                                                                                                ++i7;
                                                                                                                                                                i7 = (__int64 *)((__int64)(__int64)i7 & -2);
                                                                                                                                                                a4 = (size_t *)i11;
                                                                                                                                                                i9 = i10;
                                                                                                                                                                i11 = 0xA4093822299F31D0;
                                                                                                                                                                do {
                                                                                                                                                                    a4 = (size_t *)((__int64)(__int64)a4 ^ *i9);
                                                                                                                                                                    result = (__int64 *)arg_8;
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result ^ (__int64)i11);
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a4); /* unsigned; high half in a2 */;
                                                                                                                                                                    a4 = (size_t *)a2;
                                                                                                                                                                    a4 = (size_t *)((__int64)(__int64)a4 ^ (__int64)result);
                                                                                                                                                                    i8 ^= arg_10;
                                                                                                                                                                    result = (__int64 *)arg_18;
                                                                                                                                                                    i9 += 32;
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result ^ (__int64)i11);
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)(__int64)result * i8); /* unsigned; high half in a2 */;
                                                                                                                                                                    i8 = (__int64)a2;
                                                                                                                                                                    i8 ^= (__int64)result;
                                                                                                                                                                    i7 -= 2;
                                                                                                                                                                } while ((i7 != 0));
                                                                                                                                                                return (__int64)i7;
                                                                                                                                                            }
                                                                                                                                                            if (i12 <= 7) {
                                                                                                                                                                if (i12 <= 3) {
                                                                                                                                                                    i8 = 0x13198A2E03707344;
                                                                                                                                                                    a4 = (size_t *)i11;
                                                                                                                                                                    if (i12 == 0) {
                                                                                                                                                                        return (__int64)a4;
                                                                                                                                                                    }
                                                                                                                                                                    a4 = *i10;
                                                                                                                                                                    result = i12;
                                                                                                                                                                    result = (__int64 *)((__int64)(__int64)result >> 1);
                                                                                                                                                                    result = *(__int64 *)((__int64)i10 + (__int64)result);
                                                                                                                                                                    i8 = *(__int64 *)((__int64)i10 + (__int64)i12 - 1);
                                                                                                                                                                    a4 = (size_t *)((__int64)(__int64)a4 ^ (__int64)i11);
                                                                                                                                                                    i8 <<= 8;
                                                                                                                                                                    i8 |= (__int64)result;
                                                                                                                                                                    result = 0x13198A2E03707344;
                                                                                                                                                                    i8 ^= (__int64)result;
                                                                                                                                                                    return i8;
                                                                                                                                                                }
                                                                                                                                                                a4 = *i10;
                                                                                                                                                                i8 = *(__int64 *)((__int64)i10 + (__int64)i12 - 4);
                                                                                                                                                                a4 = (size_t *)((__int64)(__int64)a4 ^ (__int64)i11);
                                                                                                                                                                return (__int64)a4;
                                                                                                                                                            }
                                                                                                                                                            a4 = *i10;
                                                                                                                                                            a4 = (size_t *)((__int64)(__int64)a4 ^ (__int64)i11);
                                                                                                                                                            i8 = *(__int64 *)((__int64)i10 + (__int64)i12 - 8);
                                                                                                                                                            return i8;
                                                                                                                                                        }
                                                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 ^ *(__int64 *)ptr);
                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                        a2 = 0xA4093822299F31D0;
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)result ^ (__int64)a2);
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                                                                                                                                        a1 = (size_t *)a3;
                                                                                                                                                        a3 = a2;
                                                                                                                                                        a3 = (int *)((__int64)(__int64)a3 ^ (__int64)result);
                                                                                                                                                        return (__int64)a3;
                                                                                                                                                    }
                                                                                                                                                    i8 = (__int64)a4;
                                                                                                                                                    i8 >>= 4;
                                                                                                                                                    ++i8;
                                                                                                                                                    i8 &= -2;
                                                                                                                                                    a1 = (size_t *)i11;
                                                                                                                                                    ptr = (struct Struct_3_t *)i9;
                                                                                                                                                    i7 = 0xA4093822299F31D0;
                                                                                                                                                    do {
                                                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 ^ *(__int64 *)ptr);
                                                                                                                                                        result = ptr->field_8;
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)result ^ (__int64)i7);
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                                                                                                                                        a1 = (size_t *)a2;
                                                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)result);
                                                                                                                                                        a3 = (int *)((__int64)(__int64)a3 ^ (__int64)ptr->field_10);
                                                                                                                                                        result = ptr->field_18;
                                                                                                                                                        ptr += 32;
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)result ^ (__int64)i7);
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)(__int64)result * (__int64)a3); /* unsigned; high half in a2 */;
                                                                                                                                                        a3 = a2;
                                                                                                                                                        a3 = (int *)((__int64)(__int64)a3 ^ (__int64)result);
                                                                                                                                                        i8 -= 2;
                                                                                                                                                    } while ((i8 != 0));
                                                                                                                                                    return i8;
                                                                                                                                                }
                                                                                                                                                if (i2 <= 7) {
                                                                                                                                                    if (i2 <= 3) {
                                                                                                                                                        a3 = 0x13198A2E03707344;
                                                                                                                                                        a1 = (size_t *)i11;
                                                                                                                                                        if (i2 == 0) {
                                                                                                                                                            return (__int64)a1;
                                                                                                                                                        }
                                                                                                                                                        a1 = *i9;
                                                                                                                                                        result = (__int64 *)i2;
                                                                                                                                                        result = (__int64 *)((__int64)(__int64)result >> 1);
                                                                                                                                                        result = *(__int64 *)((__int64)i9 + (__int64)result);
                                                                                                                                                        a3 = *(__int64 *)((__int64)i9 + (__int64)i2 - 1);
                                                                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)i11);
                                                                                                                                                        a3 = (int *)((__int64)(__int64)a3 << 8);
                                                                                                                                                        a3 = (int *)((__int64)(__int64)a3 | (__int64)result);
                                                                                                                                                        result = 0x13198A2E03707344;
                                                                                                                                                        a3 = (int *)((__int64)(__int64)a3 ^ (__int64)result);
                                                                                                                                                        return (__int64)a3;
                                                                                                                                                    }
                                                                                                                                                    a1 = *i9;
                                                                                                                                                    a3 = *(__int64 *)((__int64)i9 + (__int64)i2 - 4);
                                                                                                                                                    a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)i11);
                                                                                                                                                    return (__int64)a1;
                                                                                                                                                }
                                                                                                                                                a1 = *i9;
                                                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)i11);
                                                                                                                                                a3 = *(__int64 *)((__int64)i9 + (__int64)i2 - 8);
                                                                                                                                                return (__int64)a3;
                                                                                                                                            }
                                                                                                                                            sub_14002EDF0(0, i12);
                                                                                                                                            if (result == 0) JUMPOUT(0x1400ef511);
                                                                                                                                            i10 = result;
                                                                                                                                            return (__int64)i10;
                                                                                                                                        }
                                                                                                                                        return (__int64)i10;
                                                                                                                                    }
                                                                                                                                    sub_14002EDF0(0, i2, i10);
                                                                                                                                    if (result == 0) JUMPOUT(0x1400ea8c0);
                                                                                                                                    i9 = result;
                                                                                                                                    return (__int64)i9;
                                                                                                                                }
                                                                                                                                return (__int64)i9;
                                                                                                                            }
                                                                                                                        }
                                                                                                                        return (__int64)i9;
                                                                                                                    }
                                                                                                                    i12 = off_140108038;
                                                                                                                    i11 = (__int64 *)v_80;
                                                                                                                    return (__int64)i11;
                                                                                                                }
                                                                                                                a1 = (size_t *)i10;
                                                                                                                a1 = (size_t *)((__int64)a1 - (__int64)i3);
                                                                                                                ++a1;
                                                                                                                a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                                                                                                if ((a1 == 0)) {
                                                                                                                    i10 = (__int64 *)((__int64)i10 - (__int64)i3);
                                                                                                                    if (i10 < 3) {
                                                                                                                        return (__int64)i10;
                                                                                                                    }
                                                                                                                    for (; i11 != result; i11 += 4) {
                                                                                                                        a1 = v_170[(__int64)i11];
                                                                                                                        *a1 = i12;
                                                                                                                        a1[45] = i11;
                                                                                                                        a1 = v_178[(__int64)i11];
                                                                                                                        *a1 = i12;
                                                                                                                        a2 = i11 + 1;
                                                                                                                        a1[45] = a2;
                                                                                                                        a1 = v_180[(__int64)i11];
                                                                                                                        *a1 = i12;
                                                                                                                        a2 = i11 + 2;
                                                                                                                        a1[45] = a2;
                                                                                                                        a1 = v_188[(__int64)i11];
                                                                                                                        *a1 = i12;
                                                                                                                        a2 = i11 + 3;
                                                                                                                        a1[45] = a2;
                                                                                                                    }
                                                                                                                    return (__int64)i11;
                                                                                                                }
                                                                                                                a3 = i12 + (__int64)(__int64)i3*8;
                                                                                                                a3 += 376;
                                                                                                                for (a2 = 0; a1 != a2; ++a2) {
                                                                                                                    a4 = a3[(__int64)a2];
                                                                                                                    *a4 = i12;
                                                                                                                    i8 = (__int64)a2 + (__int64)i11;
                                                                                                                    arg_168 = i8;
                                                                                                                }
                                                                                                                i11 = (__int64 *)((__int64)i11 + (__int64)a2);
                                                                                                                return (__int64)i11;
                                                                                                            }
                                                                                                            result = i12 + 8;
                                                                                                            a1 =  + (__int64)(__int64)i11*2;
                                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)i11);
                                                                                                            a1 = result + (__int64)(__int64)a1*8;
                                                                                                            i2 = (struct Struct_2_t *)i10;
                                                                                                            i2 = (struct Struct_2_t *)((__int64)i2 - (__int64)i3);
                                                                                                            i2 = (struct Struct_2_t *)((__int64)(__int64)i2 << 3);
                                                                                                            a3 = i2 + (__int64)(__int64)i2*2;
                                                                                                            sub_1400F27F6(a1, i7, a3);
                                                                                                            *i7 = i;
                                                                                                            xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                            _mm_storeu_si128((__m128i *)(i7 + 8), xmm0);
                                                                                                            i7 =  + (__int64)(__int64)i3*8;
                                                                                                            a2 = (__int64)i12 + (__int64)i7 + 272;
                                                                                                            i =  + (__int64)(__int64)i11*8;
                                                                                                            a1 = (__int64)i12 + (__int64)i;
                                                                                                            a1 += 272;
                                                                                                            sub_1400F27F6(a1, a2, i2);
                                                                                                            result = (__int64 *)v_28;
                                                                                                            *(__int64 *)((__int64)i12 + (__int64)i7 + 272) = result;
                                                                                                            result = (__int64 *)v_30;
                                                                                                            *(__int64 *)((__int64)i12 + (__int64)i7 + 276) = result;
                                                                                                            a2 = (__int64)i12 + (__int64)i;
                                                                                                            a2 += 368;
                                                                                                            a1 = (__int64)i12 + (__int64)i7;
                                                                                                            a1 += 384;
                                                                                                            sub_1400F27F6(a1, a2, i2);
                                                                                                            return (__int64)a1;
                                                                                                        }
                                                                                                        if (i9 == 5) {
                                                                                                            a1 = (size_t *)i3;
                                                                                                            return (__int64)a1;
                                                                                                        }
                                                                                                        i2 = (struct Struct_2_t *)a3;
                                                                                                        if (i3 != 6) {
                                                                                                            i10 = i3 - 7;
                                                                                                            a1 = 6;
                                                                                                            i9 = off_140108030;
                                                                                                            v_330 = (__int64)i11;
                                                                                                            v_338 = (__int64)result;
                                                                                                            v_340 = (int)a1;
                                                                                                            a1 = rsp + 0x5B0;
                                                                                                            a2 = rsp + 816;
                                                                                                            sub_1400F1290(a1, a2, a3, a4);
                                                                                                            i12 = (__int64 *)v_5e0;
                                                                                                            i11 = (__int64 *)arg_16a;
                                                                                                            i3 = i10 + 1;
                                                                                                            i8 = (__int64)i11;
                                                                                                            result = i10 + (__int64)(__int64)i10*2;
                                                                                                            i7 = i12 + (__int64)(__int64)result*8;
                                                                                                            i7 += 8;
                                                                                                            i8 -= (__int64)i10;
                                                                                                            if ((i8 <= 0)) {
                                                                                                                *i7 = i2;
                                                                                                                xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                                _mm_storeu_si128((__m128i *)(i7 + 8), xmm0);
                                                                                                                result = (__int64 *)v_28;
                                                                                                                v_110[(__int64)i10] = result;
                                                                                                                v_114[(__int64)i10] = i;
                                                                                                                ptr = (struct Struct_3_t *)v_70;
                                                                                                                a2 = (int *)i5;
                                                                                                                a1 = i11 + 1;
                                                                                                                result = i11 + 2;
                                                                                                                v_178[(__int64)i10] = a2;
                                                                                                                arg_16a = (__int64)a1;
                                                                                                                i7 = 0xF1357AEA2E62A9C5;
                                                                                                                if (i3 >= result) {
                                                                                                                    a3 = (int *)v_5b0;
                                                                                                                    result = rsp + 0x5B8;
                                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                                                                    _mm_store_si128((__m128i *)&v_1a0, xmm0);
                                                                                                                    a2 = (int *)v_5c8;
                                                                                                                    i = (struct Struct_1_t *)v_5cc;
                                                                                                                    result = (__int64 *)v_5d0;
                                                                                                                    v_20 = (__int64)result;
                                                                                                                    result = (__int64 *)v_5d8;
                                                                                                                    return (__int64)result;
                                                                                                                }
                                                                                                                i11 = (__int64 *)((__int64)i11 - (__int64)i10);
                                                                                                                ++i11;
                                                                                                                i11 = (__int64 *)((__int64)(__int64)i11 & 3);
                                                                                                                if ((i11 == 0)) {
                                                                                                                    if (i8 < 3) {
                                                                                                                        return (__int64)i11;
                                                                                                                    }
                                                                                                                    for (; i3 != result; i3 += 4) {
                                                                                                                        a1 = v_170[(__int64)i3];
                                                                                                                        *a1 = i12;
                                                                                                                        a1[45] = i3;
                                                                                                                        a1 = v_178[(__int64)i3];
                                                                                                                        *a1 = i12;
                                                                                                                        a2 = i3 + 1;
                                                                                                                        a1[45] = a2;
                                                                                                                        a1 = v_180[(__int64)i3];
                                                                                                                        *a1 = i12;
                                                                                                                        a2 = i3 + 2;
                                                                                                                        a1[45] = a2;
                                                                                                                        a1 = v_188[(__int64)i3];
                                                                                                                        *a1 = i12;
                                                                                                                        a2 = i3 + 3;
                                                                                                                        a1[45] = a2;
                                                                                                                    }
                                                                                                                    return (__int64)i3;
                                                                                                                }
                                                                                                                a2 = i12 + (__int64)(__int64)i10*8;
                                                                                                                a2 += 376;
                                                                                                                for (a1 = 0; i11 != a1; ++a1) {
                                                                                                                    a3 = v_0[(__int64)a1];
                                                                                                                    *a3 = i12;
                                                                                                                    a4 = (__int64)a1 + (__int64)i3;
                                                                                                                    a3[45] = a4;
                                                                                                                }
                                                                                                                i3 = (struct Struct_4_t *)((__int64)i3 + (__int64)a1);
                                                                                                                return (__int64)i3;
                                                                                                            }
                                                                                                            result = i12 + 8;
                                                                                                            a1 =  + (__int64)(__int64)i3*2;
                                                                                                            a1 = (size_t *)((__int64)a1 + (__int64)i3);
                                                                                                            a1 = result + (__int64)(__int64)a1*8;
                                                                                                            v_30 = (__int64)i;
                                                                                                            i = (struct Struct_1_t *)i11;
                                                                                                            i = (struct Struct_1_t *)((__int64)i - (__int64)i10);
                                                                                                            i = (struct Struct_1_t *)((__int64)(__int64)i << 3);
                                                                                                            a3 = i + (__int64)(__int64)i*2;
                                                                                                            v_20 = i8;
                                                                                                            sub_1400F27F6(a1, i7, a3);
                                                                                                            *i7 = i2;
                                                                                                            xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                            _mm_storeu_si128((__m128i *)(i7 + 8), xmm0);
                                                                                                            a2 = i12 + (__int64)(__int64)i10*8;
                                                                                                            a2 += 272;
                                                                                                            a1 = i12 + (__int64)(__int64)i3*8;
                                                                                                            a1 += 272;
                                                                                                            sub_1400F27F6(a1, a2, i);
                                                                                                            result = (__int64 *)v_28;
                                                                                                            v_110[(__int64)i10] = result;
                                                                                                            result = (__int64 *)v_30;
                                                                                                            v_114[(__int64)i10] = result;
                                                                                                            a2 = i12 + (__int64)(__int64)i3*8;
                                                                                                            a2 += 368;
                                                                                                            a1 = i12 + (__int64)(__int64)i10*8;
                                                                                                            a1 += 384;
                                                                                                            sub_1400F27F6(a1, a2, i);
                                                                                                            i8 = v_20;
                                                                                                            return i8;
                                                                                                        }
                                                                                                        a1 = 5;
                                                                                                        i10 = 0;
                                                                                                        return (__int64)i10;
                                                                                                    }
                                                                                                    v_30 = (__int64)i;
                                                                                                    i = i3 + 1;
                                                                                                    result =  + (__int64)(__int64)i3*2;
                                                                                                    result = (__int64 *)((__int64)result + (__int64)i3);
                                                                                                    i7 =  + (__int64)(__int64)result*8 + 8;
                                                                                                    i7 = (__int64 *)((__int64)i7 + (__int64)i11);
                                                                                                    if (i9 >= i2) {
                                                                                                        *i7 = a3;
                                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                        _mm_storeu_si128((__m128i *)(i7 + 8), xmm0);
                                                                                                        result = (__int64 *)v_28;
                                                                                                        arg_110[(__int64)i3] = result;
                                                                                                        result = (__int64 *)v_30;
                                                                                                        arg_114[(__int64)i3] = result;
                                                                                                    } else {
                                                                                                        result = i11 + 8;
                                                                                                        a1 = i + (__int64)(__int64)i*2;
                                                                                                        a1 = result + (__int64)(__int64)a1*8;
                                                                                                        i12 = (__int64 *)i2;
                                                                                                        i12 = (__int64 *)((__int64)i12 - (__int64)i3);
                                                                                                        i12 = (__int64 *)((__int64)(__int64)i12 << 3);
                                                                                                        i9 = (__int64 *)a3;
                                                                                                        a3 = i12 + (__int64)(__int64)i12*2;
                                                                                                        sub_1400F27F6(a1, i7, a3);
                                                                                                        *i7 = i9;
                                                                                                        xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                                                                        _mm_storeu_si128((__m128i *)(i7 + 8), xmm0);
                                                                                                        i7 =  + (__int64)(__int64)i3*8;
                                                                                                        a2 = (__int64)i11 + (__int64)i7 + 272;
                                                                                                        i9 =  + (__int64)(__int64)i*8;
                                                                                                        a1 = (__int64)i9 + (__int64)i11;
                                                                                                        a1 += 272;
                                                                                                        sub_1400F27F6(a1, a2, i12);
                                                                                                        result = (__int64 *)v_28;
                                                                                                        *(__int64 *)((__int64)i11 + (__int64)i7 + 272) = result;
                                                                                                        result = (__int64 *)v_30;
                                                                                                        *(__int64 *)((__int64)i11 + (__int64)i7 + 276) = result;
                                                                                                        a2 = (__int64)i9 + (__int64)i11;
                                                                                                        a2 += 368;
                                                                                                        a1 = (__int64)i7 + (__int64)i11;
                                                                                                        a1 += 384;
                                                                                                        sub_1400F27F6(a1, a2, i12);
                                                                                                        a2 = (int *)i5;
                                                                                                        ptr = (struct Struct_3_t *)v_70;
                                                                                                    }
                                                                                                    i9 = off_140108030;
                                                                                                    a1 = i2 + 1;
                                                                                                    result = i2 + 2;
                                                                                                    arg_178[(__int64)i3] = a2;
                                                                                                    arg_16a = (__int64)a1;
                                                                                                    i7 = 0xF1357AEA2E62A9C5;
                                                                                                    if (i < result) {
                                                                                                        a1 = (size_t *)i2;
                                                                                                        a1 = (size_t *)((__int64)a1 - (__int64)i3);
                                                                                                        ++a1;
                                                                                                        a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                                                                                        if (!((a1 == 0))) {
                                                                                                            a3 =  + (__int64)(__int64)i3*8 + 376;
                                                                                                            a3 = (int *)((__int64)a3 + (__int64)i11);
                                                                                                            for (a2 = 0; a1 != a2; ++a2) {
                                                                                                                a4 = a3[(__int64)a2];
                                                                                                                *a4 = i11;
                                                                                                                i8 = (__int64)i + (__int64)a2;
                                                                                                                arg_168 = i8;
                                                                                                            }
                                                                                                            i = (struct Struct_1_t *)((__int64)i + (__int64)a2);
                                                                                                        }
                                                                                                        i2 = (struct Struct_2_t *)((__int64)i2 - (__int64)i3);
                                                                                                        if (i2 >= 3) {
                                                                                                            for (; i != result; i += 4) {
                                                                                                                a1 = arg_170[(__int64)i];
                                                                                                                *a1 = i11;
                                                                                                                a1[45] = i;
                                                                                                                a1 = arg_178[(__int64)i];
                                                                                                                *a1 = i11;
                                                                                                                a2 = i + 1;
                                                                                                                a1[45] = a2;
                                                                                                                a1 = arg_180[(__int64)i];
                                                                                                                *a1 = i11;
                                                                                                                a2 = i + 2;
                                                                                                                a1[45] = a2;
                                                                                                                a1 = arg_188[(__int64)i];
                                                                                                                *a1 = i11;
                                                                                                                a2 = i + 3;
                                                                                                                a1[45] = a2;
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                    i3 = (struct Struct_4_t *)v_78;
                                                                                                    return (__int64)i3;
                                                                                                } while (i11 != 0);
                                                                                                return (__int64)i3;
                                                                                            }
                                                                                            return (__int64)i3;
                                                                                        } else {
                                                                                            i3 = (struct Struct_4_t *)v_78;
                                                                                            i12 = off_140108038;
                                                                                        }
                                                                                        return (__int64)i12;
                                                                                    } else {
                                                                                        i11 = (__int64 *)v_80;
                                                                                        if (i12 == 0) JUMPOUT(0x1400ef41b);
                                                                                        *i12 = 0;
                                                                                        i2 = (struct Struct_2_t *)v_20;
                                                                                        i9 = i2->field_16A;
                                                                                        i9 -= 5;
                                                                                        arg_16a = (__int64)i9;
                                                                                        if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                                                                        result = 112;
                                                                                        v_68 = (__int64)result;
                                                                                        v_60 = 4;
                                                                                        result = 312;
                                                                                        v_88 = (__int64)result;
                                                                                        a2 = 128;
                                                                                        result = 308;
                                                                                        a1 = 304;
                                                                                        a3 = 104;
                                                                                    }
                                                                                    return (__int64)a3;
                                                                                } else {
                                                                                    result =  + (__int64)(__int64)i3*2;
                                                                                    result = (__int64 *)((__int64)result + (__int64)i3);
                                                                                    i12 =  + (__int64)(__int64)result*8;
                                                                                    i12 = (__int64 *)((__int64)i12 + (__int64)i11);
                                                                                    i9 = off_140108030;
                                                                                    if (i <= i3) {
                                                                                        *i12 = i10;
                                                                                        arg_8 = (__int64)i7;
                                                                                        arg_10 = (__int64)i10;
                                                                                    } else {
                                                                                        result =  + (__int64)(__int64)i3*2 + 3;
                                                                                        result = (__int64 *)((__int64)result + (__int64)i3);
                                                                                        a1 =  + (__int64)(__int64)result*8;
                                                                                        a1 = (size_t *)((__int64)a1 + (__int64)i11);
                                                                                        i11 = (__int64 *)i;
                                                                                        i11 = (__int64 *)((__int64)i11 - (__int64)i3);
                                                                                        i11 = (__int64 *)((__int64)(__int64)i11 << 3);
                                                                                        a3 =  + (__int64)(__int64)i11*2;
                                                                                        a3 = (int *)((__int64)a3 + (__int64)i11);
                                                                                        sub_1400F27F6(a1, i12, a3);
                                                                                        *i12 = i10;
                                                                                        arg_8 = (__int64)i7;
                                                                                        arg_10 = (__int64)i10;
                                                                                        a2 = i2 + (__int64)(__int64)i3*8;
                                                                                        a2 += 272;
                                                                                        a1 = i2 + (__int64)(__int64)i3*8;
                                                                                        a1 += 280;
                                                                                        sub_1400F27F6(a1, a2, i11);
                                                                                    }
                                                                                    i11 = (__int64 *)v_80;
                                                                                    ptr = (struct Struct_3_t *)v_70;
                                                                                    result = (__int64 *)i5;
                                                                                    ++i;
                                                                                    *(__int64 *)(i2 + (__int64)(__int64)i3*8 + 272) = (__int64)(result);
                                                                                    result = (__int64 *)v_c0;
                                                                                    *(__int64 *)(i2 + (__int64)(__int64)i3*8 + 276) = (__int64)(result);
                                                                                    i2->field_16A = i;
                                                                                    i10 = (__int64 *)v_90;
                                                                                    i7 = 0xF1357AEA2E62A9C5;
                                                                                }
                                                                                return (__int64)i7;
                                                                            }
                                                                            i9 = off_140108030;
                                                                            i12 = off_140108038;
                                                                            if (i10 != 0) {
                                                                                ((__int64 (*)())i9)(i);
                                                                                ((__int64 (*)())i12)(result, 0, i7);
                                                                            }
                                                                            result = (__int64 *)i5;
                                                                            a1 = (size_t *)v_20;
                                                                            v_110[(__int64)i3] = result;
                                                                            result = (__int64 *)v_c0;
                                                                            v_114[(__int64)i3] = result;
                                                                            i3 = (struct Struct_4_t *)v_78;
                                                                            i10 = (__int64 *)v_90;
                                                                            i7 = 0xF1357AEA2E62A9C5;
                                                                            i11 = (__int64 *)v_80;
                                                                            ptr = (struct Struct_3_t *)v_70;
                                                                            return (__int64)ptr;
                                                                        }
                                                                        i = (struct Struct_1_t *)v_28;
                                                                        i3 = (struct Struct_4_t *)i;
                                                                        return (__int64)i3;
                                                                    } while (true);
                                                                }
                                                                return (__int64)i3;
                                                            }
                                                            i12 = off_140108038;
                                                            return (__int64)i12;
                                                        }
                                                        a1 = (size_t *)i7;
                                                        a1 = (size_t *)((__int64)a1 - (__int64)ptr);
                                                        ++a1;
                                                        a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                                        if ((a1 == 0)) {
                                                            i7 = (__int64 *)((__int64)i7 - (__int64)ptr);
                                                            if (i7 < 3) {
                                                                return (__int64)i7;
                                                            }
                                                            for (; i3 != result; i3 += 4) {
                                                                a1 = v_120[(__int64)i3];
                                                                *a1 = i12;
                                                                a1[34] = i3;
                                                                a1 = v_128[(__int64)i3];
                                                                *a1 = i12;
                                                                a2 = i3 + 1;
                                                                a1[34] = a2;
                                                                a1 = v_130[(__int64)i3];
                                                                *a1 = i12;
                                                                a2 = i3 + 2;
                                                                a1[34] = a2;
                                                                a1 = i6[(__int64)i3];
                                                                *a1 = i12;
                                                                a2 = i3 + 3;
                                                                a1[34] = a2;
                                                            }
                                                            return (__int64)i3;
                                                        }
                                                        a3 = i12 + (__int64)(__int64)ptr*8;
                                                        a3 += 296;
                                                        for (a2 = 0; a1 != a2; ++a2) {
                                                            a4 = a3[(__int64)a2];
                                                            *a4 = i12;
                                                            i8 = (__int64)a2 + (__int64)i3;
                                                            arg_110 = (__int64 *)i8;
                                                        }
                                                        i3 = (struct Struct_4_t *)((__int64)i3 + (__int64)a2);
                                                        return (__int64)i3;
                                                    }
                                                    result = i12 + 8;
                                                    a1 =  + (__int64)(__int64)i3*2;
                                                    a1 = (size_t *)((__int64)a1 + (__int64)i3);
                                                    a1 = result + (__int64)(__int64)a1*8;
                                                    i9 = i7;
                                                    i7 = (__int64 *)((__int64)i7 - (__int64)ptr);
                                                    result =  + (__int64)(__int64)i7*8;
                                                    v_60 = (__int64)result;
                                                    a3 = result + (__int64)(__int64)result*2;
                                                    sub_1400F27F6(a1, i, a3);
                                                    result = (__int64 *)v_28;
                                                    *(__int64 *)i = (__int64)(result);
                                                    xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                    _mm_storeu_si128((__m128i *)(i + 8), xmm0);
                                                    result = (__int64 *)v_20;
                                                    a2 = (__int64)i12 + (__int64)result + 276;
                                                    a1 = (__int64)i12 + (__int64)i3;
                                                    a1 += 276;
                                                    i7 = i9;
                                                    sub_1400F27F6(a1, a2, i7);
                                                    result = (__int64 *)v_30;
                                                    a1 = (size_t *)v_20;
                                                    *(__int64 *)((__int64)i12 + (__int64)a1 + 276) = result;
                                                    a2 = i12 + (__int64)(__int64)i3*8;
                                                    a2 += 288;
                                                    result = (__int64 *)v_20;
                                                    a1 = i12 + (__int64)(__int64)result*8;
                                                    a1 += 304;
                                                    a3 = (int *)v_60;
                                                    sub_1400F27F6(a1, a2, a3);
                                                    ptr = (struct Struct_3_t *)v_20;
                                                    return (__int64)ptr;
                                                }
                                                if (i9 == 5) {
                                                    a1 = (size_t *)ptr;
                                                    return (__int64)a1;
                                                }
                                                if (ptr != 6) {
                                                    i = ptr - 7;
                                                    a1 = 6;
                                                    i9 = off_140108030;
                                                    v_330 = (__int64)i7;
                                                    v_338 = (__int64)result;
                                                    v_340 = (int)a1;
                                                    a1 = rsp + 0x5B0;
                                                    a2 = rsp + 816;
                                                    sub_1400F1090(a1, a2, a3, a4);
                                                    i12 = (__int64 *)v_5e0;
                                                    i7 = (__int64 *)arg_112;
                                                    i3 = i + 1;
                                                    i8 = (__int64)i7;
                                                    result = i + (__int64)(__int64)i*2;
                                                    a1 = (size_t *)i;
                                                    i = i12 + (__int64)(__int64)result*8;
                                                    i += 8;
                                                    v_20 = (__int64)a1;
                                                    i8 -= (__int64)a1;
                                                    if ((i8 <= 0)) {
                                                        result = (__int64 *)v_28;
                                                        *(__int64 *)i = (__int64)(result);
                                                        xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                        _mm_storeu_si128((__m128i *)(i + 8), xmm0);
                                                        result = (__int64 *)v_30;
                                                        i = (struct Struct_1_t *)v_20;
                                                        *(__int64 *)((__int64)i12 + (__int64)i + 276) = result;
                                                        a2 = (int *)v_68;
                                                        a1 = i7 + 1;
                                                        result = i7 + 2;
                                                        v_128[(__int64)i] = a2;
                                                        arg_112 = (__int64)a1;
                                                        if (i3 >= result) {
                                                            a3 = (int *)v_5b0;
                                                            result = rsp + 0x5B8;
                                                            xmm0 = _mm_loadu_si128((__m128i *)result);
                                                            _mm_store_si128((__m128i *)&v_1a0, xmm0);
                                                            a2 = (int *)v_5c8;
                                                            result = (__int64 *)v_5d0;
                                                            v_20 = (__int64)result;
                                                            result = (__int64 *)v_5d8;
                                                            return (__int64)result;
                                                        }
                                                        i7 = (__int64 *)((__int64)i7 - (__int64)i);
                                                        ++i7;
                                                        i7 = (__int64 *)((__int64)(__int64)i7 & 3);
                                                        if ((i7 == 0)) {
                                                            if (i8 < 3) {
                                                                return (__int64)i7;
                                                            }
                                                            for (; i3 != result; i3 += 4) {
                                                                a1 = v_120[(__int64)i3];
                                                                *a1 = i12;
                                                                a1[34] = i3;
                                                                a1 = v_128[(__int64)i3];
                                                                *a1 = i12;
                                                                a2 = i3 + 1;
                                                                a1[34] = a2;
                                                                a1 = v_130[(__int64)i3];
                                                                *a1 = i12;
                                                                a2 = i3 + 2;
                                                                a1[34] = a2;
                                                                a1 = i6[(__int64)i3];
                                                                *a1 = i12;
                                                                a2 = i3 + 3;
                                                                a1[34] = a2;
                                                            }
                                                            return (__int64)i3;
                                                        }
                                                        a2 = i12 + (__int64)(__int64)i*8;
                                                        a2 += 296;
                                                        for (a1 = 0; i7 != a1; ++a1) {
                                                            a3 = v_0[(__int64)a1];
                                                            *a3 = i12;
                                                            a4 = (__int64)a1 + (__int64)i3;
                                                            a3[34] = a4;
                                                        }
                                                        i3 = (struct Struct_4_t *)((__int64)i3 + (__int64)a1);
                                                        return (__int64)i3;
                                                    }
                                                    result = i12 + 8;
                                                    a1 =  + (__int64)(__int64)i3*2;
                                                    a1 = (size_t *)((__int64)a1 + (__int64)i3);
                                                    a1 = result + (__int64)(__int64)a1*8;
                                                    result =  + i8*8;
                                                    v_88 = (__int64)result;
                                                    a3 = result + (__int64)(__int64)result*2;
                                                    v_60 = i8;
                                                    sub_1400F27F6(a1, i, a3);
                                                    result = (__int64 *)v_28;
                                                    *(__int64 *)i = (__int64)(result);
                                                    xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                    _mm_storeu_si128((__m128i *)(i + 8), xmm0);
                                                    i = (struct Struct_1_t *)v_20;
                                                    a2 = (__int64)i12 + (__int64)i;
                                                    a2 += 276;
                                                    a1 = (__int64)i12 + (__int64)i3;
                                                    a1 += 276;
                                                    a3 = (int *)v_60;
                                                    sub_1400F27F6(a1, a2, a3);
                                                    result = (__int64 *)v_30;
                                                    *(__int64 *)((__int64)i12 + (__int64)i + 276) = result;
                                                    a2 = i12 + (__int64)(__int64)i3*8;
                                                    a2 += 288;
                                                    a1 = i12 + (__int64)(__int64)i*8;
                                                    a1 += 304;
                                                    a3 = (int *)v_88;
                                                    sub_1400F27F6(a1, a2, a3);
                                                    i8 = v_60;
                                                    return i8;
                                                }
                                                a1 = 5;
                                                i = 0;
                                                return (__int64)i;
                                            }
                                            i3 = ptr + 1;
                                            result = ptr + (__int64)(__int64)ptr*2;
                                            i12 = i7 + (__int64)(__int64)result*8;
                                            i12 += 8;
                                            if (i9 >= i) {
                                                *i12 = a3;
                                                xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                _mm_storeu_si128((__m128i *)(i12 + 8), xmm0);
                                                result = (__int64 *)v_30;
                                                *(__int64 *)((__int64)i7 + (__int64)ptr + 276) = result;
                                            } else {
                                                result = i7 + 8;
                                                a1 =  + (__int64)(__int64)i3*2;
                                                a1 = (size_t *)((__int64)a1 + (__int64)i3);
                                                a1 = result + (__int64)(__int64)a1*8;
                                                result = (__int64 *)i;
                                                result = (__int64 *)((__int64)result - (__int64)ptr);
                                                v_60 = (__int64)result;
                                                result =  + (__int64)(__int64)result*8;
                                                v_20 = (__int64)result;
                                                a3 = result + (__int64)(__int64)result*2;
                                                i9 = (__int64 *)ptr;
                                                sub_1400F27F6(a1, i12, a3);
                                                result = (__int64 *)v_28;
                                                *i12 = result;
                                                xmm0 = _mm_load_si128((__m128i *)&v_d0);
                                                _mm_storeu_si128((__m128i *)(i12 + 8), xmm0);
                                                a2 = (__int64)i7 + (__int64)i9;
                                                a2 += 276;
                                                a1 = (__int64)i7 + (__int64)i3;
                                                a1 += 276;
                                                a3 = (int *)v_60;
                                                sub_1400F27F6(a1, a2, a3);
                                                result = (__int64 *)v_30;
                                                *(__int64 *)((__int64)i7 + (__int64)i9 + 276) = result;
                                                a2 = i7 + (__int64)(__int64)i3*8;
                                                a2 += 288;
                                                a1 = i7 + (__int64)(__int64)i9*8;
                                                a1 += 304;
                                                a3 = (int *)v_20;
                                                sub_1400F27F6(a1, a2, a3);
                                                ptr = (struct Struct_3_t *)i9;
                                                a2 = (int *)v_68;
                                            }
                                            i9 = off_140108030;
                                            a1 = i + 1;
                                            result = i + 2;
                                            v_128[(__int64)ptr] = a2;
                                            arg_112 = (__int64)a1;
                                            if (i3 < result) {
                                                a1 = (size_t *)i;
                                                a1 = (size_t *)((__int64)a1 - (__int64)ptr);
                                                ++a1;
                                                a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                                if (!((a1 == 0))) {
                                                    a3 = i7 + (__int64)(__int64)ptr*8;
                                                    a3 += 296;
                                                    for (a2 = 0; a1 != a2; ++a2) {
                                                        a4 = a3[(__int64)a2];
                                                        *a4 = i7;
                                                        i8 = (__int64)a2 + (__int64)i3;
                                                        arg_110 = (__int64 *)i8;
                                                    }
                                                    i3 = (struct Struct_4_t *)((__int64)i3 + (__int64)a2);
                                                }
                                                i = (struct Struct_1_t *)((__int64)i - (__int64)ptr);
                                                if (i >= 3) {
                                                    for (; i3 != result; i3 += 4) {
                                                        a1 = v_120[(__int64)i3];
                                                        *a1 = i7;
                                                        a1[34] = i3;
                                                        a1 = v_128[(__int64)i3];
                                                        *a1 = i7;
                                                        a2 = i3 + 1;
                                                        a1[34] = a2;
                                                        a1 = v_130[(__int64)i3];
                                                        *a1 = i7;
                                                        a2 = i3 + 2;
                                                        a1[34] = a2;
                                                        a1 = i6[(__int64)i3];
                                                        *a1 = i7;
                                                        a2 = i3 + 3;
                                                        a1[34] = a2;
                                                    }
                                                }
                                            }
                                            i3 = (struct Struct_4_t *)v_78;
                                            return (__int64)i3;
                                        } while (i7 != 0);
                                        return (__int64)i3;
                                    }
                                    return (__int64)i3;
                                } else {
                                    i3 = (struct Struct_4_t *)v_78;
                                    i12 = off_140108038;
                                }
                                return (__int64)i12;
                            } else {
                                i2 = (struct Struct_2_t *)v_30;
                                if (i12 == 0) JUMPOUT(0x1400ef40c);
                                *i12 = 0;
                                i = (struct Struct_1_t *)v_20;
                                i9 = i->field_112;
                                i9 -= 5;
                                arg_112 = (__int64)i9;
                                if (i9 >= 12) JUMPOUT(0x1400ef46a);
                                result = 112;
                                v_28 = (__int64)result;
                                v_60 = 4;
                                result = 281;
                                v_88 = (__int64)result;
                                a2 = 128;
                                result = 280;
                                a1 = 104;
                            }
                            return (__int64)a1;
                        } else {
                            a3 = (int *)i12;
                            result =  + (__int64)(__int64)i3*2;
                            result = (__int64 *)((__int64)result + (__int64)i3);
                            a2 = i2 + (__int64)(__int64)result*8;
                            a3 = (int *)((__int64)a3 - (__int64)i3);
                            i9 = off_140108030;
                            if ((a3 <= 0)) {
                                *a2 = i10;
                                arg_8 = (__int64)i7;
                                a2[2] = i10;
                            } else {
                                result =  + (__int64)(__int64)i3*2 + 3;
                                result = (__int64 *)((__int64)result + (__int64)i3);
                                a1 = i2 + (__int64)(__int64)result*8;
                                result =  + (__int64)(__int64)a3*8;
                                v_28 = (__int64)a3;
                                a3 = result + (__int64)(__int64)result*2;
                                i2 = (struct Struct_2_t *)a2;
                                sub_1400F27F6(a1, a2, a3, a4);
                                *(__int64 *)i2 = (__int64)(i10);
                                i2->field_8 = i7;
                                i2->field_10 = i10;
                                a2 = (__int64)i + (__int64)i3;
                                a2 += 276;
                                a1 = (__int64)i + (__int64)i3;
                                a1 += 277;
                                a3 = (int *)v_28;
                                sub_1400F27F6(a1, a2, a3);
                            }
                            result = (__int64 *)i5;
                            i2 = (struct Struct_2_t *)v_30;
                            ++i12;
                            *(__int64 *)((__int64)i + (__int64)i3 + 276) = result;
                            i->field_112 = i12;
                        }
                        return (__int64)i12;
                    }
                    i9 = off_140108030;
                    i12 = off_140108038;
                    i11 = (__int64 *)v_80;
                    if (i10 != 0) {
                        ((__int64 (*)())i9)(i);
                        ((__int64 (*)())i12)(result, 0, i7);
                    }
                    result = (__int64 *)i5;
                    a1 = (size_t *)v_20;
                    *(__int64 *)((__int64)a1 + (__int64)i3 + 276) = result;
                    i3 = (struct Struct_4_t *)v_78;
                    i2 = (struct Struct_2_t *)v_30;
                    if (i10 == 0) {
                        return (__int64)i2;
                    } else {
                        return (__int64)i2;
                    }
                    return (__int64)i2;
                }
                i12 = (__int64 *)v_28;
                i3 = (struct Struct_4_t *)i12;
                return (__int64)i3;
            } while (true);
        }
        return (__int64)i3;
    }
    return (__int64)result;
}