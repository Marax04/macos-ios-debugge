// inferred from 4 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    char field_8; // offset 8
    __int64 field_9; // offset 9
    char _pad_9[15];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 61 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char field_8; // offset 8
    char field_9; // offset 9
    int field_A; // offset 10
    char _pad_A[2];
    __int64 field_10; // offset 16
    char field_18; // offset 24
    char field_19; // offset 25
    int field_1A; // offset 26
    char _pad_1A[2];
    __int64 field_20; // offset 32
    char field_28; // offset 40
    char field_29; // offset 41
    int field_2A; // offset 42
    char _pad_2A[2];
    __int64 field_30; // offset 48
    char field_38; // offset 56
    char field_39; // offset 57
    int field_3A; // offset 58
    char _pad_3A[2];
    __int64 field_40; // offset 64
    char field_48; // offset 72
    char field_49; // offset 73
    int field_4A; // offset 74
    char _pad_4A[2];
    __int64 field_50; // offset 80
    char field_58; // offset 88
    char field_59; // offset 89
    int field_5A; // offset 90
    char _pad_5A[2];
    __int64 field_60; // offset 96
    char field_68; // offset 104
    __int64 field_69; // offset 105
    char _pad_69[7];
    char field_78; // offset 120
    int field_79; // offset 121
    char _pad_79[3];
    __int64 field_80; // offset 128
    char field_88; // offset 136
    char field_89; // offset 137
    int field_8A; // offset 138
    char _pad_8A[2];
    __int64 field_90; // offset 144
    char field_98; // offset 152
    __int64 field_99; // offset 153
    char _pad_99[7];
    char field_A8; // offset 168
    __int64 field_A9; // offset 169
    char _pad_A9[7];
    char field_B8; // offset 184
    char field_B9; // offset 185
    int field_BA; // offset 186
    char _pad_BA[2];
    __int64 field_C0; // offset 192
    char field_C8; // offset 200
    char field_C9; // offset 201
    int field_CA; // offset 202
    char _pad_CA[2];
    __int64 field_D0; // offset 208
    char field_D8; // offset 216
    char field_D9; // offset 217
    int field_DA; // offset 218
    char _pad_DA[2];
    __int64 field_E0; // offset 224
    char field_E8; // offset 232
    char field_E9; // offset 233
    int field_EA; // offset 234
    char _pad_EA[2];
    __int64 field_F0; // offset 240
    char field_F8; // offset 248
    __int64 field_F9; // offset 249
    char _pad_F9[7];
    char field_108; // offset 264
    __int64 field_109; // offset 265
    char _pad_109[7];
    char field_118; // offset 280
    char field_119; // offset 281
    __int64 field_11A; // offset 282
};

// inferred from 12 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[1];
    char field_49; // offset 73
    char field_4A; // offset 74
    char field_4B; // offset 75
    char field_4C; // offset 76
    __int64 field_4D; // offset 77
};

__int64 sub_1400931BD();
__int64 sub_1400F87E0();
__int64 sub_14002EDF0();
__int64 sub_14008FF00();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_140094CC0();
__int64 sub_1400FAE10();
__int64 sub_140094C37();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140124814;
extern __int64 off_1401190A3;
extern __int64 off_1401248C8;
extern __int64 off_1401248A0;

__int64 __fastcall sub_140090040(size_t *a1, int *a2) {
    __int64 rsp;
    __int64 __rdx_rax;
    int arg_2;
    int arg_8;
    int v_100;
    __int64 v_108;
    int v_10e;
    __int64 v_118;
    int v_11e;
    __int64 v_128;
    int v_130;
    int v_1f0;
    int v_20;
    int v_200;
    int v_210;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    int v_49;
    int v_4a;
    int v_50;
    int v_58;
    int v_59;
    int v_60;
    int v_68;
    int v_69;
    int v_6a;
    __int64 v_70;
    int v_78;
    __int64 v_80;
    int v_88;
    int v_90;
    __int64 v_98;
    __int64 v_a0;
    int v_b0;
    __int64 v_c0;
    __int64 v_cc;
    __int64 v_d0;
    int v_d8;
    __int64 v_e0;
    int v_e8;
    __int64 v_f0;
    __int64 v_f8;
    int *v_0;
    struct Struct_3_t *ptr2;
    __m128i xmm0;
    struct Struct_2_t *ptr;
    __int64 v2;
    __int64 *dst;
    struct Struct_1_t *result;
    __int64 i;
    __int64 *dst2;
    __int64 *src;
    __int64 i2;
    __int64 i3;
    __int64 *dst3;
    __int64 v7;
    __int64 v8;
    __m128i xmm1;
    __m128i xmm2;

    ptr2 = (struct Struct_3_t *)a1;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)(a1 + 56), xmm0);
    _mm_storeu_si128((__m128i *)(a1 + 40), xmm0);
    ptr = a2[4];
    v2 = a2[5];
    v_90 = 0;
    v_130 = (int)a2;
    if (v2 == 0) {
        *(__int64 *)ptr2 = (__int64)(0);
    } else {
        v2 <<= 5;
        v2 += (__int64)ptr;
        a1 = ptr + 32;
        dst = 0x8000000000000000;
        result = 8;
        i = &off_140124814;
        dst2 = (__int64 *)ptr;
        do {
            src = dst2;
            dst2 = (__int64 *)a1;
            a1 = *(src + 16);
            a1 = 0;
            a1 = (dst2 != v2) ? 1 : 0;
            a1 = (size_t *)((__int64)(__int64)a1 << 5);
            a1 = (size_t *)((__int64)a1 + (__int64)dst2);
        } while (dst2 != v2);
        result = (struct Struct_1_t *)v_90;
        *(__int64 *)ptr2 = (__int64)(result);
        i2 = 2;
        a2 = 8;
        do {
            result = ptr2->field_4D;
            a1 = ptr2->field_49;
            a1 = (size_t *)((__int64)(__int64)(__int64)a1 * (__int64)result);
            a1 = (size_t *)((__int64)(__int64)a1 >> 8);
            result = ptr2->field_4A;
            result = (struct Struct_1_t *)((__int64)result + (__int64)result);
            result += (__int64)(__int64)result*2;
            result = (struct Struct_1_t *)((__int64)(__int64)result >> 8);
            i3 = (__int64)a1 + (__int64)result;
            ++i3;
            if (i3 < 3) i3 = i2;
            if (i3 >= 8) i3 = a2;
            dst3 = ptr->field_10;
            i3 *= (__int64)dst3;
            if (i3 >= dst2) JUMPOUT(0x140093bf4);
            result = (struct Struct_1_t *)i3;
            result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
            i = result + (__int64)(__int64)result*2;
            if (i == 0) {
                dst = 8;
                i3 = 0;
                v_d8 = i3;
                v_e0 = (__int64)dst;
                v_e8 = 0;
                result = ptr->field_0;
                v_c0 = (__int64)result;
                dst2 = ptr->field_8;
                *(__int64 *)ptr = (__int64)(0);
                ptr->field_8 = 8;
                ptr->field_10 = 0;
                a1 = dst3 + (__int64)(__int64)dst3*2;
                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                a1 = (size_t *)((__int64)a1 + (__int64)dst2);
                v_78 = (int)a1;
                v_f0 = (__int64)dst2;
                dst3 = 0x8000000000000000;
                if ((dst3 == 0)) {
                    src = (__int64 *)v_78;
                    result = (struct Struct_1_t *)src;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)dst2);
                    result = (struct Struct_1_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                    if (src == dst2) {
                        if (v_c0 == 0) {
                            i = ptr->field_8;
                            dst3 = ptr->field_10;
                            if (dst3 == 0) {
                                if (ptr->field_0 == 0) {
                                    result = (struct Struct_1_t *)v_e8;
                                    ptr->field_10 = result;
                                    xmm0 = _mm_loadu_si128((__m128i *)&v_d8);
                                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                                    ptr += 32;
                                    a2 = 8;
                                    dst2 = 0x2AAAAAAAAAAAAAB;
                                    result = ptr2->field_4C;
                                    v_80 = (__int64)result;
                                    if (result == 0) JUMPOUT(0x140093268);
                                    result = (struct Struct_1_t *)v_130;
                                    a1 = result->field_28;
                                    if (a1 == 0) JUMPOUT(0x140093268);
                                    result = (struct Struct_1_t *)v_130;
                                    a2 = result->field_20;
                                    a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                    dst2 = ptr2->field_8;
                                    result = ptr2->field_10;
                                    v7 = ptr2->field_18;
                                    v8 = ptr2->field_20;
                                    i = ptr2->field_40;
                                    v2 = ptr2->field_28;
                                    dst = 0;
                                    dst3 = 0x800000000000000A;
                                    return sub_1400931BD();
                                }
                                off_140108030();
                                off_140108038(result, 0, i);
                                return (__int64)dst3;
                            }
                            i3 = i + 32;
                            do {
                                i3 += 48;
                                --dst3;
                            } while (!((dst3 == 0)));
                            return (__int64)dst3;
                        }
                        off_140108030();
                        dst2 = (__int64 *)v_f0;
                        off_140108038(result, 0, dst2);
                        return (__int64)dst2;
                    }
                    i = (__int64)a2;
                    dst3 = dst2;
                    i >>= 5;
                    dst3 += 32;
                    do {
                        dst3 += 48;
                        --i;
                    } while (!((i == 0)));
                    return i;
                }
                v_f8 = (__int64)ptr;
                v_100 = v2;
                i2 = 0;
                a1 = (size_t *)v_f0;
                v2 = &off_1401190A3;
                v8 = 0xE38E38E38E38E38F;
                result = *a1;
                a2 = a1[5];
                v_210 = (int)a2;
                xmm0 = _mm_loadu_si128((__m128i *)(a1 + 24));
                _mm_store_si128((__m128i *)&v_200, xmm0);
                xmm0 = _mm_loadu_si128((__m128i *)(a1 + 8));
                a1 += 48;
                v_80 = (__int64)a1;
                _mm_store_si128((__m128i *)&v_1f0, xmm0);
                a1 = 0x800000000000001B;
                while (result != a1) {
                    v_40 = (__int64)result;
                    result = (struct Struct_1_t *)v_210;
                    a1 = rsp + 72;
                    a1[4] = result;
                    xmm0 = _mm_load_si128((__m128i *)&v_1f0);
                    xmm1 = _mm_load_si128((__m128i *)&v_200);
                    _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
                    _mm_storeu_si128((__m128i *)a1, xmm0);
                    result = ptr2->field_10;
                    dst2 = result + (__int64)(__int64)result*4;
                    dst2 = __ROL8__(dst2, 7);
                    a2 = ptr2->field_8;
                    src = (__int64 *)result;
                    a1 = ptr2->field_18;
                    a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                    i = (__int64)a1;
                    i ^= (__int64)result;
                    result = (struct Struct_1_t *)((__int64)(__int64)result ^ (__int64)ptr2->field_20);
                    src = (__int64 *)((__int64)(__int64)src << 17);
                    ptr2->field_10 = i;
                    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                    ptr2->field_8 = a2;
                    a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)src);
                    ptr2->field_18 = a1;
                    result = __ROL8__(result, 45);
                    ptr2->field_20 = result;
                    dst2 += (__int64)(__int64)dst2*8;
                    if (dst2 >= ptr2->field_49) {
                        dst2 = i + i*4;
                        dst2 = __ROL8__(dst2, 7);
                        src = (__int64 *)i;
                        src = (__int64 *)((__int64)(__int64)src << 17);
                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                        result = (struct Struct_1_t *)((__int64)(__int64)result ^ i);
                        i ^= (__int64)a1;
                        ptr2->field_10 = i;
                        a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                        ptr2->field_8 = a2;
                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)src);
                        ptr2->field_18 = a1;
                        result = __ROL8__(result, 45);
                        ptr2->field_20 = result;
                        dst2 += (__int64)(__int64)dst2*8;
                        if (dst2 >= ptr2->field_4B) {
                            a1 = (size_t *)v_40;
                            result = (struct Struct_1_t *)a1;
                            result = (struct Struct_1_t *)((__int64)(__int64)result ^ (__int64)dst3);
                            /* test a1 , a1 */;
                            a1 = 8;
                            if (0 /* unresolved: flags >= 0 */) result = a1;
                            a1 = result - 9;
                            if (a1 < 3) {
                                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_60);
                                _mm_store_si128((__m128i *)&v_b0, xmm2);
                                _mm_store_si128((__m128i *)&v_a0, xmm1);
                                _mm_store_si128((__m128i *)&v_90, xmm0);
                                if (i2 == v_d8) {
                                    a1 = rsp + 216;
                                    sub_1400F87E0(a1, a2, 8);
                                    v8 = 0xE38E38E38E38E38F;
                                }
                                dst = (__int64 *)v_e0;
                                result =  + i2*2;
                                result += i2;
                                result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                                xmm0 = _mm_load_si128((__m128i *)&v_90);
                                xmm1 = _mm_load_si128((__m128i *)&v_a0);
                                xmm2 = _mm_load_si128((__m128i *)&v_b0);
                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)result + 32), xmm2);
                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)result + 16), xmm1);
                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)result), xmm0);
                                ++i2;
                                v_e8 = i2;
                                a1 = (size_t *)v_80;
                                v2 = v_100;
                                ptr = (struct Struct_2_t *)v_f8;
                                i2 = 2;
                                return i2;
                            }
                            i2 = ptr2->field_10;
                            a1 =  + i2*4;
                            a1 += i2;
                            a1 = __ROL8__(a1, 7);
                            dst = ptr2->field_8;
                            a2 = (int *)i2;
                            i = ptr2->field_18;
                            i ^= (__int64)dst;
                            ptr = (struct Struct_2_t *)i;
                            ptr = (struct Struct_2_t *)((__int64)(__int64)ptr ^ i2);
                            i2 ^= ptr2->field_20;
                            a2 = (int *)((__int64)(__int64)a2 << 17);
                            ptr2->field_10 = ptr;
                            dst = (__int64 *)((__int64)(__int64)dst ^ i2);
                            ptr2->field_8 = dst;
                            i ^= (__int64)a2;
                            ptr2->field_18 = i;
                            i2 = __ROL8__(i2, 45);
                            ptr2->field_20 = i2;
                            a1 += (__int64)(__int64)a1*8;
                            if (a1 >= ptr2->field_4A) {
                                sub_14002EDF0(0, 48);
                                if (result == 0) JUMPOUT(0x140093532);
                                ptr = (struct Struct_2_t *)result;
                                a2 = rsp + 64;
                                sub_14008FF00(result, a2);
                                a1 = ptr->field_0;
                                result = (struct Struct_1_t *)a1;
                                result = (struct Struct_1_t *)((__int64)(__int64)result ^ (__int64)dst3);
                                if (a1 >= 0) result = dst2;
                                a1 = (size_t *)v_40;
                                a2 = (int *)a1;
                                a2 = (int *)((__int64)(__int64)a2 ^ (__int64)dst3);
                                if (a1 >= 0) a2 = dst2;
                                if (result != a2) {
                                    dst3 = 0;
                                    dst3 = (__int64 *)((__int64)(__int64)dst3 ^ 1);
                                    i = 1;
                                    result = (struct Struct_1_t *)v_d8;
                                    i2 = v_e8;
                                    result -= i2;
                                    if (i > result) {
                                        v_20 = 48;
                                        a1 = rsp + 216;
                                        sub_1400F2D20(a1, i2, i, 8);
                                        i2 = v_e8;
                                    }
                                    result = (struct Struct_1_t *)i;
                                    result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                                    dst2 = result + (__int64)(__int64)result*2;
                                    dst = (__int64 *)v_e0;
                                    a1 =  + i2*2;
                                    a1 += i2;
                                    a1 = (size_t *)((__int64)(__int64)a1 << 4);
                                    a1 = (size_t *)((__int64)a1 + (__int64)dst);
                                    sub_1400F27F0(a1, ptr, dst2);
                                    i2 += i;
                                    v_e8 = i2;
                                    off_140108030();
                                    off_140108038(result, 0, ptr);
                                    if (dst3 == 0) {
                                        dst3 = 0x8000000000000000;
                                        v8 = 0xE38E38E38E38E38F;
                                        if ((v_40 - 0) < 0) {
                                            return v8;
                                        }
                                        if (v_40 == 0) {
                                            if (v_58 == 0) {
                                                return v8;
                                            }
                                            i = v_60;
                                            off_140108030();
                                            off_140108038(result, 0, i);
                                            v8 = 0xE38E38E38E38E38F;
                                            return v8;
                                        }
                                        i = v_48;
                                        off_140108030();
                                        off_140108038(result, 0, i);
                                        v8 = 0xE38E38E38E38E38F;
                                        return v8;
                                    }
                                    ptr2->field_40 = ptr2->field_40 + 1;
                                    ptr2->field_28 = ptr2->field_28 + 1;
                                    return v8;
                                }
                                dst3 = 1;
                                if (result > 26) {
                                    return (__int64)dst3;
                                }
                                a1 = &off_1401248C8;
                                result = v_0[(__int64)result];
                                result = (struct Struct_1_t *)((__int64)result + (__int64)a1);
                                JUMPOUT(result);
                                result = ptr->field_A;
                                if (result != v_4a) {
                                    return (__int64)result;
                                }
                                result = ptr->field_8;
                                if (result != v_48) {
                                    return (__int64)result;
                                }
                                result = ptr->field_9;
                                dst3 = (result == v_49) ? 1 : 0;
                                return (__int64)dst3;
                            }
                            if (result == 0) {
                                if (v_48 == 0) {
                                    return (__int64)dst3;
                                }
                                dst3 = (__int64 *)v_58;
                                i3 = v_50;
                                result =  + (__int64)(__int64)ptr*4;
                                result = (struct Struct_1_t *)((__int64)result + (__int64)ptr);
                                result = __ROL8__(result, 7);
                                result += (__int64)(__int64)result*8;
                                v_28 = (__int64)result;
                                result = (struct Struct_1_t *)ptr;
                                result = (struct Struct_1_t *)((__int64)(__int64)result << 17);
                                i ^= (__int64)dst;
                                i2 ^= (__int64)ptr;
                                ptr = (struct Struct_2_t *)((__int64)(__int64)ptr ^ i);
                                dst = (__int64 *)((__int64)(__int64)dst ^ i2);
                                i2 = __ROL8__(i2, 45);
                                i ^= (__int64)result;
                                result =  + (__int64)(__int64)ptr*4;
                                result = (struct Struct_1_t *)((__int64)result + (__int64)ptr);
                                a1 = (size_t *)ptr;
                                a1 = (size_t *)((__int64)(__int64)a1 << 17);
                                i ^= (__int64)dst;
                                i2 ^= (__int64)ptr;
                                ptr = (struct Struct_2_t *)((__int64)(__int64)ptr ^ i);
                                ptr2->field_10 = ptr;
                                dst = (__int64 *)((__int64)(__int64)dst ^ i2);
                                ptr2->field_8 = dst;
                                i ^= (__int64)a1;
                                ptr2->field_18 = i;
                                i2 = __ROL8__(i2, 45);
                                ptr2->field_20 = i2;
                                if ((i < 0)) {
                                    sub_14002EDF0(0, 144);
                                    if (result == 0) JUMPOUT(0x140093f76);
                                    ptr = (struct Struct_2_t *)result;
                                    a1 = (size_t *)v_28;
                                    i3 ^= (__int64)a1;
                                    result = 0x8000000000000000;
                                    *(__int64 *)ptr = (__int64)(result);
                                    ptr->field_8 = 1;
                                    ptr->field_10 = i3;
                                    ptr->field_18 = dst3;
                                    result = 0x8000000000000001;
                                    ptr->field_30 = result;
                                    ptr->field_38 = 0;
                                    ptr->field_39 = dst3;
                                    ptr->field_48 = 1;
                                    ptr->field_50 = a1;
                                    ptr->field_58 = dst3;
                                    ptr->field_59 = 0x809;
                                    ptr->field_60 = result;
                                    ptr->field_68 = 0;
                                    ptr->field_69 = dst3;
                                    ptr->field_78 = 1;
                                    ptr->field_80 = 0;
                                    ptr->field_88 = dst3;
                                    ptr->field_89 = 0x800;
                                    dst3 = 1;
                                    i = 3;
                                    return i;
                                }
                                sub_14002EDF0(0, 96, result);
                                if (result == 0) JUMPOUT(0x140093f85);
                                ptr = (struct Struct_2_t *)result;
                                a1 = (size_t *)v_28;
                                i3 ^= (__int64)a1;
                                result = 0x8000000000000000;
                                *(__int64 *)ptr = (__int64)(result);
                                ptr->field_8 = 1;
                                ptr->field_10 = i3;
                                ptr->field_18 = dst3;
                                result = 0x8000000000000001;
                                ptr->field_30 = result;
                                ptr->field_38 = 0;
                                ptr->field_39 = dst3;
                                ptr->field_48 = 1;
                                ptr->field_50 = a1;
                                ptr->field_58 = dst3;
                                ptr->field_59 = 0x809;
                                dst3 = 1;
                                i = 2;
                                return i;
                            }
                            if (result != 1) {
                                return i;
                            }
                            result = (struct Struct_1_t *)v_69;
                            if (result > 9) {
                                return (__int64)result;
                            }
                            a1 = &off_1401248A0;
                            result = v_0[(__int64)result];
                            result = (struct Struct_1_t *)((__int64)result + (__int64)a1);
                            JUMPOUT(result);
                            dst3 = (__int64 *)v_68;
                            i3 = v_48;
                            result = (struct Struct_1_t *)v_49;
                            v_30 = (__int64)result;
                            a2 = rsp + 72;
                            result = (struct Struct_1_t *)arg_2;
                            a1 = (size_t *)arg_8;
                            v_108 = (__int64)result;
                            v_10e = (int)a1;
                            result = (struct Struct_1_t *)v_58;
                            v_28 = (__int64)result;
                            result = (struct Struct_1_t *)v_59;
                            v_38 = (__int64)result;
                            result = a2[2];
                            a1 = a2[3];
                            v_118 = (__int64)result;
                            v_11e = (int)a1;
                            result = (struct Struct_1_t *)v_6a;
                            v_d0 = (__int64)result;
                            sub_14002EDF0(0, 3, 0x800000000000000D, src);
                            if (result == 0) JUMPOUT(0x140094c44);
                            v_90 = 3;
                            v_98 = (__int64)result;
                            *(__int64 *)result = (__int64)(dst3);
                            v_a0 = 1;
                            a1 = 1;
                            v_88 = i3;
                            if ((i3 & 1) != 0) {
                                v_70 = (__int64)dst3;
                                if (((v_28 & 1) == 0)) {
                                    result = (struct Struct_1_t *)v_38;
                                    i3 = (__int64)a1;
                                    *(__int64 *)((__int64)dst2 + (__int64)a1) = result;
                                    ++i3;
                                    v_a0 = i3;
                                    result =  + (__int64)(__int64)ptr*4;
                                    result = (struct Struct_1_t *)((__int64)result + (__int64)ptr);
                                    result = __ROL8__(result, 7);
                                    dst3 = result + (__int64)(__int64)result*8;
                                    result = (struct Struct_1_t *)ptr;
                                    result = (struct Struct_1_t *)((__int64)(__int64)result << 17);
                                    i ^= (__int64)dst;
                                    i2 ^= (__int64)ptr;
                                    ptr = (struct Struct_2_t *)((__int64)(__int64)ptr ^ i);
                                    ptr2->field_10 = ptr;
                                    dst = (__int64 *)((__int64)(__int64)dst ^ i2);
                                    ptr2->field_8 = dst;
                                    i ^= (__int64)result;
                                    i2 = __ROL8__(i2, 45);
                                    ptr2->field_18 = i;
                                    result = (struct Struct_1_t *)dst3;
                                    a1 = 0xAAAAAAAAAAAAAAAB;
                                    result = (struct Struct_1_t *)((__int64)(__int64)(__int64)result * (__int64)a1); /* unsigned; high half in a2 */;
                                    ptr2->field_20 = i2;
                                    a2 = (int *)((__int64)(__int64)a2 >> 1);
                                    i = a2 + (__int64)(__int64)a2*2;
                                    dst = dst2;
                                    sub_140094CC0(ptr2, dst2, i3, src);
                                    i2 = (__int64)result;
                                    dst3 -= i;
                                    if ((dst3 == 0)) {
                                        if (i3 == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            a2 = (int *)v_98;
                                        }
                                        *(a2 + i3) = i2;
                                        ++i3;
                                        dst = (__int64 *)a2;
                                        sub_140094CC0(ptr2, dst, i3, src);
                                        i = (__int64)result;
                                        sub_14002EDF0(0, 144);
                                        ptr = (struct Struct_2_t *)result;
                                        src = (__int64 *)v_70;
                                        result = (struct Struct_1_t *)v_88;
                                        if ((result == 0)) JUMPOUT(0x140093f76);
                                        dst2 = 0x8000000000000001;
                                        *(__int64 *)ptr = (__int64)(dst2);
                                        ptr->field_8 = result;
                                        dst2 = (__int64 *)result;
                                        dst3 = (__int64 *)v_30;
                                        ptr->field_9 = dst3;
                                        a2 = rsp + 72;
                                        result = (struct Struct_1_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr->field_A = result;
                                        ptr->field_10 = a1;
                                        v8 = v_28;
                                        ptr->field_18 = v8;
                                        v7 = v_38;
                                        ptr->field_19 = v7;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr->field_1A = result;
                                        ptr->field_20 = a1;
                                        ptr->field_28 = i2;
                                        ptr->field_29 = 8;
                                        i3 = v_d0;
                                        ptr->field_2A = i3;
                                        result = 0x8000000000000001;
                                        ptr->field_30 = result;
                                        ptr->field_38 = dst2;
                                        ptr->field_39 = dst3;
                                        result = (struct Struct_1_t *)arg_2;
                                        a1 = (size_t *)arg_8;
                                        ptr->field_3A = result;
                                        ptr->field_40 = a1;
                                        ptr->field_48 = v8;
                                        ptr->field_49 = v7;
                                        result = a2[2];
                                        a1 = a2[3];
                                        ptr->field_50 = a1;
                                        ptr->field_4A = result;
                                        ptr->field_58 = i;
                                        ptr->field_59 = 7;
                                        ptr->field_5A = i3;
                                        result = 0x8000000000000001;
                                        ptr->field_60 = result;
                                        ptr->field_68 = 0;
                                        ptr->field_69 = i2;
                                        ptr->field_78 = 0;
                                        ptr->field_79 = i;
                                        ptr->field_88 = src;
                                        ptr->field_89 = 0;
                                        ptr->field_8A = i3;
                                        i = 3;
                                        if (v_90 == 0) {
                                            dst3 = 1;
                                            return (__int64)dst3;
                                        }
                                        off_140108030(a1, a2, 0x8000000000000002, src);
                                        off_140108038(result, 0, dst);
                                        return (__int64)dst3;
                                    }
                                    if (dst3 != 1) {
                                        i = 3;
                                        if (i3 == 3) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1, a2);
                                            i = v_90;
                                            a2 = (int *)v_98;
                                        }
                                        *(a2 + i3) = i2;
                                        dst3 = i3 + 1;
                                        v_a0 = (__int64)dst3;
                                        dst = (__int64 *)a2;
                                        sub_140094CC0(ptr2, dst, dst3, src);
                                        if (dst3 == i) {
                                            a1 = rsp + 144;
                                            i = (__int64)result;
                                            sub_1400FAE10(a1, a2);
                                            result = (struct Struct_1_t *)i;
                                            a2 = (int *)v_98;
                                        }
                                        v_128 = (__int64)result;
                                        *(a2 + i3 + 1) = result;
                                        dst3 = i3 + 2;
                                        v_a0 = (__int64)dst3;
                                        sub_140094CC0(ptr2, dst, dst3);
                                        dst = (__int64 *)v_90;
                                        if (dst3 == dst) {
                                            a1 = rsp + 144;
                                            i = (__int64)result;
                                            sub_1400FAE10(a1, a2);
                                            result = (struct Struct_1_t *)i;
                                            dst = (__int64 *)v_90;
                                        }
                                        dst3 = (__int64 *)v_98;
                                        v_cc = (__int64)result;
                                        *(dst3 + i3 + 2) = result;
                                        i = i3 + 3;
                                        v_a0 = i;
                                        sub_140094CC0(ptr2, dst3, i);
                                        dst3 = (__int64 *)result;
                                        if (i == dst) {
                                            a1 = rsp + 144;
                                            sub_1400FAE10(a1);
                                            a2 = (int *)v_98;
                                        }
                                        *(a2 + i3 + 3) = dst3;
                                        i3 += 4;
                                        dst = (__int64 *)a2;
                                        sub_140094CC0(ptr2, dst3, i3);
                                        i = (__int64)result;
                                        sub_14002EDF0(0, 288);
                                        if (result == 0) JUMPOUT(0x140093fe5);
                                        ptr = (struct Struct_2_t *)result;
                                        dst2 = 0x8000000000000002;
                                        *(__int64 *)result = (__int64)(dst2);
                                        a2 = (int *)v_88;
                                        result->field_8 = a2;
                                        v8 = v_30;
                                        result->field_9 = v8;
                                        result = (struct Struct_1_t *)v_108;
                                        a1 = (size_t *)v_10e;
                                        ptr->field_A = result;
                                        ptr->field_10 = a1;
                                        ptr->field_18 = 1;
                                        ptr->field_19 = i2;
                                        ptr->field_30 = dst2;
                                        v7 = v_28;
                                        ptr->field_38 = v7;
                                        src = (__int64 *)v_38;
                                        ptr->field_39 = src;
                                        result = (struct Struct_1_t *)v_118;
                                        a1 = (size_t *)v_11e;
                                        ptr->field_3A = result;
                                        ptr->field_40 = a1;
                                        ptr->field_48 = 1;
                                        a1 = (size_t *)v_128;
                                        ptr->field_49 = a1;
                                        result = 0x8000000000000001;
                                        ptr->field_60 = result;
                                        i3 = i2;
                                        i2 = (__int64)result;
                                        ptr->field_68 = 0;
                                        ptr->field_69 = i3;
                                        ptr->field_78 = 0;
                                        ptr->field_79 = a1;
                                        result = (struct Struct_1_t *)v_cc;
                                        ptr->field_88 = result;
                                        ptr->field_89 = 7;
                                        i3 = v_d0;
                                        ptr->field_8A = i3;
                                        ptr->field_90 = dst2;
                                        ptr->field_98 = 0;
                                        ptr->field_99 = result;
                                        ptr->field_A8 = 1;
                                        ptr->field_A9 = dst3;
                                        ptr->field_C0 = i2;
                                        ptr->field_C8 = a2;
                                        ptr->field_C9 = v8;
                                        result = (struct Struct_1_t *)v_108;
                                        a1 = (size_t *)v_10e;
                                        ptr->field_D0 = a1;
                                        ptr->field_CA = result;
                                        ptr->field_D8 = v7;
                                        ptr->field_D9 = src;
                                        result = (struct Struct_1_t *)v_118;
                                        a1 = (size_t *)v_11e;
                                        ptr->field_DA = result;
                                        ptr->field_E0 = a1;
                                        ptr->field_E8 = i;
                                        ptr->field_E9 = 7;
                                        ptr->field_EA = i3;
                                        ptr->field_F0 = i2;
                                        ptr->field_F8 = 0;
                                        ptr->field_F9 = dst3;
                                        ptr->field_108 = 0;
                                        ptr->field_109 = i;
                                        result = (struct Struct_1_t *)v_70;
                                        ptr->field_118 = result;
                                        ptr->field_119 = 0;
                                        ptr->field_11A = i3;
                                        i = 6;
                                        return i;
                                    }
                                    if (i3 == 3) {
                                        a1 = rsp + 144;
                                        sub_1400FAE10(a1, a2, ptr);
                                        a2 = (int *)v_98;
                                    }
                                    *(a2 + i3) = i2;
                                    ++i3;
                                    dst = (__int64 *)a2;
                                    sub_140094CC0(ptr2, dst, i3);
                                    i = (__int64)result;
                                    sub_14002EDF0(0, 192);
                                    if (result == 0) JUMPOUT(0x140093fa5);
                                    ptr = (struct Struct_2_t *)result;
                                    dst2 = 0x8000000000000001;
                                    *(__int64 *)result = (__int64)(dst2);
                                    dst3 = (__int64 *)v_88;
                                    result->field_8 = dst3;
                                    v8 = v_30;
                                    result->field_9 = v8;
                                    a2 = rsp + 72;
                                    result = (struct Struct_1_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr->field_A = result;
                                    ptr->field_10 = a1;
                                    v7 = v_28;
                                    ptr->field_18 = v7;
                                    src = (__int64 *)v_38;
                                    ptr->field_19 = src;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr->field_1A = result;
                                    ptr->field_20 = a1;
                                    ptr->field_28 = i2;
                                    ptr->field_29 = 9;
                                    i3 = v_d0;
                                    ptr->field_2A = i3;
                                    ptr->field_30 = dst2;
                                    ptr->field_38 = dst3;
                                    ptr->field_39 = v8;
                                    result = (struct Struct_1_t *)arg_2;
                                    a1 = (size_t *)arg_8;
                                    ptr->field_3A = result;
                                    ptr->field_40 = a1;
                                    ptr->field_48 = v7;
                                    ptr->field_49 = src;
                                    result = a2[2];
                                    a1 = a2[3];
                                    ptr->field_50 = a1;
                                    ptr->field_4A = result;
                                    ptr->field_58 = i;
                                    ptr->field_59 = 7;
                                    ptr->field_5A = i3;
                                    ptr->field_60 = dst2;
                                    ptr->field_68 = 0;
                                    ptr->field_69 = i;
                                    ptr->field_78 = 1;
                                    ptr->field_80 = 1;
                                    ptr->field_88 = i;
                                    ptr->field_89 = 10;
                                    ptr->field_8A = i3;
                                    ptr->field_90 = dst2;
                                    ptr->field_98 = 0;
                                    ptr->field_99 = i2;
                                    ptr->field_A8 = 0;
                                    ptr->field_A9 = i;
                                    result = (struct Struct_1_t *)v_70;
                                    ptr->field_B8 = result;
                                    ptr->field_B9 = 0;
                                    ptr->field_BA = i3;
                                    i = 4;
                                    return i;
                                }
                                i3 = (__int64)a1;
                                return i3;
                            }
                            result = (struct Struct_1_t *)v_30;
                            *(dst2 + 1) = result;
                            v_a0 = 2;
                            a1 = 2;
                            return (__int64)a1;
                        }
                        dst2 = (__int64 *)i;
                        dst2 = (__int64 *)((__int64)(__int64)dst2 << 17);
                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                        result = (struct Struct_1_t *)((__int64)(__int64)result ^ i);
                        src = (__int64 *)a1;
                        src = (__int64 *)((__int64)(__int64)src ^ i);
                        ptr2->field_10 = src;
                        a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                        ptr2->field_8 = a2;
                        a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)dst2);
                        result = __ROL8__(result, 45);
                        ptr2->field_18 = a1;
                        ptr2->field_20 = result;
                        if (i2 == v_d8) {
                            a1 = rsp + 216;
                            sub_1400F87E0(a1);
                            v8 = 0xE38E38E38E38E38F;
                        }
                        result = i + i*4;
                        result = __ROL8__(result, 7);
                        result += (__int64)(__int64)result*8;
                        a1 = (size_t *)v_e0;
                        a2 =  + i2*2;
                        a2 += i2;
                        a2 = (int *)((__int64)(__int64)a2 << 4);
                        *(__int64 *)((__int64)a1 + (__int64)a2) = dst2;
                        *(__int64 *)((__int64)a1 + (__int64)a2 + 8) = result;
                        ++i2;
                        ptr2->field_38 = ptr2->field_38 + 1;
                        v_e8 = i2;
                        ptr2->field_28 = ptr2->field_28 + 1;
                        return v_e8;
                    }
                    dst2 = (__int64 *)i;
                    dst2 = (__int64 *)((__int64)(__int64)dst2 << 17);
                    a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)a2);
                    result = (struct Struct_1_t *)((__int64)(__int64)result ^ i);
                    src = (__int64 *)a1;
                    src = (__int64 *)((__int64)(__int64)src ^ i);
                    ptr2->field_10 = src;
                    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                    ptr2->field_8 = a2;
                    a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)dst2);
                    result = __ROL8__(result, 45);
                    ptr2->field_18 = a1;
                    ptr2->field_20 = result;
                    a1 = ptr2->field_4D;
                    if (a1 == 0) JUMPOUT(0x140094006);
                    result = i + i*4;
                    result = __ROL8__(result, 7);
                    result += (__int64)(__int64)result*8;
                    a2 = (int *)result;
                    a2 = (int *)((__int64)(__int64)a2 >> 32);
                    if ((a2 == 0)) {
                        a2 = 0;
                        result = __rdx_rax / (__int64)a1; a2 = __rdx_rax % (__int64)a1; /* unsigned */;
                        ptr = (struct Struct_2_t *)a2;
                        i = -1;
                        dst3 = 0;
                        do {
                            a2 = ptr2->field_8;
                            result = ptr2->field_10;
                            a1 = result + (__int64)(__int64)result*4;
                            a1 = __ROL8__(a1, 7);
                            a1 += (__int64)(__int64)a1*8;
                            src = (__int64 *)result;
                            src = (__int64 *)((__int64)(__int64)src << 17);
                            dst2 = ptr2->field_18;
                            dst2 = (__int64 *)((__int64)(__int64)dst2 ^ (__int64)a2);
                            v7 = (__int64)dst2;
                            v7 ^= (__int64)result;
                            result = (struct Struct_1_t *)((__int64)(__int64)result ^ (__int64)ptr2->field_20);
                            a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                            dst2 = (__int64 *)((__int64)(__int64)dst2 ^ (__int64)src);
                            result = __ROL8__(result, 45);
                            a1 = (size_t *)((__int64)(__int64)a1 >> 61);
                            src = v7 + v7*4;
                            src = __ROL8__(src, 7);
                            i3 = *(a1 + v2);
                            a1 = src + (__int64)(__int64)src*8;
                            src = (__int64 *)v7;
                            src = (__int64 *)((__int64)(__int64)src << 17);
                            dst2 = (__int64 *)((__int64)(__int64)dst2 ^ (__int64)a2);
                            result = (struct Struct_1_t *)((__int64)(__int64)result ^ v7);
                            v7 ^= (__int64)dst2;
                            ptr2->field_10 = v7;
                            a2 = (int *)((__int64)(__int64)a2 ^ (__int64)result);
                            ptr2->field_8 = a2;
                            dst2 = (__int64 *)((__int64)(__int64)dst2 ^ (__int64)src);
                            ptr2->field_18 = dst2;
                            result = __ROL8__(result, 45);
                            ptr2->field_20 = result;
                            result = (struct Struct_1_t *)a1;
                            result = (struct Struct_1_t *)((__int64)(__int64)(__int64)result * v8); /* unsigned; high half in a2 */;
                            a2 = (int *)((__int64)(__int64)a2 >> 3);
                            result = a2 + (__int64)(__int64)a2*8;
                            a1 = (size_t *)((__int64)a1 - (__int64)result);
                            result = (struct Struct_1_t *)v_d8;
                            if (i2 == result) {
                                a1 = rsp + 216;
                                sub_1400F87E0(a1);
                                v8 = 0xE38E38E38E38E38F;
                            }
                            dst = (__int64 *)v_e0;
                            result =  + i2*2;
                            result += i2;
                            result = (struct Struct_1_t *)((__int64)(__int64)result << 4);
                            a1 = 0x800000000000000C;
                            *(__int64 *)((__int64)dst + (__int64)result) = a1;
                            result = 1;
                            i2 += (__int64)result;
                            v_e8 = i2;
                            dst3 = (__int64 *)((__int64)dst3 + (__int64)result);
                            ++i;
                        } while (i < ptr);
                        xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + 40));
                        xmm1 = _mm_cvtsi64_si128(dst3);
                        xmm1 = _mm_shuffle_epi32(xmm1, 68);
                        xmm1 = _mm_add_epi64(xmm1, xmm0);
                        _mm_storeu_si128((__m128i *)(ptr2 + 40), xmm1);
                        a2 = ptr2->field_8;
                        i = ptr2->field_10;
                        a1 = ptr2->field_18;
                        result = ptr2->field_20;
                        dst3 = 0x8000000000000000;
                        return (__int64)dst3;
                    }
                    a2 = 0;
                    result = __rdx_rax / (__int64)a1; a2 = __rdx_rax % (__int64)a1; /* unsigned */;
                    ptr = (struct Struct_2_t *)a2;
                    return (__int64)ptr;
                }
                v2 = v_100;
                ptr = (struct Struct_2_t *)v_f8;
                i2 = 2;
                dst2 = (__int64 *)v_80;
                return (__int64)dst2;
            }
            sub_14002EDF0(0, i, 0x2AAAAAAAAAAAAAB, src);
            dst = (__int64 *)result;
            if (result != 0) {
                return (__int64)dst;
            }
            return sub_140094C37();
        } while (ptr != v2);
        return (__int64)dst;
    }
    return (__int64)result;
}