// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[64];
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[248];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 3 accesses on `ptr`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_5_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr3`
struct Struct_6_t {
    char _pad_start[272];
    __int64 field_110; // offset 272
    __int64 field_118; // offset 280
    __int64 field_120; // offset 288
    __int64 field_128; // offset 296
};

__int64 sub_1400F8CE0();
__int64 sub_1400F50F0();
__int64 sub_14008AB40();
__int64 sub_140073B30();
__int64 sub_140020C60();
__int64 sub_14008C1F0();
extern __int64 off_14008C520;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14008BDC0(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3, int a4) {
    __int64 rsp;
    int arg_8;
    int v_100;
    __int64 v_20;
    int v_28;
    int v_38;
    __int64 v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_c8;
    __int64 v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    int v_f0;
    struct Struct_4_t *ptr;
    struct Struct_6_t *ptr3;
    struct Struct_5_t *ptr2;
    struct Struct_3_t *result;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v9;
    __int64 v10;
    __int64 i;
    __int64 v6;
    __int64 v11;
    __int64 v8;
    __int64 v5;

    ptr = (struct Struct_4_t *)a4;
    ptr3 = (struct Struct_6_t *)a3;
    ptr2 = (struct Struct_5_t *)a1;
    result = a3 + 272;
    a1 = ((__int64 *)a3)[32];
    v_d0 = (__int64)result;
    v_d8 = 0;
    v_e0 = (int)a1;
    v_e8 = 0;
    xmm0 = _mm_loadu_si128((__m128i *)a2);
    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
    xmm2 = _mm_loadu_si128((__m128i *)(a2 + 32));
    xmm3 = _mm_loadu_si128((__m128i *)(a2 + 48));
    _mm_store_si128((__m128i *)&v_70, xmm0);
    _mm_store_si128((__m128i *)&v_80, xmm1);
    _mm_store_si128((__m128i *)&v_90, xmm2);
    _mm_store_si128((__m128i *)&v_a0, xmm3);
    v_b0 = 0;
    result = ((__int64 *)a3)[35];
    v9 = result->field_108;
    v10 = result->field_100;
    result = ((__int64 *)a3)[35];
    i = result->field_108;
    a1 = result->field_100;
    result = ((__int64 *)a3)[37];
    a3 = (struct Struct_2_t *)i;
    a3 = (struct Struct_2_t *)((__int64)a3 - (__int64)a1);
    if (a3 >= result) {
        result = (struct Struct_3_t *)((__int64)result + (__int64)result);
        a1 = ptr3 + 280;
        v6 = (__int64)a2;
        sub_1400F8CE0(a1, result);
        a2 = (struct Struct_1_t *)v6;
        result = ptr3->field_128;
    }
    v9 -= v10;
    a1 = ptr3->field_120;
    --result;
    result = (struct Struct_3_t *)((__int64)(__int64)result & i);
    result = (struct Struct_3_t *)((__int64)(__int64)result << 4);
    v11 = &off_14008C520;
    *(__int64 *)((__int64)a1 + (__int64)result) = v11;
    v10 = rsp + 112;
    *(__int64 *)((__int64)a1 + (__int64)result + 8) = v10;
    result = ptr3->field_118;
    ++i;
    result->field_108 = i;
    a1 = ptr3->field_110;
    a4 = 0x100000000;
    result = a1[62];
    while (!((i < 0))) {
        a3 = (struct Struct_2_t *)result;
        a3 = (struct Struct_2_t *)((__int64)(__int64)a3 | a4);
        /* cmpxchg %(__int64)a3, 496(%(__int64)a1) */;
        result = (struct Struct_3_t *)a3;
        result = (struct Struct_3_t *)((__int64)(__int64)result & 0xFFFF);
        if ((result != 0)) {
            if (v9 <= 0) {
                a3 = (struct Struct_2_t *)((__int64)(__int64)a3 >> 16);
                if (a3 == result) {
                    a1 += 472;
                    v9 = (__int64)a2;
                    sub_1400F50F0(a1, 1);
                    a2 = (struct Struct_1_t *)v9;
                }
                result = a2->field_40;
                a1 = a2->field_48;
                xmm0 = _mm_loadu_si128((__m128i *)(a2 + 80));
                a2 += 96;
                result = result->field_0;
                a4 = *a1;
                a1 = (__int64 *)arg_8;
                v_38 = (int)a2;
                _mm_storeu_si128((__m128i *)&v_28, xmm0);
                v_20 = (__int64)a1;
                v9 = rsp + 80;
                sub_14008AB40(v9, result, ptr, a4);
                v8 = v_50;
                v5 = v_58;
                result = (struct Struct_3_t *)v_60;
                v_48 = (__int64)result;
                result = (struct Struct_3_t *)v_d8;
                if (result != 3) {
                    sub_140073B30(ptr3);
                    while (result != 0) {
                        a1 = (__int64 *)v10;
                        a1 = (__int64 *)((__int64)(__int64)a1 ^ (__int64)a2);
                        a3 = (struct Struct_2_t *)result;
                        a3 = (struct Struct_2_t *)((__int64)(__int64)a3 ^ v11);
                        a3 = (struct Struct_2_t *)((__int64)(__int64)a3 | (__int64)a1);
                        if (!((a3 == 0))) {
                            ((__int64 (*)())result)(a2, a2, a3);
                            result = (struct Struct_3_t *)v_d8;
                            result = (struct Struct_3_t *)v_b0;
                            xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
                            if (result == 1) JUMPOUT(0x14008c1d3);
                            if (result != 2) JUMPOUT(0x14008c190);
                            a1 = _mm_cvtsi128_si64(xmm0);
                            xmm0 = _mm_shuffle_epi32(xmm0, 238);
                            a2 = _mm_cvtsi128_si64(xmm0);
                            sub_140020C60(a1, a2);
                        }
                        result = (struct Struct_3_t *)v_70;
                        if (result == 0) JUMPOUT(0x14008c208);
                        ptr3 = (struct Struct_6_t *)v_b8;
                        a1 = (__int64 *)v_c0;
                        v_68 = (int)a1;
                        v10 = v_c8;
                        v11 = v_b0;
                        xmm0 = _mm_loadu_si128((__m128i *)&v_88);
                        a1 = (__int64 *)v_78;
                        a3 = (struct Struct_2_t *)v_80;
                        a2 = (struct Struct_1_t *)v_a8;
                        v_60 = (int)a2;
                        xmm1 = _mm_loadu_si128((__m128i *)&v_98);
                        _mm_store_si128((__m128i *)&v_50, xmm1);
                        a2 = result->field_0;
                        a2 -= *a1;
                        a4 = a3->field_0;
                        result = a3->field_8;
                        v_38 = v9;
                        _mm_storeu_si128((__m128i *)&v_28, xmm0);
                        v_20 = (__int64)result;
                        a1 = rsp + 240;
                        sub_14008AB40(a1, a2, ptr, a4);
                        if (v11 != 0) {
                            ptr = (struct Struct_4_t *)v_68;
                            if (v11 != 1) {
                                result = ptr->field_0;
                                if (result != 0) {
                                    ((__int64 (*)())result)(ptr3);
                                }
                                if (ptr->field_8 != 0) {
                                    if (ptr->field_10 >= 17) {
                                        ptr3 = *(__int64 *)(ptr3 - 8);
                                    }
                                    ((__int64 (*)())off_140108030)();
                                    ((__int64 (*)())off_140108038)(result, 0, ptr3);
                                }
                            } else {
                                if (v10 != 0) {
                                    ptr3 += 24;
                                    v9 = off_140108030;
                                    v11 = off_140108038;
                                    do {
                                        ptr3 += 40;
                                        --v10;
                                    } while (!((v10 == 0)));
                                }
                            }
                        }
                        *(__int64 *)ptr2 = (__int64)(v8);
                        ptr2->field_8 = v5;
                        result = (struct Struct_3_t *)v_48;
                        ptr2->field_10 = result;
                        xmm0 = _mm_loadu_si128((__m128i *)&v_f0);
                        _mm_storeu_si128((__m128i *)(ptr2 + 24), xmm0);
                        result = (struct Struct_3_t *)v_100;
                        return sub_14008C1F0();
                    }
                    result = (struct Struct_3_t *)v_d8;
                    if (result != 3) JUMPOUT(0x14008c1a8);
                }
                return (__int64)result;
            }
            return (__int64)result;
        } else {
        }
        return (__int64)result;
    }
    a3 = (struct Struct_2_t *)result;
    result = (struct Struct_3_t *)a3;
    result = (struct Struct_3_t *)((__int64)(__int64)result & 0xFFFF);
    if (!((result == 0))) {
        return (__int64)result;
    }
    return (__int64)result;
}