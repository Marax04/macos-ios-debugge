// inferred from 5 accesses on `result`
struct Struct_1_t {
    char _pad_start[2];
    char field_2; // offset 2
    char field_3; // offset 3
    __int16 field_4; // offset 4
    char _pad_4[1];
    __int16 field_7; // offset 7
    __int64 field_9; // offset 9
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[10];
    int field_A; // offset 10
    char field_E; // offset 14
    int field_F; // offset 15
    __int64 field_13; // offset 19
};

// inferred from 8 accesses on `ptr2`
struct Struct_3_t {
    int field_0; // offset 0
    int field_4; // offset 4
    int field_8; // offset 8
    int field_C; // offset 12
    int field_10; // offset 16
    int field_14; // offset 20
    int field_18; // offset 24
    __int64 field_1C; // offset 28
};

// inferred from 24 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[2];
    char field_2; // offset 2
    int field_3; // offset 3
    __int16 field_7; // offset 7
    char field_9; // offset 9
    int field_A; // offset 10
    __int16 field_E; // offset 14
    char field_10; // offset 16
    int field_11; // offset 17
    __int16 field_15; // offset 21
    char field_17; // offset 23
    int field_18; // offset 24
    __int16 field_1C; // offset 28
    char field_1E; // offset 30
    int field_1F; // offset 31
    __int16 field_23; // offset 35
    char field_25; // offset 37
    int field_26; // offset 38
    __int16 field_2A; // offset 42
    char field_2C; // offset 44
    __int16 field_2D; // offset 45
    __int16 field_2F; // offset 47
    char field_31; // offset 49
    int field_32; // offset 50
    __int64 field_36; // offset 54
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400FB220();
__int64 sub_1400F2D20();
__int64 sub_1400F6010();
__int64 sub_1400A2E50();
__int64 sub_1400A39F0();
__int64 sub_1400F3326();
__int64 sub_1400F3360();
__int64 sub_1400A2D40();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400A24F0(size_t *a1, int *a2, size_t *a3, int *a4) {
    __int64 rsp;
    int v_150;
    int v_158;
    int v_20;
    __int64 v_34;
    __int64 v_38;
    int v_40;
    int v_44;
    __int64 v_48;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_98;
    int v_a0;
    __int64 v_a8;
    __int64 v_b0;
    int v_b8;
    __int64 v_c0;
    int v_c8;
    __int64 v_d0;
    __int64 v10;
    struct Struct_4_t *ptr3;
    struct Struct_2_t *ptr;
    __int64 i;
    struct Struct_3_t *ptr2;
    __int64 v7;
    __int64 v8;
    struct Struct_1_t *result;
    __int64 v5;
    __m128i xmm0;
    __int64 i2;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    v10 = (__int64)a4;
    ptr3 = (struct Struct_4_t *)a3;
    ptr = (struct Struct_2_t *)a2;
    i = (__int64)a1;
    ptr2 = (struct Struct_3_t *)v_158;
    v7 = v_150;
    v8 = (__int64)a3;
    v8 <<= 4;
    sub_14002EDF0(0, v8);
    if (result != 0) {
        v_38 = (__int64)result;
        sub_1400F27F0(result, ptr, v8);
        if (ptr3 >= 2) {
            if (ptr3 < 21) {
                a4 = (int *)v_38;
                result = a4 + v8;
                a3 = a4 + 16;
                a1 = 16;
                v5 = v_38;
                do {
                    a2 = (int *)a3;
                    a3 = a4[2];
                    a3 = a2 + 16;
                    a1 += 16;
                    a4 = a2;
                } while (a3 != result);
                v_58 = 0;
                v_60 = 8;
                xmm0 = _mm_setzero_si128();
                _mm_storeu_si128((__m128i *)&v_68, xmm0);
                v_78 = 1;
                v_98 = 0;
                _mm_storeu_si128((__m128i *)&v_80, xmm0);
                result = (struct Struct_1_t *)ptr3;
                result = (struct Struct_1_t *)((__int64)(__int64)result >> 58);
                if ((result == 0)) {
                    v_a0 = i;
                    ptr = (struct Struct_2_t *)ptr3;
                    ptr = (struct Struct_2_t *)((__int64)(__int64)ptr << 5);
                    sub_14002EDF0(0, ptr);
                    v_34 = v10;
                    v7 += v10;
                    v_a8 = (__int64)ptr3;
                    v_b0 = (__int64)result;
                    v_b8 = 0;
                    ptr = 0;
                    i2 = 0;
                    a2 = (int *)v_38;
                    do {
                        a1 = *(__int64 *)((__int64)a2 + (__int64)ptr + 4);
                        ptr3 = v7 + 55;
                        i = 0;
                        a1 = (__int64)a2 + (__int64)ptr;
                        xmm0 = _mm_loadu_si128((__m128i *)a1);
                        _mm_store_si128((__m128i *)&v_40, xmm0);
                        if (i2 == v_a8) {
                            a1 = rsp + 168;
                            sub_1400FB220(a1, a2);
                            a2 = (int *)v_38;
                            result = (struct Struct_1_t *)v_b0;
                        }
                        ++i2;
                        *(__int64 *)(result + (__int64)(__int64)ptr*2) = (__int64)(i);
                        *(__int64 *)(result + (__int64)(__int64)ptr*2 + 4) = (__int64)(v10);
                        xmm0 = _mm_load_si128((__m128i *)&v_40);
                        _mm_storeu_si128((__m128i *)(result + (__int64)(__int64)ptr*2 + 8), xmm0);
                        *(__int64 *)(result + (__int64)(__int64)ptr*2 + 24) = (__int64)(v7);
                        *(__int64 *)(result + (__int64)(__int64)ptr*2 + 28) = (__int64)(ptr2);
                        v_b8 = i2;
                        ptr2 += 32;
                        ptr += 16;
                        v7 = (__int64)ptr3;
                    } while (v8 != ptr);
                    ptr2 = (struct Struct_3_t *)v_b0;
                    i2 <<= 5;
                    i2 += (__int64)ptr2;
                    result = ptr2 + 32;
                    a1 = (size_t *)v_34;
                    v_c8 = (int)a1;
                    v_c0 = (__int64)ptr2;
                    v_d0 = (__int64)result;
                    i = ptr2->field_8;
                    v7 = ptr2->field_C;
                    ptr = ptr2->field_10;
                    result = ptr2->field_14;
                    v_34 = (__int64)result;
                    v10 = ptr2->field_18;
                    v8 = ptr2->field_1C;
                    sub_14002EDF0(0, 55);
                    while (result != 0) {
                        ptr3 = (struct Struct_4_t *)result;
                        a1 = v10 + 7;
                        result = (struct Struct_1_t *)v8;
                        result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                        a1 = (size_t *)result;
                        if (result == result) {
                            ptr3->field_2 = 13;
                            *(__int64 *)ptr3 = (__int64)(0x8948);
                            ptr3->field_3 = result;
                            a1 = v10 + 14;
                            result = v8 + 8;
                            result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                            a1 = (size_t *)result;
                            if (result == result) {
                                ptr3->field_9 = 21;
                                ptr3->field_7 = 0x8948;
                                ptr3->field_A = result;
                                a1 = v10 + 21;
                                result = v8 + 16;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                a1 = (size_t *)result;
                                if (result == result) {
                                    ptr3->field_10 = 5;
                                    ptr3->field_E = 0x894C;
                                    ptr3->field_11 = result;
                                    a1 = v10 + 28;
                                    result = (struct Struct_1_t *)v8;
                                    result += 24;
                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                    a1 = (size_t *)result;
                                    if (result == result) {
                                        ptr3->field_17 = 13;
                                        ptr3->field_15 = 0x894C;
                                        ptr3->field_18 = result;
                                        a1 = v10 + 35;
                                        result = (struct Struct_1_t *)ptr;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                        a1 = (size_t *)result;
                                        if (result == result) {
                                            ptr3->field_1E = 13;
                                            ptr3->field_1C = 0x8D48;
                                            ptr3->field_1F = result;
                                            ptr3->field_23 = 0xC748;
                                            ptr3->field_25 = 194;
                                            result = (struct Struct_1_t *)v_34;
                                            ptr3->field_26 = result;
                                            result = v10 + 49;
                                            v8 -= (__int64)result;
                                            result = (struct Struct_1_t *)v8;
                                            if (v8 == v8) {
                                                ptr3->field_2C = 13;
                                                ptr3->field_2A = 0x8D4C;
                                                ptr3->field_2D = v8;
                                                v10 += 54;
                                                result = (struct Struct_1_t *)v_c8;
                                                result -= v10;
                                                a1 = (size_t *)result;
                                                if (result == result) {
                                                    ptr3->field_31 = 232;
                                                    ptr3->field_32 = result;
                                                    ptr3->field_36 = 195;
                                                    result = (struct Struct_1_t *)v_70;
                                                    a2 = (int *)v_80;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                    if (result <= 54) {
                                                        v_20 = 1;
                                                        a1 = rsp + 112;
                                                        sub_1400F2D20(a1, a2, 55, 1);
                                                        a2 = (int *)v_80;
                                                    }
                                                    v10 = i;
                                                    result = (struct Struct_1_t *)v_78;
                                                    a1 = ptr3->field_2F;
                                                    *(__int64 *)((__int64)result + (__int64)a2 + 47) = a1;
                                                    xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                                                    xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 16));
                                                    xmm2 = _mm_loadu_si128((__m128i *)(ptr3 + 32));
                                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 32), xmm2);
                                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 16), xmm1);
                                                    _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2), xmm0);
                                                    a2 += 55;
                                                    v_80 = (int)a2;
                                                    if (v7 >= 5) {
                                                        v8 = ptr2->field_18;
                                                        if (ptr2->field_0 == 0) {
                                                            result = v10 + 7;
                                                            ptr2 = (struct Struct_3_t *)ptr;
                                                            ptr2 = (struct Struct_3_t *)((__int64)ptr2 - (__int64)result);
                                                            result = (struct Struct_1_t *)ptr2;
                                                            if (ptr2 == ptr2) {
                                                                result = v10 + 19;
                                                                i = v8;
                                                                i -= (__int64)result;
                                                                result = (struct Struct_1_t *)i;
                                                                if (i == i) {
                                                                    sub_14002EDF0(0, 20);
                                                                    ptr = (struct Struct_2_t *)result;
                                                                    *(__int64 *)result = (__int64)(0x8D48);
                                                                    result->field_2 = 13;
                                                                    result->field_3 = ptr2;
                                                                    result->field_7 = 0xC748;
                                                                    result->field_9 = 194;
                                                                    result = (struct Struct_1_t *)v_34;
                                                                    ptr->field_A = result;
                                                                    ptr->field_E = 232;
                                                                    ptr->field_F = i;
                                                                    ptr->field_13 = 195;
                                                                    i = v_68;
                                                                    if (i == v_58) {
                                                                        a1 = rsp + 88;
                                                                        sub_1400F6010(a1, a2);
                                                                    }
                                                                    result = (struct Struct_1_t *)v_60;
                                                                    a1 = (size_t *)i;
                                                                    a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                                                    *(__int64 *)((__int64)result + (__int64)a1) = v10;
                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 8) = 20;
                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 16) = ptr;
                                                                    *(__int64 *)((__int64)result + (__int64)a1 + 24) = 20;
                                                                    ++i;
                                                                    v_68 = i;
                                                                    v_44 = v10;
                                                                    v_40 = 0;
                                                                    a1 = rsp + 220;
                                                                    a2 = rsp + 136;
                                                                    a4 = rsp + 64;
                                                                    sub_1400A2E50(a1, a2, v10, a4);
                                                                    off_140108030();
                                                                    ((__int64 (*)())off_140108038)(result, 0, ptr3);
                                                                    result = 0;
                                                                    a2 = (int *)v_d0;
                                                                    a1 = (a2 != i2) ? 1 : 0;
                                                                    if (a2 != i2) {
                                                                        result = (struct Struct_1_t *)a1;
                                                                        result = (struct Struct_1_t *)((__int64)(__int64)result << 5);
                                                                        result = (struct Struct_1_t *)((__int64)result + (__int64)a2);
                                                                        ptr2 = (struct Struct_3_t *)a2;
                                                                    }
                                                                    result = (struct Struct_1_t *)v_98;
                                                                    /* cmp v_a8 , 0 */;
                                                                    a1 = (size_t *)v_a0;
                                                                    a1[8] = result;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_58);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)&v_68);
                                                                    xmm2 = _mm_loadu_si128((__m128i *)&v_78);
                                                                    xmm3 = _mm_loadu_si128((__m128i *)&v_88);
                                                                    _mm_storeu_si128((__m128i *)(a1 + 48), xmm3);
                                                                    _mm_storeu_si128((__m128i *)(a1 + 32), xmm2);
                                                                    _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)a1, xmm0);
                                                                    if (!((0 /* unresolved: flags == */))) {
                                                                        off_140108030(a1);
                                                                        a3 = (size_t *)v_c0;
                                                                        ((__int64 (*)())off_140108038)(result, 0, a3);
                                                                    }
                                                                    off_140108030();
                                                                    a1 = (size_t *)result;
                                                                    a3 = (size_t *)v_38;
                                                                    JUMPOUT(off_140108038);
                                                                }
                                                            }
                                                            result = 0x8000000000000000;
                                                            a1 = (size_t *)v_a0;
                                                            *a1 = result;
                                                            off_140108030(a1, 0, a3);
                                                            ((__int64 (*)())off_140108038)(result, 0, ptr3);
                                                            if (v_a8 != 0) {
                                                                off_140108030(a1);
                                                                a3 = (size_t *)v_c0;
                                                                ((__int64 (*)())off_140108038)(result, 0, a3);
                                                            }
                                                        }
                                                        ptr2 = ptr2->field_4;
                                                        a1 = ptr2 + 7;
                                                        ptr = (struct Struct_2_t *)((__int64)ptr - (__int64)a1);
                                                        a1 = (size_t *)ptr;
                                                        if (ptr == ptr) {
                                                            a1 = ptr2 + 19;
                                                            v8 -= (__int64)a1;
                                                            a1 = (size_t *)v8;
                                                            if (v8 == v8) {
                                                                a1 = (size_t *)v_70;
                                                                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                                                                if (a1 <= 19) {
                                                                    v_20 = 1;
                                                                    a1 = rsp + 112;
                                                                    sub_1400F2D20(a1, a2, 20, 1);
                                                                    result = (struct Struct_1_t *)v_78;
                                                                    a2 = (int *)v_80;
                                                                }
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x8D48;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 13;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 3) = ptr;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 7) = 0xC748;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 9) = 194;
                                                                a1 = (size_t *)v_34;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 10) = a1;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 14) = 232;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 15) = v8;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 19) = 195;
                                                                a2 += 20;
                                                                v_80 = (int)a2;
                                                                result = v10 + 5;
                                                                i = (__int64)ptr2;
                                                                i -= (__int64)result;
                                                                result = (struct Struct_1_t *)i;
                                                                if (i == i) {
                                                                    sub_14002EDF0(0, 5);
                                                                    i <<= 8;
                                                                    i |= 233;
                                                                    *(__int64 *)result = (__int64)(i);
                                                                    i >>= 32;
                                                                    result->field_4 = i;
                                                                    i = v_68;
                                                                    if (i == v_58) {
                                                                        a1 = rsp + 88;
                                                                        ptr = (struct Struct_2_t *)result;
                                                                        sub_1400F6010(a1);
                                                                        result = (struct Struct_1_t *)ptr;
                                                                    }
                                                                    a1 = (size_t *)v_60;
                                                                    a2 = (int *)i;
                                                                    a2 = (int *)((__int64)(__int64)a2 << 5);
                                                                    *(__int64 *)((__int64)a1 + (__int64)a2) = v10;
                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 8) = 5;
                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 16) = result;
                                                                    *(__int64 *)((__int64)a1 + (__int64)a2 + 24) = 5;
                                                                    ++i;
                                                                    v_68 = i;
                                                                    v_44 = v10;
                                                                    v_48 = (__int64)ptr2;
                                                                    v_40 = 1;
                                                                    return v_40;
                                                                }
                                                            }
                                                        }
                                                        return v_40;
                                                    }
                                                    v_44 = v10;
                                                    v_48 = v7;
                                                    v_40 = 2;
                                                    return v_40;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        off_140108030(a1, a2);
                        ((__int64 (*)())off_140108038)(result, 0, ptr3);
                        result = 0x8000000000000000;
                        a1 = (size_t *)v_a0;
                        *a1 = result;
                        if (v_a8 == 0) {
                            do {
                                a1 = rsp + 88;
                                sub_1400A39F0(a1);
                                return (__int64)a1;
                            } while (true);
                        }
                        return (__int64)a1;
                    }
                    sub_1400F3326(1, 55, a3, a4);
                }
                sub_1400F3360();
                return (__int64)a1;
            }
            a1 = (size_t *)v_38;
            sub_1400A2D40(a1, ptr3);
        }
        return (__int64)a1;
    }
    do {
        sub_1400F3326(4, v8);
        do {
            sub_1400F3326(4, ptr);
            do {
                sub_1400F3326(1, 20);
                do {
                    sub_1400F3326(1, 5);
                    return (__int64)result;
                } while (result == 0);
            } while (result == 0);
        } while (result == 0);
    } while (true);
}