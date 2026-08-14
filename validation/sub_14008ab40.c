// inferred from 8 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    int field_10; // offset 16
    int field_14; // offset 20
    __int64 field_18; // offset 24
    char _pad_18[4];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_14008B5CE();
__int64 sub_14008B5BA();
__int64 sub_14008B78E();
__int64 sub_14007C9D0();
__int64 sub_1400FAFD0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14012D270;
extern __int64 off_140124488;

__int64 __fastcall sub_14008AB40(size_t *a1, size_t *a2, int a3, int *a4) {
    __int64 rsp;
    int v_118;
    int v_120;
    int v_144;
    __int64 v_158;
    __int64 v_160;
    int v_168;
    __int64 v_178;
    int v_180;
    int v_20;
    int v_200;
    int v_208;
    int v_210;
    int v_218;
    __int64 v_2f;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_88;
    __int64 v_90;
    int v_98;
    __int64 v_a0;
    int v_a8;
    __int64 v_ac;
    int v_b0;
    __int64 v_b8;
    int v_c2;
    int v_d0;
    int v_d8;
    __int64 *v_0;
    struct Struct_3_t *ptr2;
    struct Struct_2_t *ptr;
    struct Struct_4_t *ptr3;
    struct Struct_1_t *result;
    __int64 *dst;
    __int64 i;
    __m128i xmm6;
    __int64 v9;
    __int64 v6;
    int v5;
    __int64 v11;
    __int64 v8;

    _mm_store_si128((__m128i *)&v_180, xmm6);
    v_98 = (int)a1;
    ptr2 = (struct Struct_3_t *)v_218;
    ptr = (struct Struct_2_t *)v_210;
    ptr3 = (struct Struct_4_t *)v_208;
    result = (struct Struct_1_t *)v_200;
    v_168 = (int)a2;
    v_178 = (__int64)result;
    a2 = (size_t *)((__int64)(__int64)a2 >> 1);
    if (a2 >= result) {
        if (a3 == 0) {
            if (a4 != 0) {
                a4 = (int *)((__int64)(__int64)a4 >> 1);
                return sub_14008B5CE();
            }
        } else {
            result = off_14012D270;
            a1 = __readgsqword(88);
            result = v_0[(__int64)result];
            result = result->field_18;
            if (result == 0) JUMPOUT(0x14008b5a9);
            result += 272;
            return sub_14008B5BA();
        }
    }
    dst = ptr2->field_8;
    result = ptr2->field_10;
    v_b8 = (__int64)result;
    if (ptr == 0) {
        i = 0;
    } else {
        result = ptr2->field_0;
        v_160 = (__int64)result;
        result = ptr3 + (__int64)(__int64)ptr*8;
        v_158 = (__int64)result;
        i = 0;
        xmm6 = _mm_cmpeq_epi32(xmm6, xmm6);
        v_a0 = (__int64)dst;
        do {
            v9 = ptr3->field_0;
            ptr2 = ptr3->field_4;
            result = (struct Struct_1_t *)v_160;
            a2 = result->field_0;
            ptr = result->field_8;
            v_40 = (__int64)ptr;
            result = ptr->field_8;
            v_48 = (__int64)result;
            v6 = ptr->field_10;
            result = ptr->field_20;
            a2 = ptr->field_28;
            result -= 28;
            a1 = a2 + (__int64)(__int64)a2*8;
            a1 += (__int64)(__int64)a1*2;
            a1 = (size_t *)((__int64)a1 + (__int64)a2);
            while (a1 != 0) {
                a3 = result->field_24;
                v5 = result->field_28;
                a2 = result->field_2C;
                if (a2 > a3) a3 = a2;
                a3 += v5;
                if ((a3 < 0)) {
                    v_50 = 0;
                    a4 = 3;
                    result = 4;
                    a2 = rsp + 136;
                    a1 = 0;
                    *a2 = a1;
                    a1 = (size_t *)v_50;
                    a2 = a1;
                    a2 = (size_t *)(-(__int64)a2);
                    if (!((0 /* overflow check on (-a2) */))) {
                        if (i == v_b8) JUMPOUT(0x14008b7aa);
                        ptr3 += 8;
                        a2 = i + i*4;
                        a3 = v_a8;
                        dst[(__int64)a2] = a3;
                        a3 = v_ac;
                        *(dst + (__int64)(__int64)a2*8 + 4) = a3;
                        *(dst + (__int64)(__int64)a2*8 + 8) = a4;
                        *(dst + (__int64)(__int64)a2*8 + 16) = a1;
                        *(dst + (__int64)(__int64)a2*8 + 24) = result;
                        result = (struct Struct_1_t *)v_88;
                        *(dst + (__int64)(__int64)a2*8 + 32) = result;
                        ++i;
                    }
                    result = (struct Struct_1_t *)v_98;
                    *(__int64 *)result = (__int64)(dst);
                    a1 = (size_t *)v_b8;
                    result->field_8 = a1;
                    result->field_10 = i;
                    return sub_14008B78E();
                }
                result += 28;
                a1 -= 28;
                a4 = (int *)v9;
                a4 -= v5;
                if (a4 >= a2) {
                    return (__int64)a4;
                }
                result = result->field_14;
                v11 = (__int64)a4;
                v11 += (__int64)result;
                if (v11 >= v6) {
                    return v11;
                }
                v_b0 = i;
                v_2f = (__int64)ptr2;
                v_58 = 0;
                v_60 = 4;
                v_68 = 0;
                v8 = 0x1000;
                result = 4;
                v_90 = (__int64)result;
                v_20 = 0;
                ptr = (struct Struct_2_t *)v9;
                dst = (__int64 *)v9;
                v_38 = v9;
                i = v6;
                a3 = v6;
                a3 -= v11;
                result = (struct Struct_1_t *)v_48;
                a2 = result + v11;
                a1 = rsp + 192;
                sub_14007C9D0(a1, a2, a3, dst);
                while (v_c2 != 2) {
                    result = (struct Struct_1_t *)v_120;
                    ptr2 = (struct Struct_3_t *)v_144;
                    dst = (__int64 *)((__int64)dst + (__int64)ptr2);
                    a1 = (size_t *)dst;
                    a1 = (size_t *)((__int64)(__int64)a1 >> 32);
                    if (a1 == 0) ptr = dst;
                    a1 = result - 4;
                    result = (struct Struct_1_t *)a1;
                    a1 = 183;
                    if (result < 4) result = a1;
                    a2 = (size_t *)result;
                    a2 += 0xFFFFFFD5;
                    if (a2 > 11) {
                        v6 = i;
                        --v8;
                        if ((v8 == 0)) {
                            a1 = (size_t *)v_58;
                            if (ptr <= v9) {
                                dst = (__int64 *)v_a0;
                                i = v_b0;
                                if (a1 == 0) {
                                    return i;
                                }
                                v9 = v_60;
                                off_140108030(a1, a2, a3, a4);
                                off_140108038(result, 0, v9);
                                return v9;
                            }
                            result = (struct Struct_1_t *)a1;
                            result = (struct Struct_1_t *)(-(__int64)result);
                            dst = (__int64 *)v_a0;
                            a4 = (int *)v_2f;
                            i = v_b0;
                            if ((0 /* overflow check on (-result) */)) {
                                return i;
                            }
                            result = (struct Struct_1_t *)v_60;
                            a2 = (size_t *)v_20;
                            v_88 = (int)a2;
                            v_ac = (__int64)ptr;
                            v_a8 = v9;
                            a2 = rsp + 80;
                            return (__int64)a2;
                        }
                        v11 += (__int64)ptr2;
                        return v11;
                    }
                    v_30 = (__int64)ptr;
                    a1 = (size_t *)v_d0;
                    result = (struct Struct_1_t *)v_d8;
                    ptr = (struct Struct_2_t *)v_118;
                    a3 = &off_140124488;
                    v6 = i;
                    switch ((__int64)a2) {
                        case 3:
                            ptr = (struct Struct_2_t *)((__int64)ptr + (__int64)result);
                            ptr = (struct Struct_2_t *)((__int64)ptr + (__int64)ptr2);
                            result = (struct Struct_1_t *)v_38;
                            if (ptr <= result) ptr = result;
                            if (a1 == 3) result = ptr;
                            v_38 = (__int64)result;
                            return v_38;
                        case 4:
                            ptr = (struct Struct_2_t *)v_30;
                            break;
                        default:
                            if (a1 != 3) {
                                a1 = (size_t *)v_20;
                                v_20 = (int)a1;
                                ptr = (struct Struct_2_t *)v_30;
                                if (dst <= v_38) {
                                    return (__int64)ptr;
                                }
                                return (__int64)ptr;
                            }
                            ptr = (struct Struct_2_t *)((__int64)ptr + (__int64)result);
                            ptr = (struct Struct_2_t *)((__int64)ptr + (__int64)ptr2);
                            a1 = (size_t *)v_20;
                            if (ptr <= dst) {
                                result = (struct Struct_1_t *)ptr;
                                result = (struct Struct_1_t *)((__int64)(__int64)result >> 32);
                                if ((result != 0)) {
                                    return (__int64)result;
                                }
                                a1 = (size_t *)v_40;
                                result = a1[4];
                                a2 = a1[5];
                                result -= 28;
                                a1 = a2 + (__int64)(__int64)a2*8;
                                a1 += (__int64)(__int64)a1*2;
                                a1 = (size_t *)((__int64)a1 + (__int64)a2);
                                while (a1 != 0) {
                                    a3 = result->field_24;
                                    v5 = result->field_28;
                                    a2 = result->field_2C;
                                    if (a2 > a3) a3 = a2;
                                    a3 += v5;
                                    if ((a3 < 0)) {
                                        return a3;
                                    }
                                    result += 28;
                                    a1 -= 28;
                                    a4 = (int *)ptr;
                                    a4 -= v5;
                                    if (a4 >= a2) {
                                        return (__int64)a4;
                                    }
                                    result = result->field_14;
                                    a1 = (size_t *)a4;
                                    a1 = (size_t *)((__int64)a1 + (__int64)result);
                                    result = (struct Struct_1_t *)v_40;
                                    if (a1 >= result->field_10) {
                                        return (__int64)result;
                                    }
                                    a1 = (size_t *)v_20;
                                    if (a1 == v_58) {
                                        a1 = rsp + 88;
                                        sub_1400FAFD0(a1);
                                        a1 = (size_t *)v_20;
                                        v6 = i;
                                    }
                                    result = (struct Struct_1_t *)v_60;
                                    v_90 = (__int64)result;
                                    *(__int64 *)(result + (__int64)(__int64)a1*4) = (__int64)(ptr);
                                    ++a1;
                                    v_68 = (int)a1;
                                    return v_68;
                                }
                                return v_68;
                            }
                            result = (struct Struct_1_t *)v_38;
                            if (ptr > result) result = ptr;
                            v_38 = (__int64)result;
                            return v_38;
                    }
                    return v_38;
                }
                return v_38;
            }
            return v_38;
        } while (ptr3 != v_158);
        return v_38;
    }
    return (__int64)result;
}