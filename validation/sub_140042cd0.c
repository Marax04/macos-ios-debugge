// inferred from 4 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[328];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int64 field_3D0; // offset 976
};

// inferred from 3 accesses on `a3`
struct Struct_2_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int16 field_3D0; // offset 976
    __int64 field_3D2; // offset 978
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[336];
    __int64 field_160; // offset 352
    char _pad_160[618];
    __int64 field_3D2; // offset 978
    char _pad_3D2[6];
    __int64 field_3E0; // offset 992
};

// inferred from 2 accesses on `ptr2`
struct Struct_4_t {
    char _pad_start[976];
    __int16 field_3D0; // offset 976
    __int64 field_3D2; // offset 978
};

// inferred from 3 accesses on `ptr3`
struct Struct_5_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int16 field_3D0; // offset 976
    __int64 field_3D2; // offset 978
};

__int64 sub_1400F27F6();
__int64 sub_1400F27F0();
__int64 sub_1400F37D0();
__int64 sub_140043632();
__int64 sub_140043EF0();
__int64 sub_1400F37A0();
__int64 sub_140043700();
__int64 sub_140043AE0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D858;
extern __int64 off_140114570;
extern __int64 off_140114508;
extern __int64 off_140114518;
extern __int64 off_1401146F8;
extern __int64 off_140114788;

__int64 __fastcall sub_140042CD0(size_t *a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    int arg_10;
    __int64 arg_100;
    int arg_108;
    __int64 arg_110;
    int arg_118;
    int arg_120;
    int arg_128;
    int arg_130;
    int arg_140;
    __int64 arg_148;
    __int64 arg_150;
    __int64 arg_158;
    __int64 arg_160;
    int arg_168;
    int arg_170;
    int arg_20;
    int arg_30;
    int arg_40;
    int arg_48;
    int arg_50;
    int arg_58;
    int arg_60;
    int arg_70;
    int arg_78;
    int arg_8;
    int arg_80;
    __int64 arg_88;
    int arg_90;
    int arg_98;
    int arg_a0;
    int arg_a8;
    int arg_b0;
    int arg_b8;
    __int64 arg_c0;
    int arg_c8;
    __int64 arg_d0;
    int arg_d8;
    __int64 arg_e0;
    int arg_e8;
    int arg_f0;
    int arg_f8;
    __int64 v_10;
    int v_18;
    __int64 v_20;
    __int64 v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    __int64 v_58;
    __int64 v_60;
    int str;
    __int64 *v_3d0;
    char *dst;
    struct Struct_3_t *ptr;
    struct Struct_4_t *ptr2;
    __int64 v4;
    __int64 *dst2;
    __int64 *result;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v11;
    struct Struct_5_t *ptr3;
    __int64 i;
    __int64 *src;
    __int64 v8;
    __int64 v9;
    __m128i xmm3;

    arg_170 = -2;
    arg_f8 = (int)a3;
    ptr = (struct Struct_3_t *)a2;
    arg_f0 = (int)a1;
    ptr2 = a2->field_0;
    v4 = a2->field_10;
    dst2 = ptr2->field_3D2;
    result = v4 * 56;
    a1 = (__int64)ptr2 + (__int64)result;
    a1 += 360;
    a2 = *(__int64 *)((__int64)ptr2 + (__int64)result + 408);
    arg_40 = (int)a2;
    xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)result + 360));
    xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)result + 376));
    xmm2 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)result + 392));
    _mm_store_si128((__m128i *)&arg_30, xmm2);
    _mm_store_si128((__m128i *)&arg_20, xmm1);
    _mm_store_si128((__m128i *)&arg_10, xmm0);
    a2 = (__int64)ptr2 + (__int64)result;
    a2 += 416;
    v11 = v4;
    v11 = ~v11;
    v11 += (__int64)dst2;
    a3 = v11 * 56;
    sub_1400F27F6(a1, a2, a3);
    arg_158 = v4;
    result = (__int64 *)v4;
    result = (__int64 *)((__int64)(__int64)result << 5);
    a1 = (__int64)ptr2 + (__int64)result;
    xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)result));
    xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)result + 16));
    _mm_storeu_si128((__m128i *)&arg_48, xmm0);
    _mm_storeu_si128((__m128i *)&arg_58, xmm1);
    a2 = (__int64)ptr2 + (__int64)result;
    a2 += 32;
    v11 <<= 5;
    sub_1400F27F6(a1, a2, v11);
    result = dst2 - 1;
    ptr3 = (struct Struct_5_t *)ptr2;
    ptr2->field_3D2 = result;
    i = ptr->field_8;
    if (result <= 4) {
        a1 = ptr3->field_160;
        if (a1 == 0) {
            arg_168 = i;
            arg_160 = (__int64)ptr3;
            ptr3 = (struct Struct_5_t *)arg_160;
            ptr = ptr3->field_160;
            if (ptr != 0) {
                result = ptr->field_3D2;
                if (result <= 4) {
                    a1 = (size_t *)arg_168;
                    v4 = a1 + 1;
                    ptr2 = (struct Struct_4_t *)ptr;
                    ptr = ptr->field_160;
                    while (ptr != 0) {
                        a3 = (struct Struct_2_t *)v4;
                        src = v4 + 1;
                        v4 = ptr2->field_3D0;
                        arg_e0 = (__int64)src;
                        if (v4 == 0) {
                            a2 = ptr->field_3D2;
                            if (a2 != 0) {
                                ptr3 = ptr->field_3E0;
                                v_60 = (__int64)ptr;
                                v_58 = (__int64)src;
                                v_50 = 0;
                                v_48 = (__int64)ptr2;
                                v_40 = (int)a3;
                                v_38 = (__int64)ptr3;
                                v_30 = (int)a3;
                                a3 = ptr3->field_3D2;
                                i = (__int64)result + (__int64)a3;
                                ++i;
                                if (i < 12) {
                                    src = result + 1;
                                    arg_150 = (__int64)src;
                                    dst2 = (__int64 *)ptr2;
                                    v4 = 0;
                                    v8 = (__int64)result;
                                    arg_148 = (__int64)a3;
                                    ptr2 = (struct Struct_4_t *)ptr3;
                                    arg_108 = v8;
                                    v11 = (__int64)a2;
                                    arg_e8 = i;
                                    *(dst2 + 978) = i;
                                    result = v4 * 56;
                                    a1 = (__int64)ptr + (__int64)result;
                                    a1 += 360;
                                    a2 = *(__int64 *)((__int64)ptr + (__int64)result + 408);
                                    arg_140 = (int)a2;
                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)result + 360));
                                    xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)result + 376));
                                    xmm2 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)result + 392));
                                    _mm_store_si128((__m128i *)&arg_130, xmm2);
                                    _mm_store_si128((__m128i *)&arg_120, xmm1);
                                    _mm_store_si128((__m128i *)&arg_110, xmm0);
                                    a2 = (__int64)ptr + (__int64)result;
                                    a2 += 416;
                                    v9 = v4;
                                    v9 = ~v9;
                                    v9 += v11;
                                    a3 = v9 * 56;
                                    sub_1400F27F6(a1, a2, a3, src);
                                    result = v8 * 56;
                                    xmm0 = _mm_load_si128((__m128i *)&arg_110);
                                    xmm1 = _mm_load_si128((__m128i *)&arg_120);
                                    xmm2 = _mm_load_si128((__m128i *)&arg_130);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 360), xmm0);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 376), xmm1);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 392), xmm2);
                                    a1 = (size_t *)arg_140;
                                    *(__int64 *)((__int64)dst2 + (__int64)result + 408) = a1;
                                    arg_100 = (__int64)ptr2;
                                    a2 = ptr2 + 360;
                                    ptr2 = (struct Struct_4_t *)arg_150;
                                    result = (__int64)(__int64)ptr2 * 56;
                                    a1 = (__int64)dst2 + (__int64)result;
                                    a1 += 360;
                                    v8 = arg_148;
                                    a3 = v8 * 56;
                                    sub_1400F27F0(a1, a2, a3);
                                    result = (__int64 *)v4;
                                    result = (__int64 *)((__int64)(__int64)result << 5);
                                    a1 = (__int64)ptr + (__int64)result;
                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)result));
                                    xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr + (__int64)result + 16));
                                    _mm_store_si128((__m128i *)&arg_120, xmm1);
                                    _mm_store_si128((__m128i *)&arg_110, xmm0);
                                    a2 = (__int64)ptr + (__int64)result;
                                    a2 += 32;
                                    a3 = (struct Struct_2_t *)v9;
                                    a3 = (struct Struct_2_t *)((__int64)(__int64)a3 << 5);
                                    sub_1400F27F6(a1, a2, a3);
                                    result = (__int64 *)arg_108;
                                    result = (__int64 *)((__int64)(__int64)result << 5);
                                    xmm0 = _mm_load_si128((__m128i *)&arg_110);
                                    xmm1 = _mm_load_si128((__m128i *)&arg_120);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result), xmm0);
                                    _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 16), xmm1);
                                    a1 = (size_t *)ptr2;
                                    a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                    a1 = (size_t *)((__int64)a1 + (__int64)dst2);
                                    a3 = (struct Struct_2_t *)v8;
                                    a3 = (struct Struct_2_t *)((__int64)(__int64)a3 << 5);
                                    a2 = (struct Struct_1_t *)arg_100;
                                    sub_1400F27F0(a1, a2, a3);
                                    v8 = v4 + 1;
                                    a1 = ptr + v4*8;
                                    a1 += 992;
                                    a2 = ptr + v4*8;
                                    a2 += 1000;
                                    v9 <<= 3;
                                    sub_1400F27F6(a1, a2, v9);
                                    if (v11 <= v8) {
                                        ptr->field_3D2 = ptr->field_3D2 - 1;
                                        v4 = arg_e0;
                                        v11 = arg_100;
                                        ptr2 = (struct Struct_4_t *)arg_e8;
                                        if (v4 < 2) {
                                            off_140108030(a1);
                                            off_140108038(result, 0, v11);
                                            result = ptr->field_3D2;
                                            ptr3 = (struct Struct_5_t *)arg_160;
                                            i = arg_168;
                                            result = (__int64 *)arg_60;
                                            a1 = (size_t *)arg_f0;
                                            a1[10] = result;
                                            xmm0 = _mm_load_si128((__m128i *)&arg_50);
                                            _mm_storeu_si128((__m128i *)(a1 + 64), xmm0);
                                            xmm0 = _mm_load_si128((__m128i *)&arg_10);
                                            xmm1 = _mm_load_si128((__m128i *)&arg_20);
                                            xmm2 = _mm_load_si128((__m128i *)&arg_30);
                                            xmm3 = _mm_load_si128((__m128i *)&arg_40);
                                            _mm_storeu_si128((__m128i *)(a1 + 48), xmm3);
                                            _mm_storeu_si128((__m128i *)(a1 + 32), xmm2);
                                            _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
                                            _mm_storeu_si128((__m128i *)a1, xmm0);
                                            a1[11] = ptr3;
                                            a1[12] = i;
                                            result = (__int64 *)arg_158;
                                            a1[13] = result;
                                            return (__int64)result;
                                        }
                                        a3 = (struct Struct_2_t *)arg_148;
                                        ++a3;
                                        result = (__int64 *)ptr2;
                                        result -= arg_108;
                                        if (a3 == result) {
                                            result = dst2 + 984;
                                            v8 = arg_150;
                                            a1 = result + v8*8;
                                            a2 = v11 + 984;
                                            a3 = (struct Struct_2_t *)((__int64)(__int64)a3 << 3);
                                            sub_1400F27F0(a1, a2, a3);
                                            a1 = (size_t *)ptr2;
                                            a1 -= v8;
                                            ++a1;
                                            result = (__int64 *)v8;
                                            a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                            if ((a1 == 0)) {
                                                a1 = (size_t *)ptr2;
                                                a1 -= v8;
                                                if (a1 < 3) {
                                                    return (__int64)a1;
                                                }
                                                do {
                                                    a1 = *(dst2 + (__int64)(__int64)result*8 + 984);
                                                    a1[44] = dst2;
                                                    a1[122] = result;
                                                    a1 = *(dst2 + (__int64)(__int64)result*8 + 992);
                                                    a1[44] = dst2;
                                                    a2 = result + 1;
                                                    a1[122] = a2;
                                                    a1 = *(dst2 + (__int64)(__int64)result*8 + 1000);
                                                    a1[44] = dst2;
                                                    a2 = result + 2;
                                                    a1[122] = a2;
                                                    a1 = *(dst2 + (__int64)(__int64)result*8 + 1008);
                                                    a1[44] = dst2;
                                                    a2 = result + 3;
                                                    a1[122] = a2;
                                                    result += 4;
                                                } while (a2 != ptr2);
                                                return (__int64)result;
                                            }
                                            a2 = (struct Struct_1_t *)v8;
                                            do {
                                                result = a2 + 1;
                                                a3 = *(dst2 + (__int64)(__int64)a2*8 + 984);
                                                a3->field_160 = dst2;
                                                a3->field_3D0 = a2;
                                                a2 = (struct Struct_1_t *)result;
                                                --a1;
                                            } while ((a1 != 0));
                                            return (__int64)a1;
                                        }
                                        a1 = &off_14011D858;
                                        a3 = &off_140114570;
                                        sub_1400F37D0(a1, 40, a3);
                                        return sub_140043632();
                                    }
                                    a1 = (size_t *)v11;
                                    a1 -= v8;
                                    a1 = (size_t *)((__int64)(__int64)a1 & 3);
                                    if ((a1 == 0)) {
                                        result = (__int64 *)v8;
                                        v4 = -v4;
                                        a1 = v11 + v4;
                                        a1 -= 2;
                                        if (a1 >= 3) {
                                            do {
                                                a1 = *(__int64 *)(ptr + (__int64)(__int64)result*8 + 984);
                                                a1[44] = ptr;
                                                a1[122] = result;
                                                a1 = *(__int64 *)(ptr + (__int64)(__int64)result*8 + 992);
                                                a1[44] = ptr;
                                                a2 = result + 1;
                                                a1[122] = a2;
                                                a1 = *(__int64 *)(ptr + (__int64)(__int64)result*8 + 1000);
                                                a1[44] = ptr;
                                                a2 = result + 2;
                                                a1[122] = a2;
                                                a1 = *(__int64 *)(ptr + (__int64)(__int64)result*8 + 1008);
                                                a1[44] = ptr;
                                                a2 = result + 3;
                                                a1[122] = a2;
                                                result += 4;
                                            } while (result != v11);
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    do {
                                        result = v8 + 1;
                                        a2 = *(__int64 *)(ptr + v8*8 + 984);
                                        a2->field_160 = ptr;
                                        a2->field_3D0 = v8;
                                        v8 = (__int64)result;
                                        --a1;
                                    } while ((a1 != 0));
                                    v4 = -v4;
                                    a1 = v11 + v4;
                                    a1 -= 2;
                                    if (a1 < 3) {
                                        return (__int64)a1;
                                    }
                                    return (__int64)a1;
                                }
                                a2 = 5;
                                a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)result);
                                a1 = dst - 96;
                                sub_140043EF0(a1, a2);
                                return (__int64)a1;
                            }
                            result = &off_140114508;
                            arg_110 = (__int64)result;
                            arg_118 = 1;
                            arg_120 = 8;
                            xmm0 = _mm_setzero_si128();
                            _mm_storeu_si128((__m128i *)&arg_128, xmm0);
                            a2 = &off_140114518;
                            a1 = dst + 272;
                            sub_1400F37A0(a1, a2);
                            return sub_140043632();
                        }
                        dst2 = *(__int64 *)(ptr + v4*8 + 976);
                        --v4;
                        v_28 = (__int64)ptr;
                        v_20 = (__int64)src;
                        v_18 = v4;
                        v_10 = (__int64)dst2;
                        str = (int)a3;
                        *dst = ptr2;
                        arg_8 = (int)a3;
                        v8 = *(dst2 + 978);
                        a2 = result + v8;
                        ++a2;
                        if (a2 < 12) {
                            a2 = v8 + 1;
                            arg_150 = (__int64)a2;
                            i = v8 + result;
                            ++i;
                            a2 = ptr->field_3D2;
                            arg_148 = (__int64)result;
                            return arg_148;
                        }
                        a2 = 5;
                        a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)result);
                        a1 = dst - 40;
                        sub_140043700(a1, a2);
                        return (__int64)a1;
                    }
                    if (result == 0) {
                        result = (__int64 *)arg_f8;
                        *result = 1;
                    }
                }
                return (__int64)result;
            } else {
            }
            return (__int64)result;
        } else {
            a2 = i + 1;
            a3 = ptr3->field_3D0;
            if (a3 == 0) {
                if (a1[122] == 0) {
                    result = &off_140114508;
                    arg_110 = (__int64)result;
                    arg_118 = 1;
                    arg_120 = 8;
                    xmm0 = _mm_setzero_si128();
                    _mm_storeu_si128((__m128i *)&arg_128, xmm0);
                    a2 = &off_140114518;
                    a1 = dst + 272;
                    sub_1400F37A0(a1, a2);
                    return sub_140043632();
                } else {
                    a3 = a1[124];
                    arg_70 = (int)a1;
                    arg_78 = (int)a2;
                    arg_80 = 0;
                    arg_88 = (__int64)ptr3;
                    arg_90 = i;
                    arg_98 = (int)a3;
                    arg_a0 = i;
                    a1 = a3->field_3D2;
                    a1 = (size_t *)((__int64)a1 + (__int64)result);
                    ++a1;
                    if (a1 >= 12) {
                        arg_168 = i;
                        arg_160 = (__int64)ptr3;
                        a1 = dst + 112;
                        sub_140043EF0(a1, 1);
                    } else {
                        if (arg_158 > result) JUMPOUT(0x14004361a);
                        a1 = dst + 112;
                        sub_140043AE0(a1, a2, a3);
                        arg_160 = (__int64)result;
                        arg_168 = (int)a2;
                    }
                    ptr3 = (struct Struct_5_t *)arg_160;
                    ptr = ptr3->field_160;
                    if (ptr != 0) {
                        return (__int64)ptr;
                    }
                }
            } else {
                src = v_3d0[(__int64)a3];
                --a3;
                arg_a8 = (int)a1;
                arg_b0 = (int)a2;
                arg_b8 = (int)a3;
                arg_c0 = (__int64)src;
                arg_c8 = i;
                arg_160 = (__int64)ptr3;
                arg_d0 = (__int64)ptr3;
                arg_d8 = i;
                dst2 = *(src + 978);
                a1 = (__int64)dst2 + (__int64)result;
                ++a1;
                if (a1 >= 12) {
                    arg_168 = i;
                    a1 = dst + 168;
                    sub_140043700(a1, 1, a3);
                    ++arg_158;
                    ptr3 = (struct Struct_5_t *)arg_160;
                    ptr = ptr3->field_160;
                    if (ptr != 0) {
                        return (__int64)ptr;
                    } else {
                    }
                    return (__int64)ptr;
                } else {
                    if (arg_158 > result) {
                        a1 = &off_1401146F8;
                        a3 = &off_140114788;
                        sub_1400F37D0(a1, 142, a3);
                        return sub_140043632();
                    } else {
                        a1 = dst + 168;
                        sub_140043AE0(a1, a2, a3, src);
                        arg_160 = (__int64)result;
                        arg_168 = (int)a2;
                        result = (__int64 *)arg_158;
                        result = (__int64 *)((__int64)result + (__int64)dst2);
                        ++result;
                        arg_158 = (__int64)result;
                        ptr3 = (struct Struct_5_t *)arg_160;
                        ptr = ptr3->field_160;
                        if (ptr != 0) {
                            return (__int64)ptr;
                        } else {
                        }
                        return (__int64)ptr;
                    }
                }
                return (__int64)ptr;
            }
            return (__int64)ptr;
        }
        return (__int64)ptr;
    }
    return (__int64)result;
}