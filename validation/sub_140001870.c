// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    int field_2; // offset 2
    __int16 field_6; // offset 6
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_1400F3600();
__int64 sub_14000E480();
__int64 sub_140027030();
__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_14000E670();
__int64 sub_14000B390();
__int64 sub_14000A690();
__int64 sub_140002754();
__int64 sub_1400276D0();
__int64 sub_1400F5F40();
__int64 sub_14000A5E0();
__int64 sub_140002730();
__int64 sub_140002706();
__int64 sub_14000275E();
__int64 sub_1400F3326();
__int64 sub_1400F3360();
__int64 sub_1400F28F0();
__int64 sub_140002833();
__int64 sub_140001350();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14012D020;
extern __int64 off_14012D018;
extern __int64 off_140111F70;
extern __int64 off_140120DA8;

__int64 __fastcall sub_140001870(size_t *a1, int *a2) {
    __int64 rsp;
    int arg_10;
    int arg_28;
    __int64 v_100;
    int v_108;
    int v_120;
    int v_130;
    __int64 v_20;
    int v_21;
    int v_27;
    __int64 v_28;
    int v_2f;
    int v_30;
    __int64 v_37;
    __int64 v_40;
    int v_68;
    int v_69;
    int v_6a;
    int v_6e;
    int v_70;
    __int64 v_78;
    __int64 v_80;
    __int64 v_88;
    __int64 v_90;
    __int64 v_98;
    __int64 v_a0;
    int v_a8;
    int v_ac;
    __int64 v_b8;
    int v_c0;
    int v_c8;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_f0;
    int v_f8;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v9;
    __int64 *i;
    __int64 *src2;
    __int64 v11;
    __int64 *result;
    __int64 *i2;
    __int64 *src3;
    struct Struct_3_t *ptr3;
    struct Struct_2_t *ptr2;
    __m128i xmm0;
    __m128i xmm1;

    ptr = (struct Struct_1_t *)a1;
    src = a2[3];
    v9 = a2[4];
    i = a2[5];
    if (i < v9) {
        src2 = a2 + 24;
        v11 = 0x100002600;
        result = *(__int64 *)((__int64)src + (__int64)i);
        while (result <= 32) {
            if (!((!((v11 >> (__int64)result) & 1)))) {
                ++i;
                a2[5] = i;
                i = (__int64 *)v9;
                v_20 = 5;
                ++i;
                if (i >= v9) i = v9;
                i2 = (__int64)src + (__int64)i;
                result = off_14012D020;
                ((__int64 (*)())result)(10, src, i2, src2);
                if (((__int64)result & 1) == 0) {
                    src3 = 0;
                } else {
                    a2 = (int *)((__int64)a2 - (__int64)src);
                    src3 = a2 + 1;
                    if (a2 < v9) {
                        i2 = (__int64)src + (__int64)src3;
                        result = off_14012D018;
                        ((__int64 (*)())result)(10, src, i2);
                        a2 = result + 1;
                        i = (__int64 *)((__int64)i - (__int64)src3);
                        a1 = rsp + 32;
                    } else {
                        do {
                            src2 = &off_140111F70;
                            sub_1400F3600(0, src3, v9, src2);
                            a1 = result - 91;
                            if (a1 <= 32) {
                                i2 = &off_140120DA8;
                                switch ((__int64)a1) {
                                    case 32:
                                        src3 = src2;
                                        a2[6] = a2[6] - 1;
                                        if ((a2[6] == 0)) JUMPOUT(0x1400026df);
                                        ++i;
                                        a2[5] = i;
                                        ptr3 = (struct Struct_3_t *)a2;
                                        v_c0 = (int)a2;
                                        v_c8 = 1;
                                        a1 = rsp + 32;
                                        a2 = rsp + 192;
                                        sub_14000E480(a1, a2);
                                        if (v_20 != 1) {
                                            if (v_21 != 1) {
                                                v_68 = 5;
                                                v_70 = 0;
                                                v_80 = 0;
                                            } else {
                                                i2 = (__int64 *)v_c0;
                                                a2 = i2 + 24;
                                                ++arg_28;
                                                arg_10 = 0;
                                                a1 = rsp + 32;
                                                sub_140027030(a1, a2, i2);
                                                result = (__int64 *)v_20;
                                                v9 = v_28;
                                                if (result == 2) {
                                                    v_70 = v9;
                                                    v_68 = 6;
                                                    ptr2 = 6;
                                                } else {
                                                    i = (__int64 *)v_30;
                                                    if (i >= 0) {
                                                        if (i == 0) {
                                                            src = 1;
                                                        } else {
                                                            sub_14002EDF0(0, i);
                                                            if (result == 0) JUMPOUT(0x140002855);
                                                            src = result;
                                                        }
                                                        sub_1400F27F0(src, v9, i);
                                                        v_e0 = 0;
                                                        v_f0 = 0;
                                                        v_90 = (__int64)i;
                                                        v_98 = (__int64)src;
                                                        v_a0 = (__int64)i;
                                                        a1 = rsp + 104;
                                                        a2 = rsp + 192;
                                                        sub_14000E670(a1, a2);
                                                        if (v_68 != 6) {
                                                            a1 = rsp + 32;
                                                            a2 = rsp + 224;
                                                            i2 = rsp + 144;
                                                            src2 = rsp + 104;
                                                            sub_14000B390(a1, a2, i2, src2);
                                                            if (v_20 != 6) {
                                                                a1 = rsp + 32;
                                                                sub_14000A690(a1);
                                                            }
                                                            src = rsp + 32;
                                                            i = rsp + 192;
                                                            sub_14000E480(src, i);
                                                            while (v_20 != 1) {
                                                                if (v_21 == 1) {
                                                                    ptr2 = (struct Struct_2_t *)v_c0;
                                                                    i = ptr2 + 24;
                                                                    ptr2->field_28 = ptr2->field_28 + 1;
                                                                    ptr2->field_10 = 0;
                                                                    v9 = (__int64)src;
                                                                    sub_140027030(src, i, ptr2);
                                                                    result = (__int64 *)v_20;
                                                                    src = (__int64 *)v_28;
                                                                    if (result == 2) JUMPOUT(0x140002754);
                                                                    i2 = (__int64 *)v_30;
                                                                    if (((__int64)result & 1) == 0) {
                                                                        if (i2 >= 0) {
                                                                            if (i2 == 0) {
                                                                                result = 1;
                                                                                v_b8 = (__int64)result;
                                                                                v_88 = (__int64)i2;
                                                                                sub_1400F27F0(result, src, i2);
                                                                                a1 = ptr2->field_20;
                                                                                result = ptr2->field_28;
                                                                                if (result >= a1) JUMPOUT(0x140002706);
                                                                                src = (__int64 *)v9;
                                                                                a2 = *i;
                                                                                do {
                                                                                    i2 = *(__int64 *)((__int64)a2 + (__int64)result);
                                                                                    if (i2 > 58) JUMPOUT(0x140002844);
                                                                                    if ((!((v11 >> (__int64)i2) & 1))) {
                                                                                        if (i2 != 58) JUMPOUT(0x140002844);
                                                                                        ++result;
                                                                                        ptr2->field_28 = result;
                                                                                        sub_140001870(src, ptr2);
                                                                                        if (v_20 != 6) {
                                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                                                                                            xmm1 = _mm_loadu_si128((__m128i *)&v_30);
                                                                                            _mm_store_si128((__m128i *)&v_130, xmm1);
                                                                                            _mm_store_si128((__m128i *)&v_120, xmm0);
                                                                                            a1 = (size_t *)v_88;
                                                                                            result = (__int64 *)a1;
                                                                                            result = (__int64 *)(-(__int64)result);
                                                                                            i = rsp + 192;
                                                                                            if (!((0 /* overflow check on (-result) */))) {
                                                                                                result = 0x8000000000000001;
                                                                                                if (a1 != result) {
                                                                                                    v_f8 = (int)a1;
                                                                                                    result = (__int64 *)v_b8;
                                                                                                    v_100 = (__int64)result;
                                                                                                    v_108 = (int)a1;
                                                                                                    a2 = rsp + 224;
                                                                                                    i2 = rsp + 248;
                                                                                                    src2 = rsp + 288;
                                                                                                    sub_14000B390(src, a2, i2, src2);
                                                                                                    sub_14000A690(src);
                                                                                                }
                                                                                                src = (__int64 *)v_b8;
                                                                                                return sub_140002754();
                                                                                            }
                                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_e0);
                                                                                            _mm_storeu_si128((__m128i *)&v_27, xmm0);
                                                                                            result = (__int64 *)v_f0;
                                                                                            v_37 = (__int64)result;
                                                                                            v_68 = 5;
                                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                                                                                            _mm_storeu_si128((__m128i *)&v_69, xmm0);
                                                                                            result = (__int64 *)v_2f;
                                                                                            v_78 = (__int64)result;
                                                                                            result = (__int64 *)v_37;
                                                                                            v_80 = (__int64)result;
                                                                                            ptr2 = 5;
                                                                                            ptr3->field_30 = ptr3->field_30 + 1;
                                                                                            a1 = ptr3->field_20;
                                                                                            result = ptr3->field_28;
                                                                                            if (result < a1) {
                                                                                                i2 = *src3;
                                                                                                src2 = *(__int64 *)((__int64)i2 + (__int64)result);
                                                                                                while (src2 <= 44) {
                                                                                                    if (!((!((v11 >> (__int64)src2) & 1)))) {
                                                                                                        ++result;
                                                                                                        a2[5] = result;
                                                                                                        v_90 = 3;
                                                                                                        sub_1400276D0(src3, ptr3, i2, src2);
                                                                                                        a1 = rsp + 144;
                                                                                                        sub_1400F5F40(a1, result, a2);
                                                                                                        src3 = result;
                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                                                                                                        xmm1 = _mm_loadu_si128((__m128i *)&v_78);
                                                                                                        _mm_store_si128((__m128i *)&v_20, xmm0);
                                                                                                        _mm_store_si128((__m128i *)&v_30, xmm1);
                                                                                                        v_40 = (__int64)result;
                                                                                                        if (v_20 != 6) {
                                                                                                            a1 = rsp + 32;
                                                                                                            sub_14000A690(a1, i);
                                                                                                            ptr2 = 6;
                                                                                                            src = src3;
                                                                                                            a2 = (int *)ptr3;
                                                                                                        } else {
                                                                                                            src = (__int64 *)v_28;
                                                                                                            sub_14000A5E0(src3);
                                                                                                            ptr2 = 6;
                                                                                                            a2 = (int *)ptr3;
                                                                                                        }
                                                                                                        return (__int64)a2;
                                                                                                    }
                                                                                                    if (src2 != 44) {
                                                                                                        if (src2 != 125) JUMPOUT(0x1400026f5);
                                                                                                        ++result;
                                                                                                        a2[5] = result;
                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                                                                                                        xmm1 = _mm_loadu_si128((__m128i *)&v_78);
                                                                                                        _mm_store_si128((__m128i *)&v_20, xmm0);
                                                                                                        _mm_store_si128((__m128i *)&v_30, xmm1);
                                                                                                        if (v_20 != 6) {
                                                                                                            result = (__int64 *)v_69;
                                                                                                            a1 = (size_t *)v_6a;
                                                                                                            v_a8 = (int)a1;
                                                                                                            a1 = (size_t *)v_6e;
                                                                                                            v_ac = (int)a1;
                                                                                                            src = (__int64 *)v_70;
                                                                                                            xmm0 = _mm_loadu_si128((__m128i *)&v_78);
                                                                                                        } else {
                                                                                                            src = (__int64 *)v_28;
                                                                                                            ptr2 = 6;
                                                                                                        }
                                                                                                    } else {
                                                                                                        v_90 = 21;
                                                                                                        return v_90;
                                                                                                    }
                                                                                                    return v_90;
                                                                                                }
                                                                                                return v_90;
                                                                                            }
                                                                                            return v_90;
                                                                                        }
                                                                                        src = (__int64 *)v_28;
                                                                                        return sub_140002730();
                                                                                    }
                                                                                    ++result;
                                                                                    ptr2->field_28 = result;
                                                                                } while (a1 != result);
                                                                                return sub_140002706();
                                                                            }
                                                                            v_88 = (__int64)i2;
                                                                            sub_14002EDF0(0, i2, i2);
                                                                            if (result == 0) JUMPOUT(0x140002862);
                                                                            i2 = (__int64 *)v_88;
                                                                            return (__int64)i2;
                                                                        }
                                                                        return (__int64)i2;
                                                                    }
                                                                    if (i2 >= 0) {
                                                                        if (i2 != 0) {
                                                                            return (__int64)i2;
                                                                        }
                                                                        return (__int64)i2;
                                                                    }
                                                                    return (__int64)i2;
                                                                }
                                                                return (__int64)i2;
                                                            }
                                                            src = (__int64 *)v_28;
                                                            return sub_140002754();
                                                        } else {
                                                            if (i == 0) JUMPOUT(0x14000275e);
                                                            off_140108030();
                                                            off_140108038(result, 0, src);
                                                            return sub_14000275E();
                                                        }
                                                    }
                                                    return (__int64)src;
                                                }
                                                return (__int64)src;
                                            }
                                            return (__int64)src;
                                        } else {
                                            v9 = v_28;
                                        }
                                        return v9;
                                    default:
                                        if (result == 34) {
                                            ++i;
                                            a2[5] = i;
                                            a2[2] = 0;
                                            a1 = rsp + 32;
                                            sub_140027030(a1, src2, a2);
                                            result = (__int64 *)v_20;
                                            i = (__int64 *)v_28;
                                            if (result != 2) {
                                                src3 = (__int64 *)v_30;
                                                if (((__int64)result & 1) == 0) {
                                                    if (src3 >= 0) {
                                                        if ((ptr2 != 0)) {
                                                            sub_14002EDF0(0, src3);
                                                            v9 = (__int64)result;
                                                            if (result != 0) {
                                                                sub_1400F27F0(v9, i, src3);
                                                                *(__int64 *)ptr = (__int64)(3);
                                                                ptr->field_8 = src3;
                                                                ptr->field_10 = v9;
                                                                ptr->field_18 = src3;
                                                            } else {
                                                                sub_1400F3326(1, src3);
                                                                a1 = (size_t *)src3;
                                                                a1 = (size_t *)((__int64)(__int64)a1 >> 63);
                                                                *(__int64 *)ptr = (__int64)(result);
                                                                ptr->field_8 = a1;
                                                                ptr->field_10 = src3;
                                                            }
                                                            return (__int64)a1;
                                                        } else {
                                                            v9 = 1;
                                                        }
                                                        return v9;
                                                    } else {
                                                        sub_1400F3360(a1, a2);
                                                        i = (__int64 *)v9;
                                                        v_20 = 2;
                                                        ++i;
                                                        if (i >= v9) i = v9;
                                                        i2 = (__int64)src + (__int64)i;
                                                        result = off_14012D020;
                                                        ((__int64 (*)())result)(10, src, i2);
                                                        if (((__int64)result & 1) != 0) {
                                                            a2 = (int *)((__int64)a2 - (__int64)src);
                                                            ptr2 = a2 + 1;
                                                            if (a2 >= v9) {
                                                                src2 = &off_140111F70;
                                                                sub_1400F3600(0, ptr2, v9, src2);
                                                                ptr2 = 0;
                                                            }
                                                            i2 = (__int64)src + (__int64)ptr2;
                                                            result = off_14012D018;
                                                            ((__int64 (*)())result)(10, src, i2);
                                                            a2 = result + 1;
                                                            i = (__int64 *)((__int64)i - (__int64)ptr2);
                                                            a1 = rsp + 32;
                                                            sub_1400F5F40(a1, a2, i);
                                                            src = result;
                                                            i = (__int64 *)v_70;
                                                            if (ptr3 != 0) {
                                                                v9 = (__int64)i;
                                                                do {
                                                                    sub_14000A690(v9);
                                                                    v9 += 32;
                                                                    --ptr3;
                                                                } while ((ptr3 != 0));
                                                            }
                                                            if (v_68 != 0) {
                                                                off_140108030();
                                                                off_140108038(result, 0, i);
                                                            }
                                                            a2 = (int *)v_d0;
                                                            v9 = a2[4];
                                                            i = a2[5];
                                                            ptr2 = 6;
                                                            ptr3 = 1;
                                                            src2 = (__int64 *)v_d8;
                                                            a2[6] = a2[6] + 1;
                                                            if (i < v9) {
                                                                result = *src2;
                                                                a1 = *(__int64 *)((__int64)result + (__int64)i);
                                                                while (a1 <= 44) {
                                                                    if (!((!((v11 >> (__int64)a1) & 1)))) {
                                                                        ++i;
                                                                        a2[5] = i;
                                                                        i = (__int64 *)a2;
                                                                        v_20 = 2;
                                                                        sub_1400276D0(src2, a2, i2, src2);
                                                                        a1 = rsp + 32;
                                                                        sub_1400F5F40(a1, result, a2);
                                                                        src3 = result;
                                                                        v_20 = (__int64)ptr2;
                                                                        v_28 = (__int64)src;
                                                                        xmm0 = _mm_load_si128((__m128i *)&v_90);
                                                                        _mm_storeu_si128((__m128i *)&v_30, xmm0);
                                                                        v_40 = (__int64)result;
                                                                        if (ptr3 == 0) {
                                                                            a1 = rsp + 32;
                                                                            sub_14000A690(a1, i);
                                                                            ptr2 = 6;
                                                                            src = src3;
                                                                        } else {
                                                                            sub_14000A5E0(src3);
                                                                            ptr2 = 6;
                                                                        }
                                                                        if (ptr2 == 6) {
                                                                            sub_1400F28F0(src, src3, i2);
                                                                            ptr->field_8 = result;
                                                                            *(__int64 *)ptr = (__int64)(6);
                                                                        } else {
                                                                            *(__int64 *)ptr = (__int64)(ptr2);
                                                                            ptr->field_1 = result;
                                                                            result = (__int64 *)v_a8;
                                                                            ptr->field_2 = result;
                                                                            result = (__int64 *)v_ac;
                                                                            ptr->field_6 = result;
                                                                            ptr->field_8 = src;
                                                                            _mm_storeu_si128((__m128i *)(ptr + 16), xmm0);
                                                                        }
                                                                        return (__int64)result;
                                                                    }
                                                                    if (a1 == 44) {
                                                                        a1 = i + 1;
                                                                        a2[5] = a1;
                                                                        if (a1 >= v9) JUMPOUT(0x140002833);
                                                                        i += 2;
                                                                        a1 = 1;
                                                                        a1 -= v9;
                                                                        do {
                                                                            i2 = *(__int64 *)((__int64)result + (__int64)i - 1);
                                                                            if (i2 > 32) JUMPOUT(0x14000281c);
                                                                            if ((!((v11 >> (__int64)i2) & 1))) JUMPOUT(0x14000281c);
                                                                            a2[5] = i;
                                                                            i2 = (__int64)a1 + (__int64)i;
                                                                            ++i2;
                                                                            ++i;
                                                                        } while (i2 != 2);
                                                                        return sub_140002833();
                                                                    }
                                                                }
                                                                if (a1 != 93) JUMPOUT(0x140002833);
                                                                ++i;
                                                                a2[5] = i;
                                                                xmm0 = _mm_load_si128((__m128i *)&v_90);
                                                                _mm_storeu_si128((__m128i *)&v_30, xmm0);
                                                                if (ptr3 == 0) {
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                                                                } else {
                                                                    ptr2 = 6;
                                                                }
                                                                return (__int64)ptr2;
                                                            }
                                                            return (__int64)ptr2;
                                                        }
                                                        return (__int64)ptr2;
                                                    }
                                                    return (__int64)ptr2;
                                                } else {
                                                    if (src3 < 0) {
                                                        return (__int64)ptr2;
                                                    } else {
                                                        if (src3 == 0) {
                                                            return (__int64)ptr2;
                                                        } else {
                                                            return (__int64)ptr2;
                                                        }
                                                        return (__int64)ptr2;
                                                    }
                                                    return (__int64)ptr2;
                                                }
                                                return (__int64)ptr2;
                                            } else {
                                                ptr->field_8 = i;
                                                *(__int64 *)ptr = (__int64)(6);
                                            }
                                        } else {
                                            if (result != 45) {
                                                result += 208;
                                                if (result >= 10) {
                                                    v_20 = 10;
                                                    src3 = (__int64 *)a2;
                                                    sub_1400276D0(src2, result, a2);
                                                    a1 = rsp + 32;
                                                    sub_1400F5F40(a1, result, a2);
                                                    src = result;
                                                    return (__int64)src;
                                                } else {
                                                    a1 = rsp + 104;
                                                    sub_140001350(a1, a2, 1);
                                                    a1 = (size_t *)v_68;
                                                    if (a1 != 3) {
                                                        result = 2;
                                                        src3 = (__int64 *)v_70;
                                                        if (a1 == 2) {
                                                            return (__int64)src3;
                                                        } else {
                                                            if (a1 != 1) {
                                                                result = 0x7FFFFFFFFFFFFFFF;
                                                                result = (__int64 *)((__int64)(__int64)result & (__int64)src3);
                                                                a1 = 0x7FEFFFFFFFFFFFFF;
                                                                if (result <= a1) {
                                                                    v_20 = 0;
                                                                    a1 = rsp + 32;
                                                                    sub_14000A690(a1);
                                                                    result = 2;
                                                                    a1 = 2;
                                                                } else {
                                                                    result = 0;
                                                                    a1 = 3;
                                                                }
                                                            } else {
                                                                a1 = 0;
                                                            }
                                                        }
                                                        return (__int64)a1;
                                                    } else {
                                                        result = (__int64 *)v_70;
                                                        return (__int64)result;
                                                    }
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            } else {
                                                ++i;
                                                a2[5] = i;
                                                a1 = rsp + 104;
                                                sub_140001350(a1, a2, 0);
                                                a1 = (size_t *)v_68;
                                                if (a1 == 3) {
                                                    return (__int64)a1;
                                                } else {
                                                    src3 = (__int64 *)v_70;
                                                    if (a1 == 0) {
                                                        return (__int64)src3;
                                                    } else {
                                                        result = 2;
                                                        if (a1 == 1) {
                                                            return (__int64)result;
                                                        } else {
                                                            return (__int64)result;
                                                        }
                                                    }
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        break;
                                }
                                return (__int64)result;
                            }
                            return (__int64)result;
                        } while (true);
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            }
        }
        return (__int64)result;
    }
    return (__int64)result;
}