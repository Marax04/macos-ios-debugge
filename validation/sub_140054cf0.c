// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 9 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[48];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
};

// inferred from 5 accesses on `i`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140058820();
__int64 sub_1400F8520();
__int64 sub_1400F27F0();
__int64 sub_1400F27F6();
__int64 sub_14004F470();
__int64 sub_140046190();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3B20();
__int64 sub_1400F3326();
__int64 sub_140055638();
__int64 sub_1400F3360();
__int64 sub_1400F8440();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401159D0;
extern __int64 off_140116770;
extern __int64 off_1401168B0;
extern __int64 off_140115F08;

__int64 __fastcall sub_140054CF0(int *a1, int *a2) {
    __int64 rsp;
    int arg_10;
    __int64 arg_18;
    int arg_20;
    int arg_28;
    int arg_60;
    __int64 arg_8;
    int v_10;
    int v_100;
    int v_108;
    int v_110;
    int v_128;
    int v_130;
    int v_138;
    int v_140;
    int v_148;
    int v_150;
    int v_158;
    __int64 v_18;
    __int64 v_20;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    __int64 v_50;
    __int64 v_58;
    __int64 v_60;
    int v_68;
    __int64 v_70;
    __int64 v_78;
    int v_8;
    int v_80;
    __int64 v_88;
    int v_90;
    int v_98;
    int v_f8;
    struct Struct_1_t *ptr;
    struct Struct_3_t *i;
    __int64 *result;
    __int64 v10;
    struct Struct_4_t *ptr3;
    __int64 *v12;
    __int64 i2;
    __int64 *src;
    __int64 v11;
    __m128i xmm0;
    struct Struct_2_t *ptr2;
    __int64 v6;
    __int64 v7;

    ptr = (struct Struct_1_t *)a2;
    i = (struct Struct_3_t *)a1;
    result = (__int64 *)arg_10;
    v_38 = (__int64)result;
    result = (__int64 *)arg_18;
    v_30 = (__int64)result;
    v_40 = 0;
    v_48 = 8;
    v_50 = 0;
    a1 = rsp + 296;
    sub_140058820(a1);
    if (!__OFSUB(result, v_128)) {
        v_20 = (__int64)i;
        a1 = rsp + 64;
        sub_1400F8520(a1, a2, 8);
        v10 = v_48;
        a2 = rsp + 296;
        ptr3 = 144;
        sub_1400F27F0(v10, a2, 144);
        v_50 = 1;
        v12 = ptr->field_10;
        i2 = ptr->field_18;
        if (i2 == 0) {
            i2 = 0;
            i = 1;
        } else {
            i = 1;
            src = rsp + 104;
            v11 = 0;
            while (*v12 == 46) {
                result = v12 + 1;
                a1 = i2 - 1;
                ptr->field_10 = result;
                ptr->field_18 = a1;
                sub_140058820(src, ptr);
                if (!(__OFSUB(v11, v_68))) {
                    if (i == v_40) {
                        a1 = rsp + 64;
                        sub_1400F8520(a1);
                        v10 = v_48;
                    }
                    a1 = v10 + ptr3;
                    sub_1400F27F6(a1, src, 144);
                    ++i;
                    v_50 = (__int64)i;
                    v12 = ptr->field_10;
                    i2 = ptr->field_18;
                    ptr3 += 144;
                    i2 = 0;
                    xmm0 = _mm_setzero_si128();
                    _mm_storeu_si128((__m128i *)&v_110, xmm0);
                    v_f8 = 1;
                    v_100 = 0;
                    v_108 = 8;
                    ptr->field_10 = v12;
                    ptr->field_18 = i2;
                    v11 = v_40;
                    a1 = rsp + 248;
                    sub_14004F470(a1, a2, ptr2);
                    v12 = (__int64 *)i;
                    i = (struct Struct_3_t *)v_20;
                    if (v12 >= 80) {
                        src = (__int64 *)ptr2;
                        v10 = (__int64)ptr2;
                        i2 = (__int64)v12;
                        do {
                            sub_140046190(v10, a2, v11);
                            v10 += 144;
                            --i2;
                        } while ((i2 != 0));
                        if (v11 != 0) {
                            off_140108030();
                            off_140108038(result, 0, src);
                        }
                        result = (__int64 *)v_38;
                        ptr->field_10 = result;
                        result = (__int64 *)v_30;
                        ptr->field_18 = result;
                        sub_14002EDF0(0, 48);
                        if (result == 0) {
                            sub_1400F3340(8, 48, ptr2);
                        } else {
                            a1 = 0x8000000000000002;
                            *result = a1;
                            arg_18 = (__int64)v12;
                            ptr3 = 1;
                            a1 = &off_1401159D0;
                            a2 = 0;
                            v11 = 0;
                            *(__int64 *)i = (__int64)(ptr3);
                            i->field_8 = v11;
                            i->field_10 = ptr2;
                            i->field_18 = a2;
                            i->field_20 = result;
                            i->field_28 = a1;
                            return v11;
                        }
                    } else {
                        if (v12 == 0) {
                            a1 = &off_140116770;
                            ptr2 = &off_1401168B0;
                            sub_1400F3B20(a1, 23, ptr2);
                        } else {
                            result = ptr2->field_60;
                            v10 = 0x8000000000000000;
                            ptr3 = 0x8000000000000003;
                            v_58 = v11;
                            if (result != ptr3) {
                                ptr = 0x8000000000000000;
                                a2 = (int *)result;
                                a2 = (int *)((__int64)(__int64)a2 ^ (__int64)ptr);
                                a1 = 1;
                                if (result < 0) a1 = a2;
                                if (a1 == 0) {
                                } else {
                                    if (a1 != 1) {
                                        a1 = ptr2->field_68;
                                        v_38 = (__int64)a1;
                                        a1 = ptr2->field_70;
                                        v_28 = (__int64)a1;
                                        ptr = 0x8000000000000002;
                                    } else {
                                        ptr = ptr2->field_70;
                                        if (ptr >= 0) {
                                            src = (__int64 *)ptr2;
                                            v11 = ptr2->field_68;
                                            if (ptr == 0) {
                                            } else {
                                                sub_14002EDF0(0, ptr, v10);
                                                if (result == 0) {
                                                    sub_1400F3326(1, ptr);
                                                } else {
                                                    a1 = (int *)result;
                                                    v_38 = (__int64)a1;
                                                    sub_1400F27F0(1, v11, ptr);
                                                    ptr2 = (struct Struct_2_t *)src;
                                                    result = (__int64 *)arg_60;
                                                    v_28 = (__int64)ptr;
                                                    if (result != ptr3) {
                                                        if (result > 0) {
                                                            v11 = ptr2->field_68;
                                                            src = (__int64 *)ptr2;
                                                            off_140108030(a1);
                                                            off_140108038(result, 0, v11);
                                                        }
                                                    } else {
                                                    }
                                                    result = 0x8000000000000000;
                                                    ptr2->field_60 = result;
                                                    result =  + (__int64)(__int64)v12*8;
                                                    result = (__int64 *)((__int64)result + (__int64)v12);
                                                    result = (__int64 *)((__int64)(__int64)result << 4);
                                                    v11 = (__int64)ptr2 + (__int64)result;
                                                    result = *(__int64 *)((__int64)ptr2 + (__int64)result - 24);
                                                    if (result != ptr3) {
                                                        v10 = 0x8000000000000000;
                                                        a2 = (int *)result;
                                                        a2 = (int *)((__int64)(__int64)a2 ^ v10);
                                                        if (result < 0) a1 = a2;
                                                        if (a1 != 0) {
                                                            if (a1 != 1) {
                                                                a1 = (int *)v_10;
                                                                v_30 = (__int64)a1;
                                                                src = (__int64 *)v_8;
                                                                v10 = 0x8000000000000002;
                                                            } else {
                                                                src = (__int64 *)v_8;
                                                                if (src >= 0) {
                                                                    i2 = (__int64)ptr2;
                                                                    ptr3 = (struct Struct_4_t *)v_10;
                                                                    if ((0 /* unresolved: flags == */)) {
                                                                    } else {
                                                                        sub_14002EDF0(0, src, i2);
                                                                        if (result == 0) {
                                                                            sub_1400F3326(1, src);
                                                                            v6 = *src;
                                                                            result = (__int64 *)arg_8;
                                                                            v12 = ptr2->field_0;
                                                                            i = ptr2->field_8;
                                                                            v7 = ptr2->field_10;
                                                                            i2 = ptr2->field_20;
                                                                            v11 = ptr2->field_28;
                                                                            if (v6 == 0) JUMPOUT(0x140055522);
                                                                            v10 = arg_10;
                                                                            ptr = (struct Struct_1_t *)arg_20;
                                                                            ptr3 = (struct Struct_4_t *)arg_28;
                                                                            if (v6 != 1) JUMPOUT(0x14005552f);
                                                                            v_20 = v7;
                                                                            if (v12 == 0) JUMPOUT(0x14005564a);
                                                                            src = ptr2->field_18;
                                                                            if (v12 != 1) JUMPOUT(0x1400556c4);
                                                                            v12 = (__int64 *)a1;
                                                                            if (result != 0) {
                                                                                off_140108030(a1, a2, ptr2, v6);
                                                                                off_140108038(result, 0, v10);
                                                                                v7 = v_20;
                                                                                a1 = (int *)v12;
                                                                            }
                                                                            if (ptr != 0) {
                                                                                result = ptr3->field_0;
                                                                                if (result != 0) {
                                                                                    ((__int64 (*)())result)(ptr);
                                                                                    v7 = v_20;
                                                                                }
                                                                                if (ptr3->field_8 != 0) {
                                                                                    if (ptr3->field_10 >= 17) {
                                                                                        ptr = *(__int64 *)(ptr - 8);
                                                                                    }
                                                                                    off_140108030(v12);
                                                                                    off_140108038(result, 0, ptr);
                                                                                    a1 = (int *)v12;
                                                                                    v7 = v_20;
                                                                                }
                                                                            }
                                                                            arg_8 = (__int64)i;
                                                                            a1[2] = v7;
                                                                            a1[3] = src;
                                                                            a1[4] = i2;
                                                                            a1[5] = v11;
                                                                            *a1 = 1;
                                                                            return sub_140055638();
                                                                        } else {
                                                                            a1 = (int *)result;
                                                                        }
                                                                    }
                                                                    v_30 = (__int64)a1;
                                                                    sub_1400F27F0(1, ptr3, src);
                                                                    result = (__int64 *)v_18;
                                                                    v10 = (__int64)src;
                                                                    ptr3 = 0x8000000000000003;
                                                                    ptr2 = (struct Struct_2_t *)i2;
                                                                    if (result != ptr3) {
                                                                        if (result > 0) {
                                                                            i2 = (__int64)ptr3;
                                                                            ptr3 = (struct Struct_4_t *)v_10;
                                                                            v_20 = v10;
                                                                            v10 = (__int64)ptr;
                                                                            ptr = (struct Struct_1_t *)src;
                                                                            src = (__int64 *)ptr2;
                                                                            off_140108030(a1);
                                                                            ptr3 = (struct Struct_4_t *)i2;
                                                                            off_140108038(result, 0, ptr3);
                                                                            src = (__int64 *)ptr;
                                                                            ptr = (struct Struct_1_t *)v10;
                                                                            v10 = v_20;
                                                                        }
                                                                    } else {
                                                                    }
                                                                    v_18 = (__int64)result;
                                                                    result = (__int64 *)v_60;
                                                                    if (result != ptr3) {
                                                                        if (result > 0) {
                                                                            i2 = (__int64)ptr3;
                                                                            ptr3 = (struct Struct_4_t *)v_58;
                                                                            v_20 = v10;
                                                                            v10 = (__int64)ptr;
                                                                            ptr = (struct Struct_1_t *)src;
                                                                            src = (__int64 *)ptr2;
                                                                            off_140108030(0x8000000000000000, a1, a2, src);
                                                                            ptr3 = (struct Struct_4_t *)i2;
                                                                            off_140108038(result, 0, ptr3);
                                                                            src = (__int64 *)ptr;
                                                                            ptr = (struct Struct_1_t *)v10;
                                                                            v10 = v_20;
                                                                        }
                                                                    }
                                                                    result = (__int64 *)v_48;
                                                                    if (result != ptr3) {
                                                                        if (result > 0) {
                                                                            ptr3 = (struct Struct_4_t *)v_40;
                                                                            i2 = (__int64)ptr2;
                                                                            off_140108030(a1, a2, src);
                                                                            off_140108038(result, 0, ptr3);
                                                                        }
                                                                    }
                                                                    v_60 = (__int64)ptr;
                                                                    result = (__int64 *)v_38;
                                                                    v_58 = (__int64)result;
                                                                    result = (__int64 *)v_28;
                                                                    v_50 = (__int64)result;
                                                                    v_48 = v10;
                                                                    result = (__int64 *)v_30;
                                                                    v_40 = (__int64)result;
                                                                    v_38 = (__int64)src;
                                                                    result = (__int64 *)v_58;
                                                                    i->field_8 = result;
                                                                    i->field_10 = ptr2;
                                                                    i->field_18 = v12;
                                                                    *(__int64 *)i = (__int64)(3);
                                                                    return (__int64)result;
                                                                } else {
                                                                    sub_1400F3360(1, a2, src);
                                                                }
                                                            }
                                                            return (__int64)result;
                                                        }
                                                        return (__int64)result;
                                                    }
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                }
                                return (__int64)result;
                            } else {
                                result = 1;
                                v_28 = (__int64)result;
                                ptr = (struct Struct_1_t *)v10;
                                return (__int64)ptr;
                            }
                            return (__int64)ptr;
                        }
                        return (__int64)ptr;
                    }
                    return (__int64)ptr;
                }
                ptr3 = (struct Struct_4_t *)v_70;
                if (ptr3 != 1) {
                    v12 = (__int64 *)v10;
                    v11 = v_78;
                    ptr2 = (struct Struct_2_t *)v_80;
                    result = (__int64 *)v_88;
                    v_28 = (__int64)result;
                    i2 = v_90;
                    src = (__int64 *)v_98;
                    if (i == 0) {
                        i = (struct Struct_3_t *)v_20;
                    } else {
                        v_60 = (__int64)ptr2;
                        v_58 = v11;
                        v11 = (__int64)v12;
                        do {
                            sub_140046190(v11, a2, ptr2);
                            v11 += 144;
                            --i;
                        } while ((i != 0));
                        i = (struct Struct_3_t *)v_20;
                        v11 = v_58;
                        ptr2 = (struct Struct_2_t *)v_60;
                    }
                    if (v_40 != 0) {
                        v10 = (__int64)ptr3;
                        ptr3 = (struct Struct_4_t *)src;
                        src = (__int64 *)i2;
                        i2 = (__int64)i;
                        i = (struct Struct_3_t *)v11;
                        v11 = (__int64)ptr2;
                        off_140108030(0, a1, a2, ptr2);
                        off_140108038(result, 0, v12);
                        v11 = (__int64)i;
                        i = (struct Struct_3_t *)i2;
                        i2 = (__int64)src;
                        src = (__int64 *)ptr3;
                        ptr3 = (struct Struct_4_t *)v10;
                    }
                    if (ptr3 != 3) {
                        if (ptr3 != 0) {
                            /* cmp ptr3 , 1 */;
                            v_68 = v11;
                            v_70 = (__int64)ptr2;
                            v12 = (__int64 *)v_28;
                            v_78 = (__int64)v12;
                            v_80 = i2;
                            v_88 = (__int64)src;
                            i2 = (__int64)v12;
                            if (v12 == v11) {
                                a1 = rsp + 104;
                                sub_1400F8440(a1);
                                v11 = v_68;
                                ptr2 = (struct Struct_2_t *)v_70;
                            }
                            a1 = rsp + 112;
                            result = i2 + i2*2;
                            ((__int64 *)ptr2)[(__int64)result] = (__int64)(3);
                            a2 = &off_140115F08;
                            *(__int64 *)(ptr2 + (__int64)(__int64)result*8 + 8) = (__int64)(a2);
                            *(__int64 *)(ptr2 + (__int64)(__int64)result*8 + 16) = (__int64)(3);
                            ++i2;
                            v_78 = i2;
                            a2 = (int *)arg_8;
                            result = a1[2];
                            a1 = a1[3];
                        }
                    } else {
                        v12 = (__int64 *)v_28;
                        if (v12 < 80) {
                            return (__int64)v12;
                        } else {
                            return (__int64)v12;
                        }
                        return (__int64)v12;
                    }
                } else {
                    a1 = rsp + 112;
                    ptr->field_10 = v12;
                    ptr->field_18 = i2;
                    v11 = v_40;
                    return v11;
                }
                return v11;
            }
        }
        return v11;
    } else {
        ptr3 = (struct Struct_4_t *)v_130;
        v11 = v_138;
        ptr2 = (struct Struct_2_t *)v_140;
        result = (__int64 *)v_148;
        v_28 = (__int64)result;
        i2 = v_150;
        v12 = 8;
        src = (__int64 *)v_158;
        return (__int64)src;
    }
    return (__int64)result;
}