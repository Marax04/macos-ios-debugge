// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_1400255E7();
__int64 sub_140013110();
__int64 sub_140022689();
__int64 sub_140022D6B();
__int64 sub_14002285E();
extern __int64 off_140116F20;
extern __int64 off_140110A3F;
extern __int64 off_14011D534;
extern __int64 off_1401109E9;
extern __int64 off_1401109D2;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;
extern __int64 off_1401109FE;

__int64 __fastcall sub_140025393(size_t *a1) {
    int v_10;
    int v_18;
    int v_30;
    int v_40;
    int v_8;
    char *str;
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v13;
    __int64 v10;
    __int64 v11;
    __int64 v12;
    __int64 i;
    __int64 *v3;
    __int64 v8;
    __int64 v9;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v7;

    result = *a1;
    if (result != 0) {
        ptr = (struct Struct_1_t *)a1;
        v5 = &off_140116F20;
        v13 = str - 24;
        v10 = str - 64;
        v11 = &off_140110A3F;
        v12 = &off_14011D534;
        i = 0;
        do {
            a1 = ptr->field_10;
            if (i == 0) {
                sub_1400255E7(ptr);
                if (result != 2) {
                    v3 = ptr->field_0;
                    while (v3 != 0) {
                        a1 = ptr->field_10;
                        if (a1 >= ptr->field_8) {
                            v13 = v10;
                            v8 = v11;
                            v9 = v12;
                            v12 = v5;
                            if ((result & 1) == 0) {
                                result = ptr->field_0;
                                ++i;
                                v5 = v12;
                                v12 = v9;
                                v11 = v8;
                                v10 = v13;
                                v13 = str - 24;
                                v5 = 0;
                                result = v5;
                                return result;
                            }
                            a1 = ptr->field_20;
                            if (a1 == 0) {
                                return (__int64)a1;
                            }
                            v5 = 1;
                            v6 = 1;
                            v3 = &off_1401109E9;
                            sub_140013110(a1, v3, 1);
                            if (result == 0) {
                                return (__int64)v3;
                            }
                            return (__int64)v3;
                        }
                        if (*(__int64 *)((__int64)v3 + (__int64)a1) != 112) {
                            return (__int64)v3;
                        }
                        ++a1;
                        ptr->field_10 = a1;
                        if ((result & 1) == 0) {
                            a1 = ptr->field_20;
                            if (a1 == 0) {
                                if (ptr->field_0 == 0) {
                                    v13 = v10;
                                    v8 = v11;
                                    v9 = v12;
                                    v12 = v5;
                                    a1 = ptr->field_20;
                                    if (a1 == 0) {
                                        return (__int64)a1;
                                    }
                                    v5 = 1;
                                    v3 = &off_1401109D2;
                                    return (__int64)v3;
                                }
                                sub_140022689(v13, ptr);
                                if (v_18 != 0) {
                                    xmm0 = _mm_loadu_si128((__m128i *)&v_18);
                                    xmm1 = _mm_loadu_si128((__m128i *)&v_8);
                                    _mm_store_si128((__m128i *)&v_30, xmm1);
                                    _mm_store_si128((__m128i *)&v_40, xmm0);
                                    v3 = ptr->field_20;
                                    if (v3 == 0) {
                                        sub_140022D6B(ptr);
                                        a1 = (size_t *)result;
                                        result = 1;
                                        if (a1 == 0) {
                                        }
                                        v5 = 1;
                                        return v5;
                                    }
                                    sub_14002285E(v10, v3);
                                    if (result == 0) {
                                        a1 = ptr->field_20;
                                        if (a1 == 0) {
                                            return (__int64)a1;
                                        }
                                        sub_140013110(a1, v11, 3);
                                        if (result == 0) {
                                            return (__int64)a1;
                                        }
                                    }
                                    return (__int64)a1;
                                }
                                i = v_10;
                                a1 = ptr->field_20;
                                if (a1 != 0) {
                                    result = i;
                                    v6 = result + result*8;
                                    v6 += 16;
                                    v7 = &off_1401109B9;
                                    v3 = &off_1401109A9;
                                    if (result != 0) v3 = v7;
                                    sub_140013110(a1, v3, v6, v7);
                                    if (result == 0) {
                                        *(__int64 *)ptr = (__int64)(0);
                                        ptr->field_8 = i;
                                        return (__int64)v3;
                                    } else {
                                        return (__int64)v3;
                                    }
                                    return (__int64)v3;
                                }
                                return (__int64)v3;
                            }
                            sub_140013110(a1, v12, 1);
                            if (result == 0) {
                                return (__int64)v3;
                            }
                            return (__int64)v3;
                        }
                        a1 = ptr->field_20;
                        if (a1 == 0) {
                            return (__int64)a1;
                        }
                        v6 = 2;
                        v3 = (__int64 *)v5;
                        return (__int64)v3;
                    }
                    return (__int64)v3;
                }
                return (__int64)v3;
            }
            a1 = ptr->field_20;
            if (a1 == 0) {
                return (__int64)a1;
            }
            v3 = &off_1401109FE;
            sub_140013110(a1, v3, 3);
            if (result == 0) {
                return (__int64)v3;
            }
            return (__int64)v3;
        } while (result != 0);
        return (__int64)v3;
    }
    return result;
}