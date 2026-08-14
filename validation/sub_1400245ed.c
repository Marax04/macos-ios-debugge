// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140022618();
__int64 sub_140013110();
__int64 sub_140022689();
__int64 sub_140023492();
__int64 sub_14002285E();
extern __int64 off_1401109D2;
extern __int64 off_140116F20;
extern __int64 off_140117BCE;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_1400245ED(size_t *a1) {
    int v_10;
    int v_17;
    int v_18;
    int v_30;
    int v_40;
    int v_8;
    char *str;
    __int64 v8;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v2;
    __int64 v12;
    __int64 v10;
    __int64 v13;
    __int64 v11;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v3;
    __int64 v6;
    __int64 v7;
    __int64 v9;

    v8 = *a1;
    if (v8 != 0) {
        ptr = (struct Struct_1_t *)a1;
        v5 = str - 24;
        v2 = &off_1401109D2;
        v12 = str - 64;
        v10 = &off_140116F20;
        v13 = 0;
        do {
            a1 = ptr->field_10;
            --v13;
            if ((v13 < 0)) {
                sub_140022618(v5, ptr, 115);
                if (v_18 != 1) {
                    if (ptr->field_0 == 0) {
                        a1 = ptr->field_20;
                        if (a1 == 0) {
                            v8 = ptr->field_0;
                            v11 = 0;
                            result = v11;
                            return result;
                        }
                        v11 = 1;
                        sub_140013110(a1, v2, 1);
                        if (result == 0) {
                            return v11;
                        }
                        return v11;
                    }
                    sub_140022689(v5, ptr);
                    if (v_18 != 0) {
                        xmm0 = _mm_loadu_si128((__m128i *)&v_18);
                        xmm1 = _mm_loadu_si128((__m128i *)&v_8);
                        _mm_store_si128((__m128i *)&v_30, xmm1);
                        _mm_store_si128((__m128i *)&v_40, xmm0);
                        v3 = ptr->field_20;
                        if (v3 == 0) {
                            sub_140023492(ptr, 1);
                            if (result == 0) {
                                return v3;
                            }
                            v11 = 1;
                            return v11;
                        }
                        sub_14002285E(v12, v3);
                        if (result == 0) {
                            a1 = ptr->field_20;
                            if (a1 == 0) {
                                return (__int64)a1;
                            }
                            v3 = &off_140117BCE;
                            sub_140013110(a1, v3, 2);
                            if (result == 0) {
                                return v3;
                            }
                        }
                        return v3;
                    }
                    v2 = v_10;
                    a1 = ptr->field_20;
                    if (a1 != 0) {
                        result = v2;
                        v6 = v8 + v8*8;
                        v6 += 16;
                        v7 = &off_1401109B9;
                        v3 = &off_1401109A9;
                        if (result != 0) v3 = v7;
                        sub_140013110(a1, v3, v6, v7);
                        if (result == 0) {
                            *(__int64 *)ptr = (__int64)(0);
                            ptr->field_8 = v2;
                            return v3;
                        } else {
                            return v3;
                        }
                        return v3;
                    }
                    return v3;
                }
                v2 = v_17;
                a1 = ptr->field_20;
                if (a1 != 0) {
                    v9 = &off_1401109B9;
                    v3 = &off_1401109A9;
                    if (v2 != 0) v3 = v9;
                    result = v2;
                    v6 = v9 + v9*8;
                    v6 += 16;
                    return v6;
                }
                return v6;
            }
            a1 = ptr->field_20;
            if (a1 == 0) {
                return (__int64)a1;
            }
            sub_140013110(a1, v10, 2);
            if (result == 0) {
                if (ptr->field_0 == 0) {
                    return (__int64)a1;
                }
                return (__int64)a1;
            }
            return (__int64)a1;
        } while (v8 != 0);
        return (__int64)a1;
    }
    return result;
}