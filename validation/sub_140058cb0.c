// inferred from 3 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140059420();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 sub_140059019();
__int64 sub_1400F3360();
__int64 off_140108038();
extern __int64 off_140108030;

__int64 __fastcall sub_140058CB0(int *a1,struct Struct_1_t *a2, int a3) {
    __int64 rsp;
    int arg_10;
    int arg_8;
    int arg_9;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_70;
    __int64 *result;
    struct Struct_2_t *ptr;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;
    __int64 v4;
    __int64 v10;
    __int64 v9;
    __int64 v12;
    __int64 v2;
    __int64 v11;
    __int64 v8;
    __int64 v7;

    result = a2->field_18;
    if (result != 0) {
        ptr = (struct Struct_2_t *)a2;
        a2 = a2->field_10;
        a3 = a2->field_0;
        v5 = result - 1;
        v6 = a2 + 1;
        ptr->field_10 = v6;
        ptr->field_18 = v5;
        if (a3 != 34) {
            ptr->field_10 = a2;
            ptr->field_18 = result;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
            *a1 = 1;
            arg_8 = 0;
            a1[1] = 0;
            a1[1] = 0;
            arg_9 = 0;
            a1[2] = 8;
        } else {
            v_38 = (int)a1;
            v_28 = 1;
            v_30 = 0;
            result = 0x8000000000000000;
            v_20 = (__int64)result;
            a1 = rsp + 64;
            sub_140059420(a1, ptr, a3, v5);
            a1 = (int *)v_40;
            v4 = v_48;
            xmm0 = _mm_loadu_si128((__m128i *)&v_50);
            _mm_store_si128((__m128i *)&v_70, xmm0);
            if (a1 != 3) {
                xmm0 = _mm_loadu_si128((__m128i *)&v_60);
                result = (__int64 *)v_38;
                _mm_storeu_si128((__m128i *)(result + 32), xmm0);
                xmm0 = _mm_load_si128((__m128i *)&v_70);
                _mm_storeu_si128((__m128i *)(result + 16), xmm0);
                *result = a1;
            } else {
                v10 = 0x8000000000000001;
                if (v4 != v10) {
                    result = rsp + 40;
                    xmm0 = _mm_load_si128((__m128i *)&v_70);
                    _mm_storeu_si128((__m128i *)result, xmm0);
                    v_20 = v4;
                }
                v9 = rsp + 64;
                v12 = off_140108030;
                sub_140059420(v9, ptr);
                a1 = (int *)v_40;
                v2 = v_48;
                v11 = v_50;
                v4 = v_58;
                while (a1 == 3) {
                    if (v2 != v10) {
                        result = (__int64 *)v_20;
                        v8 = v_30;
                        a1 = (int *)result;
                        a1 = (int *)(-(__int64)a1);
                        if ((0 /* overflow check on (-a1) */)) {
                            result -= v8;
                            if (v4 > result) {
                                a1 = rsp + 32;
                                sub_1400F5F90(a1, v8, v4);
                                v8 = v_30;
                            }
                            a1 = (int *)v_28;
                            a1 += v8;
                            sub_1400F27F0(a1, v11, v4);
                            v8 += v4;
                            v_30 = v8;
                            v2 <<= 1;
                            ((__int64 (*)())v12)();
                            off_140108038(result, 0, v11);
                        }
                        if (v8 >= 0) {
                            v10 = v9;
                            v7 = v_28;
                            if (v8 == 0) {
                                v12 = 1;
                                sub_1400F27F0(v12, v7, v8);
                                v_20 = v8;
                                v_28 = v12;
                                result = (__int64 *)v8;
                                v9 = v10;
                                v10 = 0x8000000000000001;
                                v12 = off_140108030;
                                return v12;
                            }
                            sub_14002EDF0(0, v8);
                            v12 = (__int64)result;
                            if (result != 0) {
                                return v12;
                            }
                            return sub_140059019();
                        }
                        sub_1400F3360();
                        xmm0 = _mm_loadu_si128((__m128i *)&v_60);
                        result = (__int64 *)v_38;
                        _mm_storeu_si128((__m128i *)(result + 32), xmm0);
                        *result = a1;
                        arg_8 = v2;
                        arg_10 = v11;
                        a1 = 24;
                        *(__int64 *)((__int64)result + (__int64)a1) = v4;
                        result = (__int64 *)v_20;
                        result = (__int64 *)((__int64)(__int64)result << 1);
                        if (result != 0) {
                            ptr = (struct Struct_2_t *)v_28;
                            ((__int64 (*)())off_140108030)(8);
                            off_140108038(result, 0, ptr);
                        }
                        return (__int64)ptr;
                    }
                    result = ptr->field_18;
                    if (result == 0) JUMPOUT(0x140058f77);
                    a1 = ptr->field_10;
                    a2 = *a1;
                    a3 = result - 1;
                    v5 = a1 + 1;
                    ptr->field_10 = v5;
                    ptr->field_18 = a3;
                    if (a2 != 34) JUMPOUT(0x140058f6f);
                    result = (__int64 *)v_30;
                    a1 = (int *)v_38;
                    a1[3] = result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                    _mm_storeu_si128((__m128i *)(a1 + 8), xmm0);
                    *a1 = 3;
                    return _mm_cvtsi128_si64(xmm0);
                }
                return _mm_cvtsi128_si64(xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}