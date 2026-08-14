// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F1D90();
__int64 sub_1400F3600();
__int64 sub_1400F37A0();
__int64 sub_1400F3869();
__int64 sub_140018B70();
__int64 sub_140028EC7();
__int64 off_1401080C0();
__int64 off_1401080C8();
__int64 off_140108060();
extern __int64 off_140113680;
extern __int64 off_140113640;
extern __int64 off_140113650;
extern __int64 off_140113668;
extern __int64 off_140116031;
extern __int64 off_1400291E0;
extern __int64 off_14011603A;
extern __int64 off_140028EE0;
extern __int64 off_140116045;

__int64 __fastcall sub_140028B80(size_t a1,struct Struct_1_t *a2, int *a3) {
    __int64 rsp;
    int arg_18;
    int arg_1fb8;
    int arg_1fc0;
    int arg_1fc8;
    int arg_1fd0;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_7;
    int v_8;
    char *str;
    __int64 *src;
    __int64 v3;
    __int64 v4;
    __int64 result;
    __int64 v8;
    __int64 v6;
    __m128i xmm0;
    __int64 *src2;
    __int64 v9;
    __int64 v5;
    __int64 v7;

    sub_1400F1D90(0x2068);
    src = rsp + 128;
    v3 = (__int64)a3;
    v4 = a1;
    if (v3 >= 0x1001) {
        for (v3 = 0x1000; *(a3 + v3) <= 191; --v3) {
            if (*(a3 + v3 - 1) <= 191) {
                if (*(a3 + v3 - 2) <= 191) {
                    if (*(a3 + v3 - 3) <= 191) {
                        v3 -= 4;
                        v3 = 0;
                        result = src - 72;
                        v_20 = result;
                        v_28 = 0x1000;
                        off_1401080C0(0xFDE9, 8, a2, v3);
                        if (result != 0) {
                            v8 = result;
                            if (result >= 0x1001) {
                                v6 = &off_140113680;
                                sub_1400F3600(0, v8, 0x1000, v6);
                                result = &off_140113640;
                                arg_1fb8 = result;
                                arg_1fc0 = 1;
                                arg_1fc8 = 8;
                                xmm0 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&arg_1fd0, xmm0);
                                a2 = &off_140113650;
                                a1 = src + 0x1FB8;
                                sub_1400F37A0(a1, a2);
                            } else {
                                arg_1fb8 = 0;
                                v_20 = 0;
                                src2 = src - 72;
                                off_1401080C8(v4, src2, result, str);
                                if (result == 0) {
                                    off_140108060(0);
                                    v3 = result;
                                    v3 <<= 32;
                                    v3 |= 2;
                                    result = 1;
                                } else {
                                    v9 = arg_1fb8;
                                    if (v9 != v8) {
                                        if ((0 /* unresolved: flags >= */)) {
                                            v5 = &off_140113668;
                                            sub_1400F3869(v9, v8, v5);
                                            src = rsp + 64;
                                            v4 = (__int64)a2;
                                            v3 = a1;
                                            result = a1 + 8;
                                            v_18 = result;
                                            a1 = a2->field_0;
                                            result = a2->field_8;
                                            a2 = &off_140116031;
                                            a3 = 9;
                                            ((__int64 (*)())(arg_18))();
                                            v_10 = v4;
                                            v_8 = result;
                                            v_7 = 0;
                                            result = &off_1400291E0;
                                            v_20 = result;
                                            a2 = &off_14011603A;
                                            v4 = src - 16;
                                            sub_140018B70(v4, a2, 11, v3);
                                            result = &off_140028EE0;
                                            v_20 = result;
                                            a2 = &off_140116045;
                                            v7 = src - 24;
                                            sub_140018B70(v4, a2, 9, v7);
                                            a1 = v_8;
                                            result = v_7;
                                            a2 = (struct Struct_1_t *)result;
                                            a2 = (struct Struct_1_t *)(~(__int64)a2);
                                            a2 = (struct Struct_1_t *)((__int64)(__int64)a2 | a1);
                                            if (((__int64)a2 & 1) == 0) JUMPOUT(0x140028e90);
                                            result |= a1;
                                            return sub_140028EC7();
                                        } else {
                                            a2 =  + v9*2 - 72;
                                            a2 = (struct Struct_1_t *)((__int64)a2 + (__int64)src);
                                            result = *(src + v9*2 - 72);
                                            result += 0x2312;
                                            if (result >= 786) {
                                                if (v9 == 0) {
                                                    v3 = 0;
                                                } else {
                                                    result = 0;
                                                    v3 = 0;
                                                    for (; src2 != a2; src2 += 2) {
                                                        a1 = *src2;
                                                        a3 = 1;
                                                        v3 += (__int64)a3;
                                                    }
                                                }
                                                a2 = (struct Struct_1_t *)v3;
                                                return (__int64)a2;
                                            } else {
                                                arg_1fb8 = 0;
                                                v_20 = 0;
                                                off_1401080C8(v4, a2, 1, str);
                                                if (result == 0) {
                                                    off_140108060();
                                                }
                                                a2 =  + v9*2 - 70;
                                                a2 = (struct Struct_1_t *)((__int64)a2 + (__int64)src);
                                            }
                                            return (__int64)a2;
                                        }
                                    }
                                    return (__int64)a2;
                                }
                                return (__int64)a2;
                            }
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    }
                    v3 -= 3;
                    return v3;
                }
                v3 -= 2;
                return v3;
            }
        }
    }
    return result;
}