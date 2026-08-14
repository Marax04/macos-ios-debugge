// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int16 field_0; // offset 0
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

__int64 sub_14003043F();
__int64 sub_1400307FD();

__int64 __fastcall sub_1400302C0(__int64 *a1, __int64 *a2, __int64 a3) {
    int arg_3b0;
    int arg_3d0;
    int arg_3d8;
    int arg_3e0;
    __int64 arg_3e8;
    int arg_3f0;
    int arg_3f8;
    int arg_40f;
    int arg_410;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v6;
    __int64 v2;
    __int64 result;
    __int64 v3;
    int v9;
    int v8;
    __int64 v7;
    __m128i xmm0;

    arg_410 = -2;
    ptr = *(a2 + 8);
    v4 = a2[2];
    if (v4 >= 4) {
        v6 = 0x5C003F005C005C;
        if (ptr->field_0 != v6) {
            v2 = 0x5C003F003F005C;
            if (ptr->field_0 != v2) {
                if (v4 < 248) {
                    if (ptr->field_2 == 58) {
                        result = ptr->field_4;
                        if (result != 47) {
                            if (result != 92) {
                                result = ptr->field_0;
                            } else {
                                result = ptr->field_0;
                                if (result != 47) {
                                    if (result == 92) {
                                        if (result != 92) {
                                            if (result == 47) {
                                                result = ptr->field_2;
                                                if (result != 92) {
                                                    if (result != 47) {
                                                        arg_40f = a3;
                                                        arg_3e8 = (__int64)ptr;
                                                        arg_3f8 = (int)a1;
                                                        arg_3f0 = (int)a2;
                                                        arg_3d0 = 0;
                                                        arg_3d8 = 2;
                                                        arg_3e0 = 0;
                                                        v3 = 512;
                                                        result = 2;
                                                        arg_3b0 = v4;
                                                        v9 = 0;
                                                        v4 = 0;
                                                        v8 = 0;
                                                        if (v3 >= 513) JUMPOUT(0x140030450);
                                                        return sub_14003043F();
                                                    }
                                                }
                                                v7 = a2[2];
                                                a1[2] = v7;
                                                xmm0 = _mm_loadu_si128((__m128i *)a2);
                                                _mm_storeu_si128((__m128i *)a1, xmm0);
                                                return sub_1400307FD();
                                            }
                                            return _mm_cvtsi128_si64(xmm0);
                                        }
                                        return _mm_cvtsi128_si64(xmm0);
                                    } else {
                                    }
                                    return _mm_cvtsi128_si64(xmm0);
                                }
                            }
                            return _mm_cvtsi128_si64(xmm0);
                        }
                        return _mm_cvtsi128_si64(xmm0);
                    }
                    return _mm_cvtsi128_si64(xmm0);
                }
                return _mm_cvtsi128_si64(xmm0);
            }
        }
    } else {
        if (v4 != 0) {
            if (v4 == 3) {
                if (ptr->field_2 == 58) {
                    result = ptr->field_4;
                    if (result == 0) {
                        result = ptr->field_0;
                        if (result != 47) {
                            if (result == 92) {
                                return result;
                            }
                            return result;
                        }
                    } else {
                        return result;
                    }
                }
            } else {
                if (v4 != 1) {
                    return result;
                } else {
                    if (ptr->field_0 != 0) {
                        return result;
                    } else {
                    }
                }
                return result;
            }
            return result;
        }
        return result;
    }
    return result;
}