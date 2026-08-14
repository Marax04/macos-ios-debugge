// inferred from 4 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 5 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_140022532();
__int64 sub_140022618();
__int64 sub_140013110();
__int64 sub_140022689();
__int64 sub_14002285E();
__int64 sub_1400186D0();
__int64 sub_1400232AF();
__int64 sub_140022D10();
__int64 sub_140022D6B();
__int64 sub_140022CC1();
extern __int64 off_1401109D2;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;
extern __int64 off_1401109A8;
extern __int64 off_14011530C;
extern __int64 off_1401109D3;
extern __int64 off_14011D534;
extern __int64 off_1401109E9;
extern __int64 off_1401109E5;

__int64 __fastcall sub_140021E7D(size_t *a1) {
    int arg_8;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_50;
    int v_60;
    int v_7;
    int src;
    char *src2;
    struct Struct_2_t *ptr;
    struct Struct_1_t *result;
    __int64 *v12;
    __int64 v2;
    __int64 *v5;
    __int64 v3;
    __int64 v10;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v6;
    __int64 v11;
    __int64 v13;
    __int64 v8;
    __int64 v9;
    __int64 v7;

    ptr = (struct Struct_2_t *)a1;
    result = *a1;
    if (result != 0) {
        a1 = ptr->field_18;
        ++a1;
        ptr->field_18 = a1;
        if (a1 <= 500) {
            a1 = ptr->field_10;
            if (a1 < ptr->field_8) {
                v12 = (__int64 *)v3;
                v2 = *(__int64 *)((__int64)result + (__int64)a1);
                ++a1;
                ptr->field_10 = a1;
                result = (struct Struct_1_t *)v2;
                if (v2 <= 76) {
                    if (result == 66) {
                        sub_140022532(ptr, v12, v6, v7);
                        v5 = 1;
                    } else {
                        if (result == 67) {
                            v5 = src2 - 8;
                            sub_140022618(v5, ptr, 115);
                            if (*v5 != 1) {
                                v2 = *src2;
                                v_38 = v2;
                                if (ptr->field_0 == 0) {
                                    a1 = ptr->field_20;
                                    if (a1 == 0) {
                                        v5 = 0;
                                    } else {
                                        v3 = &off_1401109D2;
                                        sub_140013110(a1, v3, 1);
                                        v5 = (__int64 *)result;
                                    }
                                    result = (struct Struct_1_t *)v5;
                                    return (__int64)result;
                                } else {
                                    sub_140022689(v5, ptr);
                                    if (*v5 == 0) {
                                        v2 = *src2;
                                        a1 = ptr->field_20;
                                        if (a1 != 0) {
                                            result = &off_1401109B9;
                                            v3 = &off_1401109A9;
                                            if (v2 != 0) v3 = result;
                                            result = (struct Struct_1_t *)v2;
                                            v10 = result + (__int64)(__int64)result*8;
                                            v10 += 16;
                                            sub_140013110(a1, v3, v10);
                                            v5 = 1;
                                            if (result == 0) {
                                                *(__int64 *)ptr = (__int64)(0);
                                                ptr->field_8 = v2;
                                                return (__int64)v5;
                                            }
                                            return (__int64)v5;
                                        }
                                        return (__int64)v5;
                                    } else {
                                        xmm0 = _mm_loadu_si128((__m128i *)&src);
                                        xmm1 = _mm_loadu_si128((__m128i *)&arg_8);
                                        _mm_store_si128((__m128i *)&v_50, xmm1);
                                        _mm_store_si128((__m128i *)&v_60, xmm0);
                                        v3 = ptr->field_20;
                                        if (v3 != 0) {
                                            a1 = src2 - 96;
                                            sub_14002285E(a1, v3);
                                            v5 = 1;
                                            if (result == 0) {
                                                result = ptr->field_20;
                                                if (result != 0) {
                                                    if (v2 != 0) {
                                                        a1 = 0x800000;
                                                        a1 = (size_t *)((__int64)(__int64)a1 & (__int64)result->field_10);
                                                        if (!((a1 != 0))) {
                                                            a1 = result->field_0;
                                                            result = result->field_8;
                                                            v3 = &off_1401109A8;
                                                            ((__int64 (*)())(result->field_18))();
                                                            if (result == 0) {
                                                                v3 = ptr->field_20;
                                                                a1 = src2 - 56;
                                                                sub_1400186D0(a1, v3, 1);
                                                                if (result == 0) {
                                                                    result = ptr->field_20;
                                                                    a1 = result->field_0;
                                                                    result = result->field_8;
                                                                    v3 = &off_14011530C;
                                                                    v6 = 1;
                                                                    ((__int64 (*)())(result->field_18))();
                                                                    if (result == 0) {
                                                                        if (ptr->field_0 != 0) {
                                                                            ptr->field_18 = ptr->field_18 - 1;
                                                                        }
                                                                        return v6;
                                                                    } else {
                                                                        v5 = 1;
                                                                    }
                                                                    return (__int64)v5;
                                                                }
                                                            }
                                                            return (__int64)v5;
                                                        }
                                                    }
                                                }
                                                return (__int64)v5;
                                            }
                                            return (__int64)v5;
                                        }
                                        return (__int64)v5;
                                    }
                                }
                            } else {
                                v2 = v_7;
                                return v2;
                            }
                        } else {
                            if (result != 73) {
                                a1 = ptr->field_20;
                                if (a1 != 0) {
                                    v3 = &off_1401109A9;
                                    sub_140013110(a1, v3, 16);
                                    v5 = 1;
                                    if (result == 0) {
                                        *(__int64 *)ptr = (__int64)(0);
                                        ptr->field_8 = 0;
                                        return (__int64)v5;
                                    }
                                    return (__int64)v5;
                                }
                                return (__int64)v5;
                            } else {
                                sub_140021E7D(ptr);
                                v5 = 1;
                                if (result == 0) {
                                    if (v12 != 0) {
                                        a1 = ptr->field_20;
                                        if (a1 != 0) {
                                            v3 = &off_1401109D3;
                                            sub_140013110(a1, v3, 2);
                                            if (result == 0) {
                                                a1 = ptr->field_20;
                                                if (a1 != 0) {
                                                    v3 = &off_14011D534;
                                                    sub_140013110(a1, v3, 1);
                                                    if (result == 0) {
                                                        sub_1400232AF(ptr);
                                                        if (result == 0) {
                                                            a1 = ptr->field_20;
                                                            if (a1 != 0) {
                                                                v3 = &off_1401109E9;
                                                                sub_140013110(a1, v3, 1);
                                                                if (result == 0) {
                                                                    return v3;
                                                                }
                                                                return v3;
                                                            }
                                                            return v3;
                                                        } else {
                                                        }
                                                    }
                                                    return v3;
                                                }
                                                return v3;
                                            }
                                            return v3;
                                        }
                                    }
                                    return v3;
                                }
                                return v3;
                            }
                        }
                        return v3;
                    }
                } else {
                    if (result > 87) {
                        if (result == 88) {
                            v5 = src2 - 8;
                            sub_140022618(v5, ptr, 115);
                            if (*v5 != 1) {
                                sub_140022D10(ptr);
                                a1 = ptr->field_20;
                                if (a1 != 0) {
                                    v3 = &off_14011D534;
                                    sub_140013110(a1, v3, 1);
                                    v5 = 1;
                                    if (result == 0) {
                                        sub_140022D6B(ptr);
                                        v5 = 1;
                                        if (result == 0) {
                                            if (v2 != 77) {
                                                a1 = ptr->field_20;
                                                if (a1 != 0) {
                                                    v3 = &off_1401109E5;
                                                    sub_140013110(a1, v3, 4);
                                                    if (result == 0) {
                                                        sub_140021E7D(ptr);
                                                        if (result == 0) {
                                                            return v3;
                                                        }
                                                    }
                                                    return v3;
                                                }
                                                return v3;
                                            }
                                            return v3;
                                        }
                                    }
                                    return v3;
                                }
                                return v3;
                            } else {
                                v2 = v_7;
                                a1 = ptr->field_20;
                                if (a1 != 0) {
                                    result = (struct Struct_1_t *)v2;
                                    v10 = result + (__int64)(__int64)result*8;
                                    v10 += 16;
                                    v11 = &off_1401109B9;
                                    v3 = &off_1401109A9;
                                    if (result != 0) v3 = v11;
                                    return v3;
                                }
                                return v3;
                            }
                            return v3;
                        } else {
                            if (result == 89) {
                                return v3;
                            } else {
                                return v3;
                            }
                            return v3;
                        }
                        return v3;
                    } else {
                        if (result == 77) {
                            return v3;
                        } else {
                            if (result != 78) {
                                return v3;
                            } else {
                                sub_140022CC1(ptr);
                                v2 = (__int64)result;
                                if ((v2 & 1) == 0) {
                                    sub_140021E7D(ptr);
                                    v5 = 1;
                                    if (result == 0) {
                                        if (ptr->field_0 == 0) {
                                            a1 = ptr->field_20;
                                            if (a1 != 0) {
                                                v3 = &off_1401109D3;
                                                sub_140013110(a1, v3, 2);
                                                if (result == 0) {
                                                    if (ptr->field_0 != 0) {
                                                        v12 = src2 - 8;
                                                        sub_140022618(v12, ptr, 115);
                                                        if (*v12 == 1) {
                                                            return (__int64)v12;
                                                        } else {
                                                            if (ptr->field_0 == 0) {
                                                                a1 = ptr->field_20;
                                                                if (a1 != 0) {
                                                                    v3 = &off_1401109D2;
                                                                    v6 = 1;
                                                                    return sub_140013110();
                                                                }
                                                            } else {
                                                                v13 = arg_8;
                                                                sub_140022689(v12, ptr);
                                                                if (*v12 == 0) {
                                                                    return v13;
                                                                } else {
                                                                    v2 >>= 32;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)&src);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)&arg_8);
                                                                    _mm_store_si128((__m128i *)&v_20, xmm1);
                                                                    _mm_store_si128((__m128i *)&v_30, xmm0);
                                                                    if (v2 != 0x110000) JUMPOUT(0x140022401);
                                                                    result = (struct Struct_1_t *)v_18;
                                                                    result = (struct Struct_1_t *)((__int64)(__int64)result | v_28);
                                                                    if (!((result == 0))) {
                                                                        a1 = ptr->field_20;
                                                                        if (a1 != 0) {
                                                                            v3 = &off_1401109D3;
                                                                            sub_140013110(a1, v3, 2);
                                                                            if (result == 0) {
                                                                                v3 = ptr->field_20;
                                                                                if (v3 != 0) {
                                                                                    a1 = src2 - 48;
                                                                                    sub_14002285E(a1, v3);
                                                                                    return (__int64)a1;
                                                                                }
                                                                                return (__int64)a1;
                                                                            }
                                                                            return (__int64)a1;
                                                                        }
                                                                    }
                                                                    return (__int64)a1;
                                                                }
                                                            }
                                                            return (__int64)a1;
                                                        }
                                                        return (__int64)a1;
                                                    }
                                                    return (__int64)a1;
                                                }
                                                return (__int64)a1;
                                            }
                                            return (__int64)a1;
                                        }
                                        return (__int64)a1;
                                    }
                                } else {
                                    v2 &= 256;
                                    a1 = ptr->field_20;
                                    if (a1 != 0) {
                                        result = 0;
                                        result = (v2 != 0) ? 1 : 0;
                                        v8 = &off_1401109A9;
                                        v3 = &off_1401109B9;
                                        if (v2 == 0) v3 = v8;
                                        v9 = result + (__int64)(__int64)result*8;
                                        v9 += 16;
                                        sub_140013110(a1, v3, v9);
                                        v5 = 1;
                                        if (result == 0) {
                                            *(__int64 *)ptr = (__int64)(0);
                                            ptr->field_8 = v2;
                                            return (__int64)v5;
                                        }
                                        return (__int64)v5;
                                    }
                                    return (__int64)v5;
                                }
                                return (__int64)v5;
                            }
                            return (__int64)v5;
                        }
                        return (__int64)v5;
                    }
                    return (__int64)v5;
                }
                return (__int64)v5;
            }
            return (__int64)v5;
        } else {
            a1 = ptr->field_20;
            if (a1 != 0) {
                v3 = &off_1401109B9;
                sub_140013110(a1, v3, 25);
                v5 = 1;
                if (result == 0) {
                    *(__int64 *)ptr = (__int64)(0);
                    ptr->field_8 = 1;
                    return (__int64)v5;
                }
                return (__int64)v5;
            }
            return (__int64)v5;
        }
        return (__int64)v5;
    }
    return (__int64)result;
}