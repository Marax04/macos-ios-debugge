// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

// inferred from 2 accesses on `i`
struct Struct_2_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

__int64 sub_14001A3F0();
__int64 sub_140019DC1();
__int64 sub_1400F2808();
__int64 sub_140019E26();
__int64 sub_140019DD6();
extern __int64 off_14010E4A8;
extern __int64 off_14010FC48;
extern __int64 off_1401085D8;

__int64 __fastcall sub_1400196A0(size_t *a1,struct Struct_1_t *a2, size_t *a3, size_t a4) {
    __int64 arg_5c0;
    int arg_5c8;
    int arg_5d0;
    __int64 v_60;
    char *str;
    __int64 v8;
    __int64 i2;
    __int64 result;
    struct Struct_2_t *i;
    __int64 i3;
    __int64 *i4;
    __int64 v2;
    __int64 *i5;
    __int64 *i6;
    __int64 v7;
    __int64 xmm0;

    if (a3 == 0) {
        *(a1 + 1) = 0;
    } else {
        v8 = a2->field_0;
        if (v8 != 45) {
            if (v8 == 43) {
                --a3;
                if (!((a3 == 0))) {
                    ++a2;
                    arg_5d0 = (int)a1;
                    if (a3 < 8) {
                        i2 = 0;
                        result = (__int64)a3;
                        i = (struct Struct_2_t *)a2;
                    } else {
                        i2 = 0;
                        a4 = 0x4646464646464646;
                        i3 = 0xCFCFCFCFCFCFCFD0;
                        i4 = 0x8080808080808080;
                        a1 = 0xFF000000FF;
                        v2 = 0xF424000000064;
                        i5 = 0x271000000001;
                        i = (struct Struct_2_t *)a2;
                        result = (__int64)a3;
                        i6 = i->field_0;
                        v7 = i6 + a4;
                        i6 += i3;
                        v7 |= (__int64)i6;
                        while ((v7 & (__int64)i4) == 0) {
                            v7 = i2 * 0x5F5E100;
                            i2 = i6 + (__int64)(__int64)i6*4;
                            i6 = (__int64 *)((__int64)(__int64)i6 >> 8);
                            i2 = i6 + i2*2;
                            i6 = (__int64 *)i2;
                            i6 = (__int64 *)((__int64)(__int64)i6 & (__int64)a1);
                            i6 = (__int64 *)((__int64)(__int64)(__int64)i6 * v2);
                            i2 >>= 16;
                            i2 &= (__int64)a1;
                            i2 *= (__int64)i5;
                            i2 += (__int64)i6;
                            i2 >>= 32;
                            i2 += v7;
                            result -= 8;
                            i += 8;
                            if (result != 0) {
                                i3 = 0;
                                a1 = i->field_0;
                                a4 = a1 - 48;
                                while (a4 <= 9) {
                                    ++i;
                                    a1 = i2 + i2*4;
                                    i2 = a4 + (__int64)(__int64)a1*2;
                                    --result;
                                    i = 1;
                                    result = 0;
                                    a4 = (size_t)a3;
                                    v2 = 0;
                                    v7 = 0;
                                    if (a4 >= 20) {
                                        a4 -= 19;
                                        a1 = 0;
                                        do {
                                            i4 = *(__int64 *)((__int64)a2 + (__int64)a1);
                                            i4 -= 47;
                                            if (i4 < 0) i4 = v7;
                                            a4 -= (__int64)i4;
                                            ++a1;
                                        } while (a3 != a1);
                                        if (a4 <= 0) {
                                            v7 = 0;
                                            if (i != 0) {
                                                result = v2 - 38;
                                                result = (result < -60) ? 1 : 0;
                                                a1 = 0x20000000000000;
                                                a1 = (i2 > a1) ? 1 : 0;
                                                result |= v7;
                                                result |= (__int64)a1;
                                                if ((result == 0)) {
                                                    a1 = (size_t *)arg_5d0;
                                                    if (v2 > 22) {
                                                        arg_5c8 = (int)a2;
                                                        a2 = &off_14010E4A8;
                                                        result = i2;
                                                        i2 *= *(a2 + v2*8 - 176); /* unsigned; high half in a2 */;
                                                        a4 = (0 /* unresolved: flags OF */) ? 1 : 0;
                                                        a4 = ~a4;
                                                        a2 = 0x20000000000001;
                                                        a2 = (i2 < a2) ? 1 : 0;
                                                        if ((a4 & (__int64)a2) != 0) JUMPOUT(0x140019da0);
                                                        i6 = (__int64 *)v8;
                                                        arg_5c0 = (__int64)a3;
                                                        v8 = (__int64)a1;
                                                        sub_14001A3F0(v2, i2, a3, a4);
                                                        i5 = (__int64 *)result;
                                                        i4 = (__int64 *)a2;
                                                    } else {
                                                        /* cvtsi2sd %i2, %xmm0 */;
                                                        if (v2 < 0) JUMPOUT(0x140019daf);
                                                        result = &off_14010FC48;
                                                        /* mulsd (%result,%v2,8), %xmm0 */;
                                                        return sub_140019DC1();
                                                    }
                                                } else {
                                                    i6 = (__int64 *)v8;
                                                    arg_5c0 = (__int64)a3;
                                                    arg_5c8 = (int)a2;
                                                    v8 = arg_5d0;
                                                    sub_14001A3F0(v2, i2, a3, a4);
                                                    i5 = (__int64 *)result;
                                                    i4 = (__int64 *)a2;
                                                    result = (a2 >= 0) ? 1 : 0;
                                                    if ((v7 & result) == 0) {
                                                        a1 = (size_t *)v8;
                                                        v7 = (__int64)i6;
                                                        if (i4 >= 0) JUMPOUT(0x14001a1e0);
                                                    } else {
                                                        ++i2;
                                                        sub_14001A3F0(v2, i2);
                                                        v7 = (__int64)i6;
                                                        if (i5 == result) {
                                                            a1 = (size_t *)v8;
                                                            if (i4 == a2) JUMPOUT(0x14001a1e0);
                                                        }
                                                    }
                                                    v2 = str - 96;
                                                    i4 = 0;
                                                    i2 = str - 96;
                                                    sub_1400F2808(i2, 0, 781);
                                                    a1 = 0;
                                                    i3 = 0;
                                                    i = (struct Struct_2_t *)arg_5c8;
                                                    a3 = (size_t *)arg_5c0;
                                                    do {
                                                        if (a3 == i3) JUMPOUT(0x14001a068);
                                                        result = i3;
                                                        a2 = (struct Struct_1_t *)a1;
                                                        a4 = *(__int64 *)(i + i3);
                                                        ++i3;
                                                        --a1;
                                                    } while (a4 == 48);
                                                    i5 = a4 - 48;
                                                    if (i5 > 9) JUMPOUT(0x140019dec);
                                                    a2 = (struct Struct_1_t *)a3;
                                                    a2 -= i3;
                                                    a2 += 2;
                                                    a1 = (size_t *)((__int64)a1 + (__int64)a3);
                                                    result = i + i3;
                                                    i6 = 0;
                                                    do {
                                                        a4 = (size_t)a2;
                                                        i4 = i6 + 1;
                                                        if (a1 == i6) JUMPOUT(0x140019eac);
                                                        i6 = (__int64 *)((__int64)i6 + (__int64)i);
                                                        v8 = *(i6 + i3);
                                                        i5 = v8 - 48;
                                                        a2 = a4 - 1;
                                                        i6 = i4;
                                                    } while (i5 <= 9);
                                                    v_60 = (__int64)i4;
                                                    if (v8 != 46) JUMPOUT(0x140019ee2);
                                                    result += (__int64)i4;
                                                    result -= 2;
                                                    a2 -= 2;
                                                    result += 2;
                                                    a4 = (size_t)a2;
                                                    return sub_140019E26();
                                                }
                                                return a4;
                                            }
                                        } else {
                                            a4 = (size_t)a3;
                                            a4 = -a4;
                                            i2 = 0;
                                            i4 = 0xDE0B6B3A763FFFF;
                                            i5 = (__int64 *)a2;
                                            a1 = (size_t *)a4;
                                            a4 = *i5;
                                            a4 += 208;
                                            while (a4 <= 9) {
                                                ++i5;
                                                i2 += i2*4;
                                                i2 = a4 + i2*2;
                                                a4 = (size_t)a1;
                                                ++a4;
                                                v2 = (a4 == 0) ? 1 : 0;
                                                if (i2 <= i4) {
                                                }
                                                if (i2 <= i4) {
                                                    if (a1 == -1) JUMPOUT(0x14001a3d8);
                                                    a4 = -a4;
                                                    --a4;
                                                    if ((a4 != 0)) {
                                                        ++i5;
                                                        result = a4;
                                                        a1 = *i5;
                                                        a1 += 208;
                                                        while (a1 <= 9) {
                                                            v2 = result - 1;
                                                            i2 += i2*4;
                                                            i2 = a1 + i2*2;
                                                            if (i2 <= i4) {
                                                                ++i5;
                                                                /* cmp result , 1 */;
                                                                result = v2;
                                                            }
                                                            v2 -= a4;
                                                            v2 += i3;
                                                            v7 = 1;
                                                            if (i != 0) {
                                                                return v7;
                                                            } else {
                                                                if (a3 == 3) {
                                                                    a1 = a2->field_0;
                                                                    result = a2->field_1;
                                                                    result <<= 8;
                                                                    result |= (__int64)a1;
                                                                    result &= 0xDFDFDF;
                                                                    a1 = (size_t *)arg_5d0;
                                                                    if (result == 0x464E49) JUMPOUT(0x140019d96);
                                                                    if (result == 0x4E414E) {
                                                                        xmm0 = off_1401085D8;
                                                                        return sub_140019DC1();
                                                                    }
                                                                } else {
                                                                    a1 = (size_t *)arg_5d0;
                                                                    if (a3 == 8) {
                                                                        result = 0xDFDFDFDFDFDFDFDF;
                                                                        result &= a2->field_0;
                                                                        a2 = 0x5954494E49464E49;
                                                                        if (result == a2) JUMPOUT(0x140019d96);
                                                                    }
                                                                }
                                                                *(a1 + 1) = 1;
                                                                result = 1;
                                                                return sub_140019DD6();
                                                            }
                                                        }
                                                        v2 = result;
                                                    } else {
                                                        v2 = 0;
                                                    }
                                                    return v2;
                                                } else {
                                                    result += a4;
                                                    result = -result;
                                                    v2 = result;
                                                    v2 += i3;
                                                    v7 = 1;
                                                    if (i == 0) {
                                                        return v7;
                                                    }
                                                }
                                                return v7;
                                            }
                                            a1 = (size_t *)(-(__int64)a1);
                                            a4 = (size_t)a1;
                                            --a4;
                                            if ((a4 == 0)) {
                                                return a4;
                                            } else {
                                                return a4;
                                            }
                                            return a4;
                                        }
                                        return a4;
                                    }
                                    return a4;
                                }
                                i5 = (__int64 *)a3;
                                i5 -= result;
                                if (a1 != 46) {
                                    a4 = 0;
                                    i3 = result;
                                    v2 = 0;
                                    a4 += (__int64)i5;
                                    if ((a4 != 0)) {
                                        i4 = (__int64 *)i3;
                                        --i4;
                                        if ((i4 >= 0)) {
                                            a1 = i->field_0;
                                            a1 = (size_t *)((__int64)(__int64)a1 | 32);
                                            if (a1 != 101) {
                                                i = 0;
                                                i3 = 0;
                                            } else {
                                                if (i4 != 0) {
                                                    i6 = i + 1;
                                                    i5 = *i6;
                                                    if (i5 != 45) {
                                                        a1 = (size_t *)i5;
                                                        if (i5 == 43) {
                                                            i3 -= 2;
                                                            if (!((i3 == 0))) {
                                                                a1 = i->field_2;
                                                                i += 2;
                                                                i6 = (__int64 *)i;
                                                                i4 = (__int64 *)i3;
                                                                a1 += 208;
                                                                if (a1 <= 9) {
                                                                    a1 = 0;
                                                                    i = 0;
                                                                    i3 = *i6;
                                                                    i3 += 208;
                                                                    while (i3 <= 9) {
                                                                        ++i6;
                                                                        /* cmp i , 0x10000 */;
                                                                        v7 = i + (__int64)(__int64)i*4;
                                                                        i3 += v7*2;
                                                                        if (i3 < 0) a1 = i3;
                                                                        if (i3 < 0) i = i3;
                                                                        --i4;
                                                                        i4 = 0;
                                                                    }
                                                                    i3 = (__int64)a1;
                                                                    i3 = -i3;
                                                                    if (i5 != 45) i3 = a1;
                                                                    v2 += i3;
                                                                    i = (i4 == 0) ? 1 : 0;
                                                                    return (__int64)i;
                                                                }
                                                            }
                                                            return (__int64)i;
                                                        }
                                                        return (__int64)i;
                                                    }
                                                    return (__int64)i;
                                                }
                                                return (__int64)i;
                                            }
                                        } else {
                                            i3 = 0;
                                            i = 1;
                                        }
                                        return (__int64)i;
                                    } else {
                                    }
                                    return (__int64)i;
                                } else {
                                    arg_5c0 = (__int64)i5;
                                    arg_5c8 = v8;
                                    a4 = result - 1;
                                    ++i;
                                    if (a4 < 8) {
                                        i3 = a4;
                                    } else {
                                        i5 = 0xCFCFCFCFCFCFCFD0;
                                        i6 = 0x8080808080808080;
                                        v7 = 0xFF000000FF;
                                        v8 = 0xF424000000064;
                                        i4 = 0x271000000001;
                                        i3 = a4;
                                        a1 = i->field_0;
                                        v2 = 0x4646464646464646;
                                        v2 += (__int64)a1;
                                        a1 = (size_t *)((__int64)a1 + (__int64)i5);
                                        v2 |= (__int64)a1;
                                        while ((v2 & (__int64)i6) == 0) {
                                            v2 = i2 * 0x5F5E100;
                                            i2 = a1 + (__int64)(__int64)a1*4;
                                            a1 = (size_t *)((__int64)(__int64)a1 >> 8);
                                            i2 = a1 + i2*2;
                                            a1 = (size_t *)i2;
                                            a1 = (size_t *)((__int64)(__int64)a1 & v7);
                                            a1 = (size_t *)((__int64)(__int64)(__int64)a1 * v8);
                                            i2 >>= 16;
                                            i2 &= v7;
                                            i2 *= (__int64)i4;
                                            i2 += (__int64)a1;
                                            i2 >>= 32;
                                            i2 += v2;
                                            i3 -= 8;
                                            i += 8;
                                            v8 = arg_5c8;
                                            if (i3 != 0) {
                                                i5 = (__int64 *)arg_5c0;
                                                i4 = (__int64 *)i;
                                                i += i3;
                                                a1 = *i4;
                                                a1 += 208;
                                                while (a1 <= 9) {
                                                    ++i4;
                                                    i2 += i2*4;
                                                    i2 = a1 + i2*2;
                                                    --i3;
                                                    i3 = 0;
                                                    a4 -= i3;
                                                    v2 = a4;
                                                    v2 = -v2;
                                                    a4 += (__int64)i5;
                                                    if (!((a4 == 0))) {
                                                        return a4;
                                                    }
                                                    return a4;
                                                }
                                                i = (struct Struct_2_t *)i4;
                                            } else {
                                                i3 = 0;
                                                i5 = (__int64 *)arg_5c0;
                                            }
                                            return (__int64)i5;
                                        }
                                        v8 = arg_5c8;
                                        return v8;
                                    }
                                    return v8;
                                }
                                return v8;
                            } else {
                                i = 1;
                                result = 0;
                                a4 = (size_t)a3;
                                i3 = 0;
                                v2 = 0;
                            }
                            return v2;
                        }
                    }
                    return v2;
                }
                return v2;
            }
            return v2;
        }
        return v2;
    }
    return result;
}