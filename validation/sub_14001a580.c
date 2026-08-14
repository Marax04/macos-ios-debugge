// inferred from 12 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
};

__int64 sub_1400F3600();
__int64 sub_1400F3869();
__int64 sub_1400F27FC();
__int64 sub_140013110();
extern __int64 off_14010F0C8;
extern __int64 off_14010F0B0;
extern __int64 off_14010F068;
extern __int64 off_14010F098;
extern __int64 off_14010FD48;
extern __int64 off_14010F080;

__int64 __fastcall sub_14001A580(int *a1, int *a2, int *a3, int a4) {
    int arg_70;
    int v_8;
    char *dst;
    __int64 *src;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 i;
    __int64 i2;
    __int64 v8;
    __int64 result;
    __int64 v7;
    __int64 i3;

    src = (__int64 *)a4;
    v2 = (__int64)a3;
    ptr = (struct Struct_1_t *)a1;
    v3 = arg_70;
    *dst = a2;
    if (v3 != 1) {
        i = 1;
        i2 = 0;
        a3 = 1;
        a4 = 0;
        v8 = 1;
        result = 0;
        a1 = result + a4;
        while (a1 < v3) {
            a1 = *(__int64 *)((__int64)src + (__int64)a1);
            if (*(src + i) < a1) {
                a3 += a4;
                ++a3;
                v8 = (__int64)a3;
                v8 -= result;
                a4 = 0;
                i = a3 + a4;
                i2 = 1;
                a3 = 0;
                a4 = 1;
                i = 0;
                a2 = 1;
                v7 = 0;
                a1 = v7 + i;
                while (a1 < v3) {
                    a1 = *(__int64 *)((__int64)src + (__int64)a1);
                    if (*(src + i2) > a1) {
                        a4 += i;
                        ++a4;
                        a2 = (int *)a4;
                        a2 -= v7;
                        i = 0;
                        i2 = a4 + i;
                        if (result > v7) v7 = result;
                        if (0 /* unresolved: flags <= */) v8 = a2;
                        i3 = v3;
                        i3 -= v7;
                        if ((i3 < 0)) {
                            a4 = &off_14010F0C8;
                            sub_1400F3600(0, v7, v3, a4);
                        } else {
                            a2 = (int *)v8;
                            a2 += v7;
                            if (!((a2 < 0))) {
                                if (a2 > v3) {
                                    a4 = &off_14010F0B0;
                                    sub_1400F3600(v8, a2, v3, a4);
                                    a3 = &off_14010F068;
                                    sub_1400F3869(a1, v3, a3);
                                } else {
                                    a2 = src + v8;
                                    sub_1400F27FC(src, a2, v7);
                                    if (result == 0) {
                                        v_8 = v2;
                                        a4 = 1;
                                        a3 = 0;
                                        i = 0;
                                        i2 = 1;
                                        a2 = 0;
                                        result = i2 + i;
                                        while (result < v3) {
                                            result = i2;
                                            result = ~result;
                                            a1 = (int *)v3;
                                            a1 -= i;
                                            a1 += result;
                                            if (a1 < v3) {
                                                result = i;
                                                result = ~result;
                                                result += v3;
                                                result -= (__int64)a2;
                                                if (result < v3) {
                                                    i3 = i2 + 1;
                                                    result = *(src + result);
                                                    if (*(__int64 *)((__int64)src + (__int64)a1) < result) {
                                                        i3 = i + i2;
                                                        ++i3;
                                                        a4 = i3;
                                                        a4 -= (__int64)a2;
                                                        i = 0;
                                                        i2 = i3;
                                                        v2 = 1;
                                                        a3 = 0;
                                                        i2 = 0;
                                                        i3 = 1;
                                                        i = 0;
                                                        result = i3 + i2;
                                                        while (result < v3) {
                                                            result = i3;
                                                            result = ~result;
                                                            a1 = (int *)v3;
                                                            a1 -= i2;
                                                            a1 += result;
                                                            if (a1 < v3) {
                                                                result = i2;
                                                                result = ~result;
                                                                result += v3;
                                                                result -= i;
                                                                if (result < v3) {
                                                                    a4 = i3 + 1;
                                                                    result = *(src + result);
                                                                    if (*(__int64 *)((__int64)src + (__int64)a1) > result) {
                                                                        a4 = i2 + i3;
                                                                        ++a4;
                                                                        v2 = a4;
                                                                        v2 -= i;
                                                                        i2 = 0;
                                                                        i3 = a4;
                                                                        if (i > a2) a2 = i;
                                                                        a1 = (int *)v3;
                                                                        a1 = (int *)((__int64)a1 - (__int64)a2);
                                                                        if (v8 == 0) {
                                                                            a4 = 0;
                                                                            a2 = (int *)v3;
                                                                            result = 0;
                                                                            v8 = 0;
                                                                            v2 = v_8;
                                                                            i3 = *dst;
                                                                        } else {
                                                                            a2 = (int *)v8;
                                                                            a2 = (int *)((__int64)(__int64)a2 & 3);
                                                                            v2 = v_8;
                                                                            i3 = *dst;
                                                                            if (v8 >= 4) {
                                                                                a4 = v8;
                                                                                a4 &= -4;
                                                                                a3 = 0;
                                                                                result = 0;
                                                                                for (; a4 != a3; a3 += 4) {
                                                                                    i = *(__int64 *)((__int64)src + (__int64)a3);
                                                                                    i2 = *(__int64 *)((__int64)src + (__int64)a3 + 1);
                                                                                    result |= 1 << i; /* bts: CF = old bit */;
                                                                                    result |= 1 << i2; /* bts: CF = old bit */;
                                                                                    i = *(__int64 *)((__int64)src + (__int64)a3 + 2);
                                                                                    result |= 1 << i; /* bts: CF = old bit */;
                                                                                    i = *(__int64 *)((__int64)src + (__int64)a3 + 3);
                                                                                    result |= 1 << i; /* bts: CF = old bit */;
                                                                                }
                                                                            } else {
                                                                                a3 = 0;
                                                                                result = 0;
                                                                            }
                                                                            if (a2 == 0) {
                                                                                a4 = 0;
                                                                            } else {
                                                                                a3 = (int *)((__int64)a3 + (__int64)src);
                                                                                a4 = 0;
                                                                                for (i = 0; a2 != i; ++i) {
                                                                                    i2 = *(a3 + i);
                                                                                    result |= 1 << i2; /* bts: CF = old bit */;
                                                                                }
                                                                            }
                                                                            a2 = (int *)v3;
                                                                        }
                                                                        ptr->field_48 = i3;
                                                                        ptr->field_50 = v2;
                                                                        ptr->field_58 = src;
                                                                        ptr->field_60 = v3;
                                                                        *(__int64 *)ptr = (__int64)(1);
                                                                        ptr->field_8 = v7;
                                                                        ptr->field_10 = a1;
                                                                        ptr->field_18 = v8;
                                                                        ptr->field_20 = result;
                                                                        ptr->field_28 = 0;
                                                                        ptr->field_30 = v2;
                                                                        ptr->field_38 = a4;
                                                                        ptr->field_40 = a2;
                                                                        return (__int64)a2;
                                                                    }
                                                                    if (*(__int64 *)((__int64)src + (__int64)a1) != result) {
                                                                        v2 = 1;
                                                                        i2 = 0;
                                                                        i = i3;
                                                                        return i;
                                                                    }
                                                                    ++i2;
                                                                    result = i2;
                                                                    if (i2 == v2) result = a3;
                                                                    if (i2 != v2) i2 = a3;
                                                                    a4 = i2;
                                                                    a4 += i3;
                                                                    i2 = result;
                                                                    return i2;
                                                                }
                                                                a3 = &off_14010F098;
                                                                sub_1400F3869(result, v3, a3);
                                                                a1 = a2;
                                                                a2 = &off_14010FD48;
                                                                a3 = 24;
                                                                return sub_140013110();
                                                            }
                                                            a3 = &off_14010F080;
                                                            sub_1400F3869(a1, v3, a3);
                                                            return (__int64)a3;
                                                        }
                                                        return (__int64)a3;
                                                    }
                                                    if (*(__int64 *)((__int64)src + (__int64)a1) != result) {
                                                        a4 = 1;
                                                        i = 0;
                                                        a2 = (int *)i2;
                                                        return (__int64)a2;
                                                    }
                                                    ++i;
                                                    result = i;
                                                    if (i == a4) result = a3;
                                                    if (i != a4) i = a3;
                                                    i3 = i;
                                                    i3 += i2;
                                                    i = result;
                                                    return i;
                                                }
                                                return i;
                                            }
                                            return i;
                                        }
                                        return i;
                                    } else {
                                        a1 = (int *)v3;
                                        a1 = (int *)((__int64)(__int64)a1 & 3);
                                        if (v3 >= 4) {
                                            a3 = (int *)v3;
                                            a3 = (int *)((__int64)(__int64)a3 & 28);
                                            a2 = 0;
                                            result = 0;
                                            do {
                                                a4 = *(__int64 *)((__int64)src + (__int64)a2);
                                                i = *(__int64 *)((__int64)src + (__int64)a2 + 1);
                                                result |= 1 << a4; /* bts: CF = old bit */;
                                                result |= 1 << i; /* bts: CF = old bit */;
                                                a4 = *(__int64 *)((__int64)src + (__int64)a2 + 2);
                                                result |= 1 << a4; /* bts: CF = old bit */;
                                                a4 = *(__int64 *)((__int64)src + (__int64)a2 + 3);
                                                result |= 1 << a4; /* bts: CF = old bit */;
                                                a2 += 4;
                                            } while (a3 != a2);
                                        } else {
                                            a2 = 0;
                                            result = 0;
                                        }
                                        if (a1 != 0) {
                                            a2 = (int *)((__int64)a2 + (__int64)src);
                                            for (a3 = 0; a1 != a3; ++a3) {
                                                a4 = *(__int64 *)((__int64)a2 + (__int64)a3);
                                                result |= 1 << a4; /* bts: CF = old bit */;
                                            }
                                        }
                                        if (i3 <= v7) i3 = v7;
                                        ++i3;
                                        a4 = -1;
                                        a2 = -1;
                                        v8 = i3;
                                        a1 = (int *)v7;
                                        i3 = *dst;
                                    }
                                    return i3;
                                }
                                return i3;
                            }
                        }
                        return i3;
                    }
                    if (*(src + i2) != a1) {
                        v7 = a4;
                        ++a4;
                        a2 = 1;
                        return (__int64)a2;
                    }
                    ++i;
                    a1 = (int *)i;
                    if (i == a2) a1 = a3;
                    if (i != a2) i = a3;
                    a4 += i;
                    i = (__int64)a1;
                    i2 = a4 + a1;
                    return i2;
                }
                return i2;
            }
            if (*(src + i) == a1) {
                ++a4;
                a1 = (int *)a4;
                if (a4 == v8) a1 = i2;
                if (a4 != v8) a4 = i2;
                a3 += a4;
                a4 = (int)a1;
                i = (__int64)a3 + (__int64)a1;
                return i;
            }
            result = (__int64)a3;
            ++a3;
            v8 = 1;
            return v8;
        }
    } else {
        v8 = 1;
        result = 0;
        v7 = 0;
        a2 = 1;
        return (__int64)a2;
    }
    return result;
}