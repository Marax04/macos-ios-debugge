// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F5F40();
__int64 sub_1400F3600();
__int64 sub_140027750();
__int64 sub_140001000();
__int64 sub_1400F58D0();
extern __int64 off_14012D020;
extern __int64 off_14012D018;
extern __int64 off_140111F70;

__int64 __fastcall sub_140001350(__int64 *str,struct Struct_1_t *a2, __int64 a3, size_t a4) {
    int v_30;
    __int64 *result;
    __int64 v2;
    __int64 *i;
    __int64 *dst;
    __int64 *src;
    __int64 v5;
    __int64 v9;
    __int64 v8;
    __int64 i2;
    __int64 v7;
    __int64 xmm0;

    result = a2 + 24;
    v2 = a2->field_20;
    i = a2->field_28;
    if (i >= v2) {
        str = 5;
        if ((0 /* unresolved: flags > */)) JUMPOUT(0x140001540);
        dst = str;
        src = *result;
    } else {
        src = a2->field_18;
        a4 = *(__int64 *)((__int64)src + (__int64)i);
        v5 = i + 1;
        a2->field_28 = v5;
        if (a4 == 48) {
            if (v5 < v2) {
                result = *(src + v5);
                result += 208;
                if (result >= 10) {
                } else {
                    dst = str;
                    str = 13;
                    i += 2;
                    if (i >= v2) i = v2;
                    a3 = (__int64)src + (__int64)i;
                    result = off_14012D020;
                    ((__int64 (*)())result)(10, src, a3, a4);
                    if (((__int64)result & 1) == 0) {
                        v9 = 0;
                    } else {
                        a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)src);
                        v9 = a2 + 1;
                        if (a2 < v2) {
                            v8 = src + v9;
                            result = off_14012D018;
                            ((__int64 (*)())result)(10, src, v8, 0);
                            a2 = result + 1;
                            i -= v9;
                            sub_1400F5F40(str, a2, i);
                            *(dst + 8) = result;
                            *dst = 3;
                        } else {
                            a4 = &off_140111F70;
                            sub_1400F3600(0, v9, v2, a4);
                            i2 = a4 - 49;
                            if (i2 >= 9) {
                                str = 13;
                                i = str;
                                sub_140027750(result);
                                sub_1400F5F40(str, result, a2);
                                *(i + 8) = result;
                                *i = 3;
                            } else {
                                a4 += 208;
                                if (v5 < v2) {
                                    result = 1;
                                    result -= v2;
                                    i += 2;
                                    v7 = 0x1999999999999999;
                                    i2 = *(__int64 *)((__int64)src + (__int64)i - 1);
                                    i2 += 208;
                                    while (i2 < 10) {
                                        if (a4 < v7) {
                                            a2->field_28 = i;
                                            a4 += a4*4;
                                            a4 = i2 + a4*2;
                                            i2 = (__int64)result + (__int64)i;
                                            ++i2;
                                            ++i;
                                            return sub_140001000();
                                        }
                                        if (a4 == v7) {
                                            if (i2 <= 5) {
                                                return (__int64)i;
                                            }
                                        }
                                        i = str;
                                        sub_1400F58D0(str, a2, a3, a4);
                                        if (str != 1) {
                                            xmm0 = v_30;
                                            *(i + 8) = xmm0;
                                            result = 0;
                                            *i = result;
                                        } else {
                                            result = (__int64 *)v_30;
                                            *(i + 8) = result;
                                            result = 3;
                                            *i = result;
                                        }
                                        return (__int64)result;
                                    }
                                }
                                return (__int64)result;
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