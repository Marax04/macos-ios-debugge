// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14001B090();
__int64 sub_1400F27FC();

__int64 __fastcall sub_1400679E0(int a1,struct Struct_1_t *a2, size_t a3) {
    int v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v11;
    __int64 v10;
    struct Struct_2_t *result;
    __int64 i;
    __int64 v9;
    __int64 v7;
    __int64 *src;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    __int64 i2;
    __int64 v8;

    v_30 = a1;
    v11 = a2->field_8;
    v10 = ((__int64 *)a2)[3];
    result = (v10 > v11) ? 1 : 0;
    i = ((__int64 *)a2)[2];
    a3 = (v10 < i) ? 1 : 0;
    a3 |= (__int64)result;
    if (!((a3 != 0))) {
        v9 = a2->field_0;
        v7 = ((__int64 *)a2)[5];
        src = *(__int64 *)(a2 + v7 + 31);
        if (v7 >= 5) {
            do {
                a3 = v10;
                a3 -= i;
                result = (struct Struct_2_t *)v9;
                result += i;
                v3 = (__int64)a2;
                v4 = v7;
                sub_14001B090(src, result, a3, a3);
                v7 = v4;
                v5 = (__int64)a2;
                a2 = (struct Struct_1_t *)v3;
                if (((__int64)result & 1) != 0) {
                    i += v5;
                    ++i;
                    ((__int64 *)a2)[2] = (__int64)(i);
                    result = (i < v7) ? 1 : 0;
                    a3 = (i > v11) ? 1 : 0;
                    a3 |= (__int64)result;
                    if ((a3 == 0)) JUMPOUT(0x140067cde);
                    a1 = 0;
                    result = (struct Struct_2_t *)v_30;
                    *(__int64 *)result = (__int64)(a1);
                    return (__int64)result;
                }
                ((__int64 *)a2)[2] = (__int64)(v10);
                a1 = 0;
            } while (v10 >= i);
            return a1;
        } else {
            result = a2 + 32;
            v_38 = (__int64)result;
            result = (struct Struct_2_t *)src;
            v4 = 0x101010101010101;
            v4 *= (__int64)result;
            result = v9 + 8;
            v_40 = (__int64)result;
            v3 = 0x101010101010100;
            v_28 = v9;
            do {
                a3 = v10;
                a3 -= i;
                result = (struct Struct_2_t *)v9;
                result += i;
                v5 = result + 7;
                v5 &= -8;
                v5 -= (__int64)result;
                if ((v5 != 0)) {
                    i2 = 0;
                    while (*(__int64 *)(result + i2) != src) {
                        ++i2;
                        v_20 = v7;
                        a1 = v11;
                        i2 = a3 - 16;
                        if (v5 <= i2) {
                            src = (__int64 *)v_40;
                            src += i;
                            v11 = *(src + v5 - 8);
                            v11 ^= v4;
                            v8 = v3;
                            v8 -= v11;
                            v8 |= v11;
                            v11 = *(src + v5);
                            v11 ^= v4;
                            v9 = v3;
                            v9 -= v11;
                            v9 |= v11;
                            v9 &= v8;
                            v9 = ~v9;
                            v11 = 0x8080808080808080;
                            while ((v9 & v11) == 0) {
                                v5 += 16;
                            }
                        }
                        v7 = v_20;
                        v9 = v_28;
                        if (a3 != v5) {
                            v11 = a1;
                            result += v5;
                            a3 = v10;
                            a3 -= v5;
                            a3 -= i;
                            i2 = 0;
                            while (*(__int64 *)(result + i2) != src) {
                                ++i2;
                                return i2;
                            }
                            i2 += v5;
                            i += i2;
                            ++i;
                            ((__int64 *)a2)[2] = (__int64)(i);
                            v8 = i;
                            v8 -= v7;
                            result = (v8 < 0) ? 1 : 0;
                            a3 = (i > v11) ? 1 : 0;
                            a3 |= (__int64)result;
                            if ((a3 != 0)) {
                                return a3;
                            }
                            a1 = v8 + v9;
                            v_20 = v11;
                            v11 = (__int64)a2;
                            a2 = (struct Struct_1_t *)v_38;
                            v9 = v10;
                            v10 = v7;
                            sub_1400F27FC(a1, a2, v7, v5);
                            v7 = v10;
                            v10 = v9;
                            v9 = v_28;
                            a2 = (struct Struct_1_t *)v11;
                            v11 = v_20;
                            if (result != 0) {
                                return v11;
                            }
                            result = (struct Struct_2_t *)v_30;
                            result->field_8 = v8;
                            result->field_10 = i;
                            a1 = 1;
                            return a1;
                        }
                        return a1;
                    }
                    return a1;
                }
                v_20 = v7;
                a1 = v11;
                i2 = a3 - 16;
                v5 = 0;
                return v5;
            } while (v10 >= i);
            return v5;
        }
        return v5;
    }
    return (__int64)result;
}