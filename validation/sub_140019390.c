// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[776];
    int field_308; // offset 776
    __int64 field_30C; // offset 780
};

__int64 sub_140019551();
__int64 sub_1400F3869();
extern __int64 off_14010B570;
extern __int64 off_14010B558;

__int64 __fastcall sub_140019390(int *a1, int *a2, __int64 a3) {
    struct Struct_1_t *result;
    __int64 v7;
    __int64 v5;
    __int64 i;
    __int64 v3;
    __int64 i2;
    __int64 v2;
    __int64 v9;
    __int64 v10;
    __int64 v11;
    __int64 v8;

    result = (struct Struct_1_t *)a1;
    a2 = (int *)((__int64)(__int64)a2 & 63);
    v7 = *a1;
    v5 = v7 - 1;
    i = 0;
    a3 = 0;
    while (v7 != i) {
        if (i != 768) {
            a1 = a3 + a3*4;
            a3 = *(__int64 *)(result + i + 8);
            a3 += (__int64)(__int64)a1*2;
            v3 = a3;
            a1 = a2;
            v3 >>= (__int64)a1;
            if (v3 == 0) {
                if (v5 != i) {
                    a1 = a3 + a3*4;
                    a3 = *(__int64 *)(result + i + 9);
                    a3 += (__int64)(__int64)a1*2;
                    i += 2;
                    v3 = a3;
                    a1 = a2;
                    v3 >>= (__int64)a1;
                    a1 = result->field_308;
                    a1 -= i;
                    ++a1;
                    result->field_308 = a1;
                    if (a1 >= 0xFFFFF801) {
                        v3 = -1;
                        a1 = a2;
                        v3 <<= (__int64)a1;
                        v3 = ~v3;
                        v5 = v7;
                        v5 -= i;
                        if ((v5 <= 0)) {
                            if (a3 == 0) {
                                *(__int64 *)result = (__int64)(0);
                            } else {
                                return sub_140019551();
                            }
                        } else {
                            i2 = 8;
                            while (i < 768) {
                                v2 = a3;
                                a1 = a2;
                                v2 >>= (__int64)a1;
                                a3 &= v3;
                                a1 = a3 + a3*4;
                                a3 = *(__int64 *)(result + i + 8);
                                ++i;
                                a3 += (__int64)(__int64)a1*2;
                                *(__int64 *)(result + i2) = (__int64)(v2);
                                ++i2;
                                if (a3 != 0) JUMPOUT(0x140019551);
                                *(__int64 *)result = (__int64)(v5);
                                if (v5 > 768) JUMPOUT(0x14001953a);
                                --v5;
                                while (*(__int64 *)(result + v5 + 8) == 0) {
                                    *(__int64 *)result = (__int64)(v5);
                                    v5 -= 1;
                                }
                                return v5;
                            }
                            v9 = &off_14010B570;
                            sub_1400F3869(i, 768, v9);
                            return v9;
                        }
                    } else {
                        *(__int64 *)result = (__int64)(0);
                        result->field_308 = 0;
                        result->field_30C = 0;
                    }
                    return v9;
                }
                if (a3 != 0) {
                    v10 = a3;
                    a1 = a2;
                    v10 >>= (__int64)a1;
                    i = v7;
                    if (v10 == 0) {
                        do {
                            a3 += a3;
                            a3 += a3*4;
                            ++i;
                            v11 = a3;
                            a1 = a2;
                            v11 >>= (__int64)a1;
                        } while (v11 == 0);
                    }
                    return v11;
                }
                return v11;
            }
            ++i;
            return i;
        }
        v8 = &off_14010B558;
        sub_1400F3869(768, 768, v8, 0);
        return v8;
    }
    return (__int64)result;
}