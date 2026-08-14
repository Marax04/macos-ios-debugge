// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3A70();
__int64 sub_1400F3600();
__int64 sub_140033E9D();
__int64 sub_140034180();
__int64 sub_1400F27F0();
__int64 sub_1400F7020();
__int64 sub_140033EF0();
extern __int64 off_140114A00;
extern __int64 off_14010F2D8;
extern __int64 off_14010F2C0;

__int64 __fastcall sub_140033BC0(__int64 *a1, int *a2, __int64 *a3, __int64 a4) {
    __int64 v_10;
    int v_8;
    __int64 v3;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 *src2;
    __int64 v9;
    __int64 v10;
    __int64 v5;
    __int64 v6;
    __int64 v8;

    v_8 = -2;
    if (a1[2] != 0) {
        a1 = &off_140114A00;
        sub_1400F3A70(a1);
    } else {
        v3 = (__int64)a3;
        src = (__int64 *)a2;
        ptr = (struct Struct_1_t *)a1;
        a1[2] = -1;
        a2 += 7;
        a2 = (int *)((__int64)(__int64)a2 & -8);
        a2 = (int *)((__int64)a2 - (__int64)src);
        a1 = a3;
        result = a3;
        if (a3 >= a2) {
            result = (__int64 *)v3;
            result = (__int64 *)((__int64)result - (__int64)a2);
            result = (__int64 *)((__int64)(__int64)result & 15);
            a1 = (__int64 *)v3;
            a1 = (__int64 *)((__int64)a1 - (__int64)result);
            if ((a1 < 0)) {
                v_10 = (__int64)ptr;
                a4 = &off_14010F2D8;
                sub_1400F3600(a1, v3, v3, a4);
                return sub_140033E9D();
            } else {
                result = (__int64 *)a2;
            }
        }
        src2 = ptr + 24;
        a3 = (__int64 *)v3;
        a3 = (__int64 *)((__int64)a3 - (__int64)a1);
        a2 = v3 + src;
        --a2;
        while (a3 != 0) {
            v9 = (__int64)a3;
            --a3;
            --a2;
            v9 += (__int64)a1;
            v3 -= v9;
            v_10 = (__int64)ptr;
            if ((v3 < 0)) JUMPOUT(0x140033e6b);
            v10 = ptr->field_28;
            if (v10 == 0) {
                a1 = ptr + 49;
                sub_140034180(a1, src, v9);
                a1 = 0xFFFFFFFF00000003;
                a1 = (__int64 *)((__int64)(__int64)a1 & (__int64)result);
                a2 = 0x600000002;
                a1 = (a1 == a2) ? 1 : 0;
                a2 = (result == 0) ? 1 : 0;
                a2 = (int *)((__int64)(__int64)a2 | (__int64)a1);
                if (!((a2 == 0))) {
                    src += v9;
                    ptr = (struct Struct_1_t *)v_10;
                    result = ptr->field_18;
                    v9 = ptr->field_28;
                    result -= v9;
                    if (v3 < result) {
                        a1 = ptr->field_20;
                        a1 += v9;
                        sub_1400F27F0(a1, src, v3);
                        v9 += v3;
                        ptr->field_28 = v9;
                        result = 0;
                    } else {
                        sub_1400F7020(src2, src, v3);
                        ptr = (struct Struct_1_t *)v_10;
                    }
                    ptr->field_10 = ptr->field_10 + 1;
                    return (__int64)ptr;
                }
            } else {
                result = *src2;
                result -= v10;
                if (v9 >= result) JUMPOUT(0x140033e9f);
                a1 = ptr->field_20;
                a1 += v10;
                sub_1400F27F0(a1, src, v9, 0x101010101010101);
                v10 += v9;
                ptr->field_28 = v10;
                sub_140033EF0(src2);
                if (result == 0) {
                    return v10;
                }
            }
            return v10;
        }
        a3 = 0xF5F5F5F5F5F5F5F5;
        v5 = 0x8080808080808080;
        a2 = (int *)a1;
        while (a1 > result) {
            a1 = a2 - 16;
            v6 = *(__int64 *)((__int64)src + (__int64)a2 - 16);
            v9 = *(__int64 *)((__int64)src + (__int64)a2 - 8);
            v10 = v6;
            v10 ^= (__int64)a3;
            v10 += a4;
            v10 |= v6;
            v8 = v9;
            v8 ^= (__int64)a3;
            v8 += a4;
            v8 |= v9;
            v8 &= v10;
            v8 = ~v8;
        }
        if (a2 > v3) {
            v_10 = (__int64)ptr;
            a4 = &off_14010F2C0;
            sub_1400F3600(0, a2, v3, a4);
            return sub_140033E9D();
        } else {
            while (a2 != 0) {
                v9 = (__int64)a2;
                --a2;
                return (__int64)a2;
            }
            v9 = ptr->field_28;
            if (v9 == 0) {
                v9 = 0;
            } else {
                result = ptr->field_20;
                if (*(result + v9 - 1) != 10) {
                    result = *src2;
                    result -= v9;
                    if (v3 >= result) {
                        v_10 = (__int64)ptr;
                        sub_1400F7020(src2, src, v3);
                        return v_10;
                    } else {
                        return v_10;
                    }
                    return v_10;
                } else {
                    v_10 = (__int64)ptr;
                    sub_140033EF0(src2);
                    if (result == 0) {
                        ptr = (struct Struct_1_t *)v_10;
                        v9 = ptr->field_28;
                        result = *src2;
                        result -= v9;
                        if (v3 < result) {
                            return (__int64)result;
                        } else {
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
    }
    return (__int64)result;
}