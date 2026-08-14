// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a3`
struct Struct_2_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
__int64 sub_1400276D0();
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_14000E480(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3, __int64 a4) {
    __int64 rsp;
    int arg_1;
    int v_28;
    __int64 *src;
    __int64 v2;
    __int64 *i;
    __int64 *dst;
    __int64 result;
    __int64 i2;
    __int64 v6;
    __int64 v9;
    __int64 v8;
    __int64 v7;

    a3 = a2->field_0;
    src = a3->field_18;
    v2 = a3->field_20;
    i = a3->field_28;
    if (i >= v2) {
        dst = a1;
    } else {
        result = a3 + 24;
        i2 = *(__int64 *)((__int64)src + (__int64)i);
        while (i2 <= 32) {
            if (!((!((a4 >> i2) & 1)))) {
                ++i;
                a3->field_28 = i;
                dst = a1;
                i = (__int64 *)v2;
                v_28 = 3;
                ++i;
                if (i >= v2) i = v2;
                v6 = (__int64)src + (__int64)i;
                result = off_14012D020;
                ((__int64 (*)())result)(10, src, v6);
                if ((result & 1) != 0) {
                    a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)src);
                    v9 = a2 + 1;
                    if (a2 >= v2) {
                        v8 = &off_140111F70;
                        sub_1400F3600(0, v9, v2, v8);
                        v9 = 0;
                    }
                    v7 = src + v9;
                    result = off_14012D018;
                    ((__int64 (*)())result)(10, src, v7);
                    a2 = result + 1;
                    i -= v9;
                    a1 = rsp + 40;
                    sub_1400F5F40(a1, a2, i);
                    a1 = dst;
                    *(dst + 8) = result;
                    result = 1;
                    *a1 = result;
                    return result;
                }
                return result;
            }
        }
        if (i2 != 125) {
            if (a2->field_8 == 0) {
                if (i2 != 44) JUMPOUT(0x14000e64a);
                a2 = i + 1;
                a3->field_28 = a2;
                if (a2 < v2) {
                    i += 2;
                    a2 = 1;
                    a2 -= v2;
                    do {
                        i2 = *(__int64 *)((__int64)src + (__int64)i - 1);
                        if (i2 > 34) JUMPOUT(0x14000e633);
                        if (!((!((a4 >> i2) & 1)))) {
                            a3->field_28 = i;
                            i2 = (__int64)a2 + (__int64)i;
                            ++i2;
                            ++i;
                            v_28 = 5;
                            i = a1;
                            sub_1400276D0(result, a2, a3, 0x100002600);
                            a1 = rsp + 40;
                            sub_1400F5F40(a1, result, a2);
                            a1 = i;
                            *(i + 8) = result;
                            return (__int64)a1;
                        }
                        if (i2 != 34) JUMPOUT(0x14000e633);
                        arg_1 = 1;
                        result = 0;
                        return result;
                    } while (i2 != 2);
                }
                return result;
            } else {
                a2->field_8 = 0;
                if (i2 == 34) {
                    return result;
                } else {
                    v_28 = 17;
                    return v_28;
                }
                return v_28;
            }
            return v_28;
        } else {
            arg_1 = 0;
            result = 0;
        }
        return result;
    }
    return result;
}