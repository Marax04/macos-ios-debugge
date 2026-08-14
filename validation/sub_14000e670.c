// inferred from 4 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
__int64 sub_140001870();
__int64 sub_1400276D0();
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_14000E670(__int64 *str,struct Struct_1_t *a2, __int64 a3, size_t a4) {
    __int64 *src;
    __int64 v2;
    __int64 i;
    __int64 *dst;
    __int64 result;
    __int64 v5;
    __int64 v9;
    __int64 v8;
    __int64 v6;
    __int64 v7;

    a2 = a2->field_0;
    src = a2->field_18;
    v2 = a2->field_20;
    i = a2->field_28;
    if (i >= v2) {
        dst = str;
    } else {
        result = a2 + 24;
        a3 = 0x100002600;
        a4 = *(src + i);
        while (a4 <= 58) {
            if (!((!((a3 >> a4) & 1)))) {
                ++i;
                a2->field_28 = i;
                dst = str;
                i = v2;
                str = 3;
                ++i;
                if (i >= v2) i = v2;
                v5 = src + i;
                result = off_14012D020;
                ((__int64 (*)())result)(10, src, v5, a4);
                if ((result & 1) != 0) {
                    a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)src);
                    v9 = a2 + 1;
                    if (a2 >= v2) {
                        v8 = &off_140111F70;
                        sub_1400F3600(0, v9, v2, v8);
                        v9 = 0;
                    }
                    v6 = src + v9;
                    result = off_14012D018;
                    ((__int64 (*)())result)(10, src, v6);
                    a2 = result + 1;
                    i -= v9;
                    sub_1400F5F40(str, a2, i);
                    *(dst + 8) = result;
                    *dst = 6;
                    return i;
                }
                return i;
            }
            if (a4 == 58) {
                ++i;
                a2->field_28 = i;
                return sub_140001870();
            }
        }
        dst = str;
        str = 6;
        sub_1400276D0(result);
        v7 = (__int64)a2;
        a2 = (struct Struct_1_t *)result;
        return (__int64)a2;
    }
    return result;
}