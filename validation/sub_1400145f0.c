// inferred from 10 accesses on `result`
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
};

__int64 sub_1400F37D0();
extern __int64 off_14010E551;
extern __int64 off_14010E578;
extern __int64 off_14010E54F;
extern __int64 off_1401161C0;
extern __int64 off_14010E590;
extern __int64 off_14010E5B0;

__int64 __fastcall sub_1400145F0(int *a1, int a2, __int64 a3, __int64 a4) {
    int arg_30;
    int arg_70;
    int arg_80;
    int arg_88;
    int arg_90;
    struct Struct_1_t *result;
    __int64 v3;
    __int64 v6;
    __int64 v5;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 v4;
    __int64 v2;

    if (a2 == 0) {
        a1 = &off_14010E551;
        a3 = &off_14010E578;
        sub_1400F37D0(a1, 33, a3, a4);
    } else {
        if (*a1 > 48) {
            result = (struct Struct_1_t *)arg_30;
            *(__int64 *)result = (__int64)(2);
            if (a3 <= 0) {
                v3 = a3;
                v3 = -v3;
                v6 = &off_14010E54F;
                result->field_8 = v6;
                result->field_10 = 2;
                result->field_18 = 0;
                result->field_20 = v3;
                result->field_30 = 2;
                result->field_38 = a1;
                result->field_40 = a2;
                a1 = 3;
                a4 -= a2;
                if (!((a4 <= 0))) {
                    if (a4 > v3) {
                        a4 += a3;
                        result->field_48 = 0;
                        result->field_50 = a4;
                        a1 = 4;
                        a2 = (int)a1;
                        return a2;
                    }
                }
            } else {
                v5 = a2;
                result->field_8 = a1;
                v5 -= a3;
                if ((v5 <= 0)) {
                    result->field_10 = a2;
                    a3 -= a2;
                    result->field_18 = 0;
                    result->field_20 = a3;
                    if (a4 == 0) {
                        a1 = 2;
                        a2 = (int)a1;
                        return a2;
                    } else {
                        result->field_30 = 2;
                        a1 = &off_1401161C0;
                        result->field_38 = a1;
                        result->field_40 = 1;
                    }
                } else {
                    result->field_10 = a3;
                    result->field_18 = 2;
                    a2 = &off_1401161C0;
                    result->field_20 = a2;
                    result->field_28 = 1;
                    a1 += a3;
                    result->field_30 = 2;
                    result->field_38 = a1;
                    result->field_40 = v5;
                    a1 = 3;
                    a4 -= v5;
                    if (!((a4 > 0))) {
                        a2 = (int)a1;
                        return a2;
                    }
                }
                return a2;
            }
            return a2;
        }
    }
    a1 = &off_14010E590;
    a3 = &off_14010E5B0;
    sub_1400F37D0(a1, 31, a3);
    v7 = arg_90;
    result = (struct Struct_1_t *)arg_88;
    v8 = (__int64)result;
    v8 -= v7;
    if (!((v8 <= 0))) {
        if (v8 > v7) {
            v9 = arg_80;
            v3 = arg_70;
            v4 = (__int64)result;
            v4 -= v9;
            if (v4 > v9) {
                v2 = (__int64)result;
                v2 -= v9;
                v2 -= v9;
                v4 = v7 + v7;
                if (v2 >= v4) JUMPOUT(0x1400147cd);
            }
            v9 -= v7;
            if (!((v9 <= 0))) {
                result -= v9;
                if (result <= v9) JUMPOUT(0x1400147de);
            }
        }
    }
    *a1 = 0;
    return (__int64)result;
}