__int64 sub_1400F7E60();
__int64 sub_1400F2C50();

__int64 __fastcall sub_140063FC0(size_t *a1, int a2) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    __int64 result;
    __int64 v5;
    __int64 v6;
    __int64 v4;
    __int64 v3;
    __int64 *dst;
    __int64 v7;
    __int64 v10;
    __int64 v8;
    __int64 v9;

    if (a2 > a1[5]) {
        result = a1 + 24;
        v5 = arg_8;
        v6 = a1[2];
        v4 = (__int64)a1;
        v3 = a2;
        sub_1400F7E60(result, v9, v5, v6);
        a2 = v3;
        a1 = (size_t *)v4;
    }
    result = *a1;
    v3 = a1[2];
    v5 = result;
    v5 -= v3;
    if (a2 > v5) {
        v6 = a1[5];
        v6 += a1[6];
        v4 = 0x63E7063E7063E7;
        if (v6 < v4) v4 = v6;
        v5 = v4;
        v5 -= v3;
        dst = (__int64 *)a1;
        if (v5 <= a2) {
            v5 = arg_8;
        } else {
            v5 = arg_8;
            if (v6 >= v3) {
                v7 = a2;
                v_28 = 328;
                v_20 = 8;
                a1 = rsp + 48;
                v10 = result;
                v8 = v5;
                sub_1400F2C50(a1, result, v5, v4);
                if (v_30 == 1) {
                    result = v10;
                    v3 += a2;
                    v_28 = 328;
                    v_20 = 8;
                    a1 = rsp + 48;
                    sub_1400F2C50(a1, result, v8, v3);
                    if (v_30 != 0) JUMPOUT(0x1400640d4);
                    result = v_38;
                } else {
                    result = v_38;
                    v3 = v4;
                }
                *(dst + 8) = result;
                *dst = v3;
                return v3;
            }
        }
        return v3;
    }
    return result;
}