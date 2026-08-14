__int64 sub_140014893();
__int64 sub_1400F2808();
__int64 sub_14001488B();

__int64 __fastcall sub_140014750(__int64 *a1, __int64 *a2, __int64 a3, __int64 a4) {
    int arg_70;
    int arg_78;
    int arg_80;
    int arg_88;
    int arg_90;
    __int64 v5;
    __int64 result;
    __int64 v6;
    __int64 v7;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    __int64 v8;

    v5 = arg_90;
    result = arg_88;
    v6 = result;
    v6 -= v5;
    if (!((v6 <= 0))) {
        if (v6 > v5) {
            v7 = arg_80;
            v3 = arg_70;
            v4 = result;
            v4 -= v7;
            if (v4 > v7) {
                v2 = result;
                v2 -= v7;
                v2 -= v7;
                v4 = v5 + v5;
                if (v2 >= v4) {
                    if (a4 > a3) JUMPOUT(0x1400148a0);
                    *a1 = a2;
                    return sub_140014893();
                }
            }
            v7 -= v5;
            if (!((v7 <= 0))) {
                result -= v7;
                if (result <= v7) {
                    if (a4 > a3) JUMPOUT(0x1400148b4);
                    v2 = arg_78;
                    v3 = a4;
                    do {
                        if (v3 == 0) JUMPOUT(0x140014836);
                        result = v3;
                        --v3;
                    } while (*(a2 + result - 1) == 57);
                    v9 = a3;
                    *(a2 + v3) = *(a2 + v3) + 1;
                    v2 = a4;
                    a3 = a4;
                    a3 -= result;
                    if ((a3 < 0)) JUMPOUT(0x1400148dc);
                    v8 = (__int64)a1;
                    v4 = (__int64)a2;
                    result += (__int64)a2;
                    sub_1400F2808(result, 48, a3);
                    a4 = v2;
                    a3 = v9;
                    a1 = (__int64 *)v8;
                    return sub_14001488B();
                }
            }
        }
    }
    *a1 = 0;
    return result;
}