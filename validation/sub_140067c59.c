__int64 sub_14001B090();

__int64 __fastcall sub_140067C59(int *a1, __int64 *a2, size_t a3, __int64 a4) {
    int v_30;
    __int64 *v5;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 *result;
    __int64 v8;
    __int64 v9;
    __int64 v7;
    __int64 v6;

    a1[7] = a1[7] + a1;
    /* out %(__int64)result, %(__int64)a2 */;
    a1 = 0;
    if (!((a1[7] < 0))) {
        a3 = v8;
        a3 -= v9;
        v5 = (__int64 *)v7;
        v5 += v9;
        if (a3 > 15) {
            v3 = (__int64)a2;
            v4 = v6;
            sub_14001B090(v2, v5, a3, a3);
            v2 = (__int64)a2;
            a2 = (__int64 *)v3;
        } else {
            a4 = 0;
            if (a3 == 0) {
                result = 0;
            } else {
                while (*(v5 + a4) != v2) {
                    ++a4;
                    result = 0;
                    if (((__int64)result & 1) != 0) JUMPOUT(0x140067c3a);
                    a2[2] = v8;
                    a1 = 0;
                    result = (__int64 *)v_30;
                    *result = a1;
                    return (__int64)result;
                }
                result = 1;
            }
        }
        return (__int64)result;
    }
    return (__int64)result;
}