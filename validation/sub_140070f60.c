extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140070F60(__int64 *a1, __int64 a2) {
    __int64 v_20;
    int v_28;
    __int64 v_30;
    __int64 *src;
    __int64 *result;
    __int64 i;
    __int64 v8;
    __int64 v10;
    __int64 *v7;
    __int64 v2;
    __int64 v9;
    __int64 v6;

    src = *(a1 + 8);
    v_28 = (int)a1;
    result = a1[2];
    v_30 = (__int64)result;
    if (result != 0) {
        i = 0;
        v8 = off_140108030;
        v10 = off_140108038;
        do {
            v7 = (__int64 *)i;
            v7 = (__int64 *)((__int64)(__int64)v7 << 5);
            result = *(__int64 *)((__int64)src + (__int64)v7 + 8);
            v_20 = (__int64)result;
            v2 = (__int64)src;
            v9 = *(__int64 *)((__int64)src + (__int64)v7 + 16);
            src = (__int64 *)v2;
            v7 += v2;
            if (*v7 == 0) {
                ++i;
                result = (__int64 *)v_28;
                if (*result != 0) {
                    ((__int64 (*)())off_140108030)();
                    a1 = result;
                    a2 = 0;
                    v6 = (__int64)src;
                    JUMPOUT(off_140108038);
                }
                return v6;
            }
            ((__int64 (*)())v8)();
            ((__int64 (*)())v10)(result, 0, v_20);
            return v6;
        } while (i != v_30);
    }
    return (__int64)result;
}