extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400448D0(__int64 *a1, __int64 a2) {
    __int64 *v4;
    __int64 v3;
    __int64 v10;
    __int64 *src;
    __int64 v8;
    __int64 v9;
    __int64 result;
    __int64 v2;
    __int64 v7;
    __int64 v5;
    __int64 v6;

    v4 = a1;
    v3 = *(a1 + 8);
    v10 = a1[2];
    if (v10 != 0) {
        src = v3 + 40;
        v8 = off_140108030;
        v9 = off_140108038;
        do {
            result = *(src - 8);
            result <<= 1;
            v2 = *src;
            ((__int64 (*)())v8)();
            ((__int64 (*)())v9)(result, 0, v2);
            if (*(src - 40) == 2) {
                src += 72;
                --v10;
                if (*v4 != 0) {
                    ((__int64 (*)())off_140108030)();
                    v7 = result;
                    a2 = 0;
                    v5 = v3;
                    JUMPOUT(off_140108038);
                }
                return v5;
            }
            if (*(src - 32) == 0) {
                return v5;
            }
            v6 = *(src - 24);
            ((__int64 (*)())v8)();
            ((__int64 (*)())v9)(result, 0, v6);
            return v6;
        } while (!((v10 == 0)));
    }
    return result;
}