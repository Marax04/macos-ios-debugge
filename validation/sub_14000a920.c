extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14000A920(__int64 *a1, __int64 a2) {
    __int64 *v3;
    __int64 v2;
    __int64 v9;
    __int64 *src;
    __int64 v7;
    __int64 v8;
    __int64 v6;
    __int64 v4;
    __int64 v5;
    __int64 v1;

    v3 = a1;
    v2 = *(a1 + 8);
    v9 = a1[2];
    if (v9 != 0) {
        src = v2 + 40;
        v7 = off_140108030;
        v8 = off_140108038;
        do {
            if (*(src - 8) == 0) {
                src += 64;
                --v9;
                if (*v3 != 0) {
                    ((__int64 (*)())off_140108030)();
                    v6 = v1;
                    a2 = 0;
                    v4 = v2;
                    JUMPOUT(off_140108038);
                }
                return v4;
            }
            v5 = *src;
            ((__int64 (*)())v7)();
            ((__int64 (*)())v8)(v1, 0, v5);
            return v5;
        } while (!((v9 == 0)));
    }
    return v5;
}