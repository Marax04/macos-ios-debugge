extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400355C0(__int64 *a1, __int64 a2) {
    __int64 *v3;
    __int64 v2;
    __int64 v8;
    __int64 v9;
    __int64 v6;
    __int64 v7;
    __int64 v5;
    __int64 v4;
    __int64 v1;

    v3 = a1;
    v2 = *(a1 + 8);
    v8 = a1[2];
    if (v8 != 0) {
        v9 = v2 + 8;
        v6 = off_140108030;
        v7 = off_140108038;
        do {
            v9 += 32;
            --v8;
        } while (!((v8 == 0)));
    }
    if (*v3 != 0) {
        ((__int64 (*)())off_140108030)();
        v5 = v1;
        a2 = 0;
        v4 = v2;
        JUMPOUT(off_140108038);
    }
    return v4;
}