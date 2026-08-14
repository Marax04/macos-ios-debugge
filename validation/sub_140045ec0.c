extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140045EC0(int *a1, __int64 a2) {
    int v_20;
    __int64 *v4;
    __int64 result;
    __int64 v8;
    __int64 v6;
    __int64 v7;
    __int64 v9;
    __int64 v3;
    __int64 *src;
    __int64 v5;

    v4 = (__int64 *)a1;
    result = *(a1 + 8);
    v_20 = result;
    v8 = a1[2];
    if (v8 != 0) {
        v6 = 1;
        v7 = 0x8000000000000003;
        v9 = off_140108030;
        v3 = off_140108038;
        src = (__int64 *)v_20;
        do {
            a1 = *src;
            result = a1 - 8;
            if (a1 < 8) result = v6;
            src += 176;
            --v8;
        } while (!((v8 == 0)));
    }
    if (*v4 != 0) {
        ((__int64 (*)())off_140108030)();
        a1 = (int *)result;
        a2 = 0;
        v5 = v_20;
        JUMPOUT(off_140108038);
    }
    return result;
}