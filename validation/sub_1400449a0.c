__int64 sub_1400448D0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400449A0(__int64 *a1, __int64 a2) {
    __int64 *v4;
    __int64 v3;
    __int64 v6;
    __int64 v2;
    __int64 v5;
    __int64 v1;

    v4 = a1;
    v3 = *(a1 + 8);
    v6 = a1[2];
    if (v6 != 0) {
        v2 = v3;
        do {
            sub_1400448D0(v2);
            v2 += 56;
            --v6;
        } while ((v6 != 0));
    }
    if (*v4 != 0) {
        off_140108030();
        v5 = v1;
        a2 = 0;
        JUMPOUT(off_140108038);
    }
    return a2;
}