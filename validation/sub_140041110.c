__int64 sub_140040D50();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140041110(__int64 a1, __int64 a2) {
    int v_8;
    char *dst;
    __int64 *dst2;
    __int64 v2;
    __int64 v1;

    *dst = -2;
    v_8 = a1;
    a1 += 16;
    sub_140040D50(a1);
    dst2 = (__int64 *)v_8;
    if (dst2 != -1) {
        *(dst2 + 8) = *(dst2 + 8) - 1;
        if (!((*(dst2 + 8) != 0))) {
            off_140108030();
            v2 = v1;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
    }
    return a2;
}