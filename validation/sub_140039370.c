__int64 sub_140039260();
__int64 sub_140039423();
extern __int64 off_140108058;
extern __int64 off_140108060;

__int64 __fastcall sub_140039370(__int64 *a1) {
    int v_10;
    int v_f;
    char *str;
    __int64 *src;
    __int64 v4;
    __int64 v2;
    __int64 v6;
    __int64 v5;
    int v1;

    src = a1;
    v4 = str - 16;
    v2 = off_140108058;
    v6 = off_140108060;
    do {
        v5 = *src;
        sub_140039260(v4, src);
        if (v_10 == 1) JUMPOUT(0x14003941f);
    } while (v_f != 0);
    v1 = 0;
    return sub_140039423();
}