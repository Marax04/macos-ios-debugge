__int64 sub_140046190();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140046040(int *a1, __int64 a2) {
    __int64 v2;
    __int64 *src;
    __int64 v6;
    __int64 v7;
    __int64 v4;
    __int64 v5;
    __int64 result;

    if (a2 != 0) {
        v2 = a2;
        src = (__int64 *)a1;
        v6 = 1;
        v7 = 0x8000000000000003;
        v4 = off_140108030;
        v5 = off_140108038;
        do {
            a1 = src + 176;
            sub_140046190(a1);
            a1 = *src;
            result = a1 - 8;
            if (a1 < 8) result = v6;
            src += 328;
            --v2;
        } while (!((v2 == 0)));
    }
    return result;
}