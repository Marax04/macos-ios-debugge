int __fastcall sub_1400A23E0(__int64 *a1, size_t a2) {
    int result;
    __int64 v2;
    int v3;

    result = 0;
    if (a2 >= 4) {
        v2 = a2;
        a2 = *a1;
        a2 = __builtin_bswap32(a2);
        v3 = 0x7375625F;
        a2 = (v3 > a2) ? 1 : 0;
        a2 -= 0;
        if (a2 == 0) JUMPOUT(0x1400a2409);
        return a2;
    } else {
        return result;
    }
}