__int64 __fastcall sub_1400281E0(size_t *a1, size_t a2, size_t a3) {
    char *dst;
    __int64 result;

    if (*a1 != 0) {
        *dst = -2;
        result = *a1;
        a1 = (size_t *)result;
        a1 = (size_t *)((__int64)(__int64)a1 & 3);
        if (a1 == 1) JUMPOUT(0x14002dc67);
        return (__int64)a1;
    } else {
        return result;
    }
}