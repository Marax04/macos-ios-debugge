__int64 __fastcall sub_140024BB5(__int64 *a1, size_t a2, __int64 a3, __int64 a4) {
    __int64 result;

    result = a2;
    a2 -= (__int64)a1;
    if (a2 >= 32) JUMPOUT(0x140011be0);
    if (result == a1) {
        result = 0;
        return result;
    } else {
        a3 = 0;
        result = 0;
        do {
            a4 = 0;
            a4 = (*(a1 + a3) >= 192) ? 1 : 0;
            result += a4;
            ++a3;
        } while (a2 != a3);
        return result;
    }
}