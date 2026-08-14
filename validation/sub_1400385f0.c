__int64 sub_140038250();

__int64 __fastcall sub_1400385F0(__int64 a1, int a2) {
    __int64 v2;
    __int64 *result;

    sub_140038250();
    if (result != 0) {
        if (a2 == 2) {
            if (*result != 0x2E2E) {
                v2 = a2;
                while (v2 != 0) {
                    a1 = v2;
                    --v2;
                    if (v2 == 0) {
                        result = 0;
                        return (__int64)result;
                    } else {
                        result += a1;
                        a2 -= a1;
                        return a2;
                    }
                }
                result = 0;
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}