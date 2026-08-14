__int64 sub_140067F3A();

__int64 __fastcall sub_140067D00(__int64 *a1, __int64 *a2, size_t a3) {
    __int64 result;
    __int64 v3;
    __int64 v2;

    if (a3 == 1) {
        result = *a2;
        if (result != 45) {
            if (result != 43) {
                if (result == 45) JUMPOUT(0x140067d64);
                if (result != 43) JUMPOUT(0x140067df7);
                ++a2;
                v3 = a3 - 1;
                if (a3 >= 17) JUMPOUT(0x140067e7a);
                v2 = v3;
                if (v3 != 0) JUMPOUT(0x140067e01);
                return sub_140067F3A();
            }
        }
        *(a1 + 1) = 1;
    } else {
        if (a3 != 0) {
            result = *a2;
            return result;
        } else {
            *(a1 + 1) = 0;
        }
    }
    result = 1;
    *a1 = result;
    return result;
}