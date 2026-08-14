__int64 sub_140038250();
__int64 sub_1400386D1();
__int64 sub_1400386B7();
__int64 sub_1400386C0();

__int64 __fastcall sub_140038660(__int64 a1, int a2) {
    __int64 v3;
    __int64 v2;
    __int64 *v1;

    sub_140038250();
    if (v1 == 0) {
        a1 = 0;
        return sub_1400386D1();
    } else {
        if (a2 == 2) {
            if (*v1 == 0x2E2E) {
                a2 = 2;
                return sub_1400386B7();
            }
        }
        v3 = a2;
        do {
            if (v3 == 0) JUMPOUT(0x1400386bb);
            v2 = v3;
            --v3;
        } while (*(v1 + v2 - 1) != 46);
        if (v3 == 0) JUMPOUT(0x1400386b7);
        a2 -= v2;
        a1 = (__int64)v1;
        a1 += v2;
        return sub_1400386C0();
    }
}