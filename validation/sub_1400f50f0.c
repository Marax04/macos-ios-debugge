__int64 sub_14001F3F0();

void __fastcall sub_1400F50F0(__int64 *a1, int a2) {
    __int64 v2;
    __int64 v4;
    int v3;
    __int64 i;

    if (a2 != 0) {
        v2 = a1;
        v4 = a1[2];
        if (v4 != 0) {
            v3 = a2;
            i = 0;
            do {
                sub_14001F3F0(v2);
                ++i;
            } while (v4 != i);
        }
    }
    return;
}