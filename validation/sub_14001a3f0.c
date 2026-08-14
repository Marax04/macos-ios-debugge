__int64 sub_14001A490();

int __fastcall sub_14001A3F0(__int64 a1, __int64 a2, int a3) {
    __int64 v2;
    int v1;

    v2 = a1;
    v1 = (a2 == 0) ? 1 : 0;
    a1 = (a1 < -342) ? 1 : 0;
    a1 |= v1;
    if ((a1 == 0)) {
        a3 = 0x7FF;
        if (v2 <= 308) JUMPOUT(0x14001a424);
        v1 = 0;
        return sub_14001A490();
    } else {
        a3 = 0;
        v1 = 0;
        return sub_14001A490();
    }
}