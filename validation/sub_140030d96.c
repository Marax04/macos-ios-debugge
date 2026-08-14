__int64 sub_140030E06();

void __fastcall sub_140030D96(__int64 a1, int a2, __int64 a3, __int64 a4) {
    __int64 *dst;

    *dst = *dst - dst;
    if ((*dst == 0)) {
        if (a2 == 0) JUMPOUT(0x140030df9);
        a2 = 0x40000000;
        if (a1 != 0) JUMPOUT(0x140030e01);
        sub_140030E06();
    } else {
        a4 = a2;
        a4 |= 0xFFFFFFFE;
        a4 <<= 30;
        a2 = 0x80120114;
        if (a1 == 0) a2 = a4;
        sub_140030E06();
    }
}