int __fastcall sub_1400898D0(__int64 a1, int a2) {
    int result;

    result = (a2 == 5) ? 1 : 0;
    a1 &= 15;
    a2 = result;
    a2 <<= 4;
    a2 |= a1;
    result |= 4;
    a2 += 16;
    return result;
}