__int64 sub_1400F27D8();
extern __int64 off_14012D280;

void __fastcall sub_1400F2224(__int64 a1, __int64 a2) {
    int v2;
    int v1;

    v2 = a1;
    sub_1400F27D8();
    a2 = 0;
    if (v1 != 0) {
        if (v2 == 0) {
            a2 = _InterlockedExchange64(&off_14012D280, a2);
        }
    }
    return;
}