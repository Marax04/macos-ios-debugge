__int64 sub_1400F6C80();
extern __int64 off_14012D240;

int __fastcall sub_1400281F0() {
    int v3;
    int result;
    __int64 v2;

    v3 = 0xFFFFFFFF;
    /* xadd %v3, off_14012D240 */;
    --v3;
    result = v3;
    result &= 0xBFFFFFFF;
    result = -result;
    if ((0 /* overflow check on (-result) */)) {
        v2 = &off_14012D240;
        return sub_1400F6C80();
    } else {
        return result;
    }
}