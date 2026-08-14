__int64 sub_1400F27D8();
extern __int64 off_14012D280;

__int64 __fastcall sub_1400F2088() {
    __int64 *result;
    __int64 v2;

    sub_1400F27D8();
    if (result != 0) {
        result = __readgsqword(48);
        v2 = *(result + 8);
        result = 0;
        /* cmpxchg %v2, off_14012D280 */;
        while ((0 /* unresolved: flags != */)) {
            if (v2 == result) JUMPOUT(0x1400f20bd);
        }
    }
    result = 0;
    return (__int64)result;
}