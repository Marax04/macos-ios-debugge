__int64 sub_1400F2898();
__int64 sub_1400F289E();
extern __int64 off_14012D290;

__int64 __fastcall sub_1400F2274(__int64 a1) {
    __int64 v2;
    __int64 v4;
    __int64 v3;
    __int64 result;

    v2 = a1;
    if (off_14012D290 != -1) {
        v4 = &off_14012D290;
        sub_1400F2898(v4, v2);
    } else {
        sub_1400F289E();
    }
    v3 = 0;
    if (result == 0) v3 = v2;
    result = v3;
    return result;
}