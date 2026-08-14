extern __int64 off_14012D270;

__int64 __fastcall sub_1400F6820() {
    __int64 *result;
    __int64 *v2;

    result = off_14012D270;
    v2 = __readgsqword(88);
    result = v2[(__int64)result];
    result = (*(result + 128) == 0) ? 1 : 0;
    return (__int64)result;
}