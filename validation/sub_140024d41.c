extern __int64 off_14011DB98;
extern __int64 off_14011DC68;

__int64 __fastcall sub_140024D41(size_t a1) {
    __int64 *result;
    __int64 v3;
    __int64 v2;

    a1 += 159;
    if (a1 > 25) {
        result = 0;
        return (__int64)result;
    } else {
        result = (__int64 *)a1;
        result = (__int64 *)((__int64)(__int64)result << 3);
        a1 = &off_14011DB98;
        v3 = *(result + a1);
        v2 = &off_14011DC68;
        result = *(result + v2);
        return (__int64)result;
    }
}