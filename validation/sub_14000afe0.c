extern __int64 off_14010A7E8;

__int64 __fastcall sub_14000AFE0(__int64 *a1, __int64 a2) {
    __int64 *v2;
    __int64 v3;
    __int64 result;
    __int64 *v4;

    v2 = *a1;
    ((__int64 (*)())(*(v2 + 8)))();
    v3 = (__int64)v2;
    JUMPOUT(*(v4 + 48));
    result = v3 + 16;
    a2 = &off_14010A7E8;
    return result;
}