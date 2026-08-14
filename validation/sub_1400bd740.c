__int64 sub_1400BD817();
extern __int64 off_1401249B4;
extern __int64 off_1400BD4D0;
extern __int64 off_14011B0D8;

__int64 __fastcall sub_1400BD740(__int64 *a1) {
    __int64 v_60;
    int v_68;
    char *str;
    __int64 v1;
    __int64 *src;
    __int64 v2;
    __int64 v3;

    v1 = *a1;
    src = &off_1401249B4;
    v1 = *(src + v1*4);
    v1 += (__int64)src;
    JUMPOUT(v1);
    a1 += 4;
    str = (char *)a1;
    v_60 = (__int64)str;
    v2 = &off_1400BD4D0;
    v_68 = v2;
    v3 = &off_14011B0D8;
    return sub_1400BD817();
}