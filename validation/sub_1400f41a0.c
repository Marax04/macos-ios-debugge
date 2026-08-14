__int64 sub_1400F6DC0();
extern __int64 off_14012D000;
extern __int64 off_14012D008;
extern __int64 off_140110030;
extern __int64 off_140110068;

__int64 __fastcall sub_1400F41A0(__int64 a1, __int64 a2) {
    int v_20;
    char *str;
    char *str2;
    char *str3;
    __int64 result;
    __int64 v2;
    __int64 v3;

    result = &off_14012D000;
    str = (char *)result;
    result = off_14012D008;
    if (result != 0) {
        str2 = str;
        str3 = str2;
        v2 = &off_140110030;
        v_20 = v2;
        a1 = &off_14012D008;
        v3 = &off_140110068;
        return sub_1400F6DC0(a1, 0, str3, v3);
    } else {
        return result;
    }
}