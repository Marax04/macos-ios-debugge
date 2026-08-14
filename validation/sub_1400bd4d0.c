// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_1400F1D20;
extern __int64 off_14011DB38;
extern __int64 off_14011DAF8;
extern __int64 off_14011DAE8;

__int64 __fastcall sub_1400BD4D0(__int64 *a1,struct Struct_1_t *a2) {
    int v_30;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    char *str;
    char *str2;
    char *str3;
    __int64 *result;
    __int64 v7;
    int v4;
    __int64 v5;
    __int64 v6;
    __int64 v2;
    __int64 v3;

    result = *a1;
    v7 = a2->field_0;
    a2 = a2->field_8;
    v4 = *result;
    result += 4;
    if (v4 != 0) {
        if (v4 != 1) {
            str = (char *)result;
            str2 = str;
            v5 = &off_1400F1D20;
            v_30 = v5;
            v6 = &off_14011DB38;
            str3 = (char *)v6;
            v_40 = 2;
        } else {
            result = ((__int64 *)a2)[3];
            a2 = &off_14011DAF8;
            v4 = 33;
            JUMPOUT(result);
            str = (char *)result;
            str2 = str;
            v2 = &off_1400F1D20;
            v_30 = v2;
            v3 = &off_14011DAE8;
            str3 = (char *)v3;
            v_40 = 1;
        }
        v_58 = 0;
        v_48 = (__int64)str2;
        v_50 = 1;
        return sub_140011760(v7, a2, str3);
    }
    return (__int64)result;
}