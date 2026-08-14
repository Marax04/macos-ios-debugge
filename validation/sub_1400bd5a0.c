// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_140119DF0;
extern __int64 off_14008D400;
extern __int64 off_140119E18;

__int64 __fastcall sub_1400BD5A0(__int64 *a1,struct Struct_1_t *a2) {
    int v_30;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    char *str;
    char *str2;
    char *str3;
    __int64 *v1;
    __int64 v5;
    int v4;
    __int64 v2;
    __int64 v3;

    v1 = *a1;
    v5 = a2->field_0;
    a2 = a2->field_8;
    if (*v1 == 13) {
        v1 = ((__int64 *)a2)[3];
        a2 = &off_140119DF0;
        v4 = 24;
        JUMPOUT(v1);
    }
    str = (char *)v1;
    str2 = str;
    v2 = &off_14008D400;
    v_30 = v2;
    v3 = &off_140119E18;
    str3 = (char *)v3;
    v_40 = 1;
    v_58 = 0;
    v_48 = (__int64)str2;
    v_50 = 1;
    return sub_140011760(v5, a2, str3);
}