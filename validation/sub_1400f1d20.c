// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_1400182E0;
extern __int64 off_1401172F0;

__int64 __fastcall sub_1400F1D20(__int64 *a1,struct Struct_1_t *a2) {
    int v_30;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    char *str;
    char *str2;
    __int64 v1;
    __int64 v4;
    __int64 v2;
    __int64 v3;

    v1 = *a1;
    v4 = a2->field_0;
    a2 = a2->field_8;
    str = (char *)v1;
    v2 = &off_1400182E0;
    v_30 = v2;
    v3 = &off_1401172F0;
    str2 = (char *)v3;
    v_40 = 1;
    v_58 = 0;
    v_48 = (__int64)str;
    v_50 = 1;
    return sub_140011760(v4, a2, str2);
}