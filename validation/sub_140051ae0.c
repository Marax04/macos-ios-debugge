// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_1400181C0;
extern __int64 off_140017D60;
extern __int64 off_1401154C0;
extern __int64 off_1401154F0;

__int64 __fastcall sub_140051AE0(__int64 *a1,struct Struct_1_t *a2) {
    int v_30;
    __int64 v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    char *str;
    char *str2;
    __int64 v1;
    __int64 v5;
    __int64 v4;
    __int64 v6;
    __int64 v2;
    __int64 v3;
    __int64 v7;

    v1 = *a1;
    v5 = v1 + 2;
    str2 = (char *)v1;
    v1 += 3;
    v4 = &off_1400181C0;
    v_60 = v4;
    v_68 = v5;
    v6 = &off_140017D60;
    v_70 = v6;
    v_78 = v1;
    v_80 = v6;
    v2 = &off_1401154C0;
    str = (char *)v2;
    v_30 = 3;
    v3 = &off_1401154F0;
    v_48 = v3;
    v_50 = 3;
    v_38 = (__int64)str2;
    v_40 = 3;
    v7 = a2->field_0;
    a2 = a2->field_8;
    return sub_140011760(v7, a2, str);
}