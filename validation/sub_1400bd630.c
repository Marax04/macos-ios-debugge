// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_14008D400;
extern __int64 off_14011D460;
extern __int64 off_1400E9A70;
extern __int64 off_14011D4A8;
extern __int64 off_14011D4C8;

__int64 __fastcall sub_1400BD630(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_38;
    __int64 v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    char *str;
    char *str2;
    __int64 *result;
    __int64 v2;

    result = *a1;
    a1 = a2->field_0;
    a2 = a2->field_8;
    if (*result != 1) {
        result += 2;
        str = (char *)result;
        result = rsp + 40;
        v_68 = (__int64)result;
        result = &off_14008D400;
        v_70 = (__int64)result;
        result = &off_14011D460;
        str2 = (char *)result;
        v_38 = 1;
        v_50 = 0;
        result = rsp + 104;
        v_40 = (__int64)result;
        v_48 = 1;
        return sub_140011760(a1, a2, str2);
    } else {
        v2 = result + 4;
        v_60 = v2;
        result += 8;
        str = (char *)result;
        result = rsp + 96;
        v_68 = (__int64)result;
        result = &off_1400E9A70;
        v_70 = (__int64)result;
        v_78 = (__int64)str;
        v_80 = (__int64)result;
        result = &off_14011D4A8;
        str2 = (char *)result;
        v_38 = 2;
        result = &off_14011D4C8;
        v_50 = (__int64)result;
        v_58 = 2;
        result = rsp + 104;
        v_40 = (__int64)result;
        v_48 = 2;
        sub_140011760(a1, a2, str2);
        return (__int64)result;
    }
}