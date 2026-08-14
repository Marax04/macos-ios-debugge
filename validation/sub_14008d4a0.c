// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_1401244B8;
extern __int64 off_140118E88;
extern __int64 off_140118F50;
extern __int64 off_140118F6B;
extern __int64 off_14008FE80;
extern __int64 off_140118EB8;
extern __int64 off_14011D9F8;
extern __int64 off_140118ED0;
extern __int64 off_140118EF0;

__int64 __fastcall sub_14008D4A0(__int64 *a1,struct Struct_1_t *a2, int a3) {
    __int64 rsp;
    __int64 v_28;
    int v_38;
    __int64 v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    __int64 v_80;
    char *str;
    char *str2;
    __int64 *result;
    __int64 v3;
    __int64 *src;
    __int64 v2;

    result = *a1;
    a1 = a2->field_0;
    a2 = a2->field_8;
    a3 = *result;
    v3 = a3 - 2;
    src = 1;
    if (a3 >= 2) src = v3;
    v3 = (__int64)src;
    src = &off_1401244B8;
    v3 = *(src + v3*4);
    v3 += (__int64)src;
    JUMPOUT(v3);
    result = ((__int64 *)a2)[3];
    a2 = &off_140118E88;
    a3 = 21;
    JUMPOUT(result);
    result = ((__int64 *)a2)[3];
    a2 = &off_140118F50;
    a3 = 27;
    JUMPOUT(result);
    result = ((__int64 *)a2)[3];
    a2 = &off_140118F6B;
    a3 = 22;
    JUMPOUT(result);
    if ((a3 & 1) == 0) {
        result += 2;
        v_28 = (__int64)result;
        result = rsp + 40;
        v_68 = (__int64)result;
        result = &off_14008FE80;
        v_70 = (__int64)result;
        result = &off_140118EB8;
        str = (char *)result;
        v_38 = 1;
        result = &off_14011D9F8;
        v_50 = (__int64)result;
        v_58 = 1;
        result = rsp + 104;
        v_40 = (__int64)result;
        v_48 = 1;
        return sub_140011760(a1, a2, str);
    } else {
        v2 = result + 1;
        result += 2;
        str2 = (char *)result;
        v_28 = v2;
        result = rsp + 40;
        v_68 = (__int64)result;
        result = &off_14008FE80;
        v_70 = (__int64)result;
        v_78 = (__int64)str2;
        v_80 = (__int64)result;
        result = &off_140118ED0;
        str = (char *)result;
        v_38 = 2;
        result = &off_140118EF0;
        v_50 = (__int64)result;
        v_58 = 2;
        result = rsp + 104;
        v_40 = (__int64)result;
        v_48 = 2;
        sub_140011760(a1, a2, str, v3);
        return (__int64)result;
    }
}