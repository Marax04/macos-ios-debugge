// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_14008D770;
extern __int64 off_14008D420;
extern __int64 off_140118D00;
extern __int64 off_140118D80;
extern __int64 off_140118D38;

__int64 __fastcall sub_14008D640(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_28;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    __int64 v_50;
    int v_60;
    __int64 v_68;
    int v_70;
    int v_78;
    char *str;
    char *str2;
    __int64 *src;
    __int64 v4;
    __int64 v2;
    __int64 v3;

    src = *a1;
    a1 = a2->field_0;
    a2 = a2->field_8;
    v4 = *src;
    if (v4 == 0) {
        v2 = src + 4;
        v_28 = v2;
        src += 40;
        str = (char *)src;
        src = rsp + 40;
        v_38 = (__int64)src;
        src = &off_14008D770;
        v_40 = (__int64)src;
        src = rsp + 48;
        v_48 = (__int64)src;
        src = &off_14008D420;
        v_50 = (__int64)src;
        src = &off_140118D00;
    } else {
        if (v4 != 1) {
            v3 = src + 8;
            v_28 = v3;
            src += 16;
            str = (char *)src;
            src = rsp + 40;
            v_38 = (__int64)src;
            src = &off_14008D420;
            v_40 = (__int64)src;
            v_48 = (__int64)str;
            v_50 = (__int64)src;
            src = &off_140118D80;
        } else {
            v4 = src + 4;
            v_28 = v4;
            src += 40;
            str = (char *)src;
            src = rsp + 40;
            v_38 = (__int64)src;
            src = &off_14008D770;
            v_40 = (__int64)src;
            src = rsp + 48;
            v_48 = (__int64)src;
            src = &off_14008D420;
            v_50 = (__int64)src;
            src = &off_140118D38;
        }
    }
    str2 = (char *)src;
    v_60 = 2;
    v_78 = 0;
    src = rsp + 56;
    v_68 = (__int64)src;
    v_70 = 2;
    return sub_140011760(a1, a2, str2);
}