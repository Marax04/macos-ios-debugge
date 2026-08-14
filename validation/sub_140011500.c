// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

__int64 sub_140011760();
__int64 sub_140010C30();
extern __int64 off_140010C50;
extern __int64 off_1401175D8;
extern __int64 off_14010AEE8;

__int64 __fastcall sub_140011500(__int64 *a1, __int64 *a2) {
    __int64 v_28;
    __int64 v_38;
    int v_48;
    int v_58;
    __int64 v_60;
    int v_68;
    int v_70;
    int v_80;
    char *str;
    char *str2;
    char *str3;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 *result;
    __int64 v7;
    __int64 v4;
    __int64 v2;
    __int64 v3;
    __int64 v5;
    __int64 *v6;

    ptr = (struct Struct_1_t *)a2;
    src = *a1;
    result = *src;
    a1 = src;
    ((__int64 (*)())(*(result + 8)))();
    str = (char *)result;
    v_38 = (__int64)a2;
    str2 = str;
    v7 = &off_140010C50;
    v_48 = v7;
    result = &off_1401175D8;
    str3 = (char *)result;
    v_58 = 1;
    v_70 = 0;
    v_60 = (__int64)str2;
    v_68 = 1;
    v4 = ptr->field_0;
    v2 = ptr->field_8;
    sub_140011760(v4, v2, str3);
    v3 = 1;
    if (result == 0) {
        if ((ptr->field_12 & 128) != 0) {
            result = *src;
            a1 = src;
            ((__int64 (*)())(*(result + 8)))();
            a1 = result;
            ((__int64 (*)())(a2[6]))();
            if (result != 0) {
                a1 = result;
                v_28 = (__int64)result;
                v3 = (__int64)a2;
                ((__int64 (*)())(a2[6]))();
                a1 = (__int64 *)v3;
                v5 = (__int64)result;
                v6 = a2;
                result = (__int64 *)v_28;
                str = (char *)result;
                v_38 = (__int64)a1;
                str2 = str;
                v_48 = v7;
                result = &off_14010AEE8;
                str3 = (char *)result;
                v_58 = 1;
                v_70 = 0;
                v_60 = (__int64)str2;
                v_68 = 1;
                sub_140010C30(v4, v2, str3);
                if (result == 0) {
                    while (v5 != 0) {
                        a1 = (__int64 *)v5;
                        ((__int64 (*)())(*(v6 + 48)))();
                        v_28 = (__int64)result;
                        v_80 = (int)a2;
                        str = (char *)v5;
                        v_38 = (__int64)v6;
                        str2 = str;
                        v_48 = v7;
                        result = &off_14010AEE8;
                        str3 = (char *)result;
                        v_58 = 1;
                        v_70 = 0;
                        v_60 = (__int64)str2;
                        v_68 = 1;
                        sub_140010C30(v4, v2, str3);
                        v5 = v_28;
                        v6 = (__int64 *)v_80;
                        result = (__int64 *)v3;
                        return (__int64)result;
                    }
                    v3 = 0;
                }
                return v3;
            }
        }
        return v3;
    }
    return (__int64)result;
}