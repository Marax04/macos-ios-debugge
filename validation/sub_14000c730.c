// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int16 field_10; // offset 16
    __int64 field_12; // offset 18
};

__int64 sub_140009600();
__int64 sub_14000C858();
extern __int64 off_1401109A8;
extern __int64 off_14011AB0E;
extern __int64 off_14010B408;
extern __int64 off_14011530C;

__int64 __fastcall sub_14000C730(int *a1, __int64 *a2) {
    __int64 rsp;
    int arg_8;
    __int64 v_28;
    __int64 v_30;
    int v_38;
    __int64 v_48;
    __int64 v_50;
    char *str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 *result;
    __int64 v2;
    __int64 *v8;
    __int64 v6;
    int v5;

    ptr = (struct Struct_1_t *)a2;
    v4 = *(a1 + 8);
    v7 = a1[2];
    a1 = *a2;
    result = (__int64 *)arg_8;
    a2 = &off_1401109A8;
    ((__int64 (*)())(*(result + 24)))();
    a1 = (int *)result;
    if (v7 != 0) {
        result = 1;
        if (a1 == 0) {
            if ((ptr->field_12 & 128) != 0) {
                v2 = ptr->field_0;
                v8 = ptr->field_8;
                a2 = &off_14011AB0E;
                a1 = (int *)v2;
                ((__int64 (*)())(*(v8 + 24)))();
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    str = 1;
                    str2 = (char *)v2;
                    v_48 = (__int64)v8;
                    v_50 = (__int64)str;
                    v6 = ptr->field_10;
                    v_38 = v6;
                    v_28 = (__int64)str2;
                    result = &off_14010B408;
                    v_30 = (__int64)result;
                    a2 = rsp + 40;
                    sub_140009600(v4, a2, 1);
                    if (result == 0) JUMPOUT(0x14000c838);
                    result = 1;
                }
                if (v7 != 1) JUMPOUT(0x14000c858);
            } else {
                sub_140009600(v4, ptr, 1);
                if (v7 != 1) {
                    return sub_14000C858();
                }
            }
            a1 = (int *)result;
            result = 1;
            if (a1 == 0) {
                a1 = ptr->field_0;
                result = ptr->field_8;
                a2 = &off_14011530C;
                v5 = 1;
                ((__int64 (*)())(*(result + 24)))();
            }
            return v5;
        }
        return v5;
    }
    return (__int64)result;
}