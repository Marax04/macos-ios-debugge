// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int16 field_10; // offset 16
    __int64 field_12; // offset 18
};

__int64 sub_140029040();
__int64 sub_14002FB61();
extern __int64 off_1401109A8;
extern __int64 off_14011AB0E;
extern __int64 off_14010B408;
extern __int64 off_14011530C;

__int64 __fastcall sub_14002FA40(int *a1, __int64 *a2) {
    int arg_7;
    int arg_8;
    __int64 v_10;
    int v_18;
    int v_20;
    __int64 v_28;
    int v_30;
    int v_8;
    char *str;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v8;
    __int64 *result;
    __int64 v2;
    __int64 *v10;
    __int64 v6;
    __int64 v7;
    __int64 v9;
    int v5;

    ptr = (struct Struct_1_t *)a2;
    v4 = *(a1 + 8);
    v8 = a1[2];
    a1 = *a2;
    result = (__int64 *)arg_8;
    a2 = &off_1401109A8;
    ((__int64 (*)())(*(result + 24)))();
    a1 = (int *)result;
    if (v8 != 0) {
        result = 1;
        if (a1 == 0) {
            if ((ptr->field_12 & 128) != 0) {
                v2 = ptr->field_0;
                v10 = ptr->field_8;
                a2 = &off_14011AB0E;
                a1 = (int *)v2;
                ((__int64 (*)())(*(v10 + 24)))();
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    arg_7 = 1;
                    v_30 = v2;
                    v_28 = (__int64)v10;
                    v6 = str + 7;
                    v_20 = v6;
                    v7 = ptr->field_10;
                    v_8 = v7;
                    v9 = str - 48;
                    v_18 = v9;
                    result = &off_14010B408;
                    v_10 = (__int64)result;
                    a2 = str - 24;
                    sub_140029040(v4, a2, 1);
                    if (result == 0) JUMPOUT(0x14002fb43);
                    result = 1;
                }
                if (v8 != 1) JUMPOUT(0x14002fb61);
            } else {
                sub_140029040(v4, ptr, 1);
                if (v8 != 1) {
                    return sub_14002FB61();
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