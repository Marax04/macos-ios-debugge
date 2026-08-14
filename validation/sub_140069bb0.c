// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400127C0();
__int64 sub_140069CC8();
extern __int64 off_1401109A8;
extern __int64 off_14011AB0E;
extern __int64 off_14010B408;
extern __int64 off_14011530C;

__int64 __fastcall sub_140069BB0(int *a1, __int64 a2) {
    int arg_10;
    int arg_8;
    __int64 v_38;
    __int64 v_40;
    char *str;
    char *str2;
    __int64 *src;
    __int64 v11;
    __int64 v10;
    __int64 v3;
    __int64 *src2;
    __int64 v9;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v5;

    src = (__int64 *)ptr;
    v11 = *(a1 + 8);
    v10 = a1[2];
    v3 = ptr->field_0;
    src2 = ptr->field_8;
    v9 = *(src2 + 24);
    a2 = &off_1401109A8;
    ((__int64 (*)())v9)(v3, a2, 1);
    a1 = (int *)result;
    if (v10 != 0) {
        ptr = *(src + 16);
        result = 1;
        if (a1 == 0) {
            if (((__int64)ptr & 0x800000) != 0) {
                a2 = &off_14011AB0E;
                ((__int64 (*)())v9)(v3, a2, 1);
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    str = 1;
                    str2 = (char *)v3;
                    v_38 = (__int64)src2;
                    v_40 = (__int64)str;
                    a2 = arg_10;
                    v5 = &off_14010B408;
                    sub_1400127C0(arg_8, a2, str2, v5);
                    if (result == 0) JUMPOUT(0x140069cab);
                    result = 1;
                }
                if (v10 != 1) JUMPOUT(0x140069cc8);
            } else {
                a2 = arg_10;
                sub_1400127C0(arg_8, a2, v3, src2);
                if (v10 != 1) {
                    return sub_140069CC8();
                }
            }
            a1 = (int *)result;
            result = 1;
            if (a1 == 0) {
                a2 = &off_14011530C;
                ((__int64 (*)())v9)(v3, a2, 1);
            }
            return a2;
        }
        return a2;
    }
    return result;
}