// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

__int64 sub_14008FA20();
__int64 sub_14008F9F7();
extern __int64 off_140117BB4;
extern __int64 off_140117BB8;
extern __int64 off_1401109F8;

__int64 __fastcall sub_14008F8C0(__int64 *a1, __int64 *a2) {
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v7;
    int v5;
    __int64 v10;
    __int64 v3;
    __int64 *src;
    __int64 v11;
    __int64 v9;
    __int64 v2;
    __int64 *src2;

    ptr = (struct Struct_1_t *)a2;
    if (*a1 == 6) {
        a1 = ptr->field_0;
        result = ptr->field_8;
        result = *(result + 24);
        v7 = &off_140117BB4;
        v5 = 4;
        JUMPOUT(result);
    }
    v10 = (__int64)a1;
    v3 = ptr->field_0;
    src = ptr->field_8;
    v11 = *(src + 24);
    v9 = &off_140117BB8;
    ((__int64 (*)())v11)(v3, v9, 4);
    v2 = 1;
    if (result == 0) {
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x14008f971);
        v9 = &off_1401109F8;
        ((__int64 (*)())v11)(v3, v9, 1);
        if (result == 0) {
            sub_14008FA20(v10, ptr);
            if (result == 0) {
                v3 = ptr->field_0;
                src2 = ptr->field_8;
                v2 = *(src2 + 24);
                return sub_14008F9F7();
            }
        }
    }
    result = (__int64 *)v2;
    return (__int64)result;
}