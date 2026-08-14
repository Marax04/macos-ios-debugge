// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140021E7D();
__int64 sub_1400F3B80();
__int64 sub_140024D41();
__int64 sub_140022DD6();
extern __int64 off_140110AA0;
extern __int64 off_140110A60;
extern __int64 off_140110CA8;

__int64 __fastcall sub_140022D10(int *a1, int a2) {
    int v_20;
    char *str;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v7;
    __int64 *src2;
    __int64 v6;
    __int64 v5;
    __int64 v12;
    __int64 v9;
    __int64 v2;
    __int64 v11;
    __int64 v10;
    int v1;

    ptr = (struct Struct_1_t *)a1;
    src = a1[4];
    a1[4] = 0;
    sub_140021E7D(a1, 0);
    if (v1 != 0) {
        v7 = &off_140110AA0;
        v_20 = v7;
        src2 = &off_140110A60;
        v6 = &off_140110CA8;
        v5 = str - 1;
        sub_1400F3B80(src2, 61, v5, v6);
        ptr = (struct Struct_1_t *)src2;
        src = *src2;
        if (src == 0) JUMPOUT(0x140022dc0);
        v12 = ptr->field_8;
        v9 = ptr->field_10;
        if (v9 >= v12) JUMPOUT(0x140022de9);
        v2 = *(src + v9);
        v11 = v9 + 1;
        ptr->field_10 = v11;
        sub_140024D41();
        if (v7 == 0) JUMPOUT(0x140022e29);
        v10 = ptr->field_20;
        if (v10 == 0) JUMPOUT(0x140022e16);
        v2 = a2;
        return sub_140022DD6();
    } else {
        ptr->field_20 = src;
        return v2;
    }
}