// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

__int64 sub_140018B70();
__int64 sub_140018FD7();
__int64 sub_140018FDA();
extern __int64 off_140110A3D;

__int64 __fastcall sub_140018F40(__int64 *a1, int a2, int a3, __int64 a4) {
    int arg_50;
    int arg_58;
    __int64 v_10;
    int v_20;
    int v_7;
    int v_8;
    char *str;
    __int64 v3;
    __int64 *src;
    __int64 v2;
    __int64 v9;
    __int64 *v5;
    __int64 v7;
    int v1;
    struct Struct_1_t *ptr;
    __int64 v8;
    __int64 v10;

    v3 = a4;
    src = a1;
    v2 = arg_50;
    v9 = arg_58;
    a1 = *a1;
    v5 = *(src + 8);
    ((__int64 (*)())(*(v5 + 24)))();
    v_10 = (__int64)src;
    v_8 = v1;
    v_7 = 0;
    v_20 = v9;
    v7 = str - 16;
    sub_140018B70(v7, v3, 4);
    a1 = (__int64 *)v_8;
    v1 = v_7;
    a2 = v1;
    a2 = ~a2;
    a2 |= (__int64)a1;
    if ((a2 & 1) == 0) {
        ptr = (struct Struct_1_t *)v_10;
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x140018fc3);
        v8 = ptr->field_0;
        ptr = ptr->field_8;
        v10 = &off_140110A3D;
        a3 = 2;
        return sub_140018FD7();
    } else {
        v1 |= (__int64)a1;
        return sub_140018FDA();
    }
}