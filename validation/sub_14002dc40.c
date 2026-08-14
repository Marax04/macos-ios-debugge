// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    int field_0; // offset 0
    char _pad_0[3];
    __int64 field_7; // offset 7
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14000ECF0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14002DC40(int *a1, __int64 a2) {
    __int64 rsp;
    int v_10;
    int v_18;
    __int64 v_8;
    __int64 *dst;
    struct Struct_2_t *ptr;
    __int64 v7;
    __int64 v8;
    __int64 *src;
    struct Struct_3_t *ptr2;
    __int64 v10;
    __int64 v5;
    __int64 v11;
    struct Struct_1_t *result;

    dst = rsp + 64;
    *dst = -2;
    ptr = *a1;
    a1 = (int *)result;
    a1 = (int *)((__int64)(__int64)a1 & 3);
    if (a1 == 1) {
        v7 = ptr - 1;
        v_18 = v7;
        v8 = *(__int64 *)(ptr - 1);
        v_10 = v8;
        ptr = ptr->field_7;
        v_8 = (__int64)ptr;
        ptr = ptr->field_0;
        if (ptr != 0) {
            ((__int64 (*)())ptr)(v_10);
        }
        src = (__int64 *)v_10;
        ptr2 = (struct Struct_3_t *)v_8;
        if (ptr2->field_8 != 0) {
            if (ptr2->field_10 >= 17) {
                src = *(src - 8);
            }
            off_140108030();
            ((__int64 (*)())off_140108038)(ptr2, 0, src);
        }
        off_140108030();
        v10 = (__int64)ptr2;
        a2 = 0;
        v5 = v_18;
        JUMPOUT(off_140108038);
        dst = a2 + 64;
        v11 = a2;
        result = (struct Struct_1_t *)v_8;
        if (result->field_8 != 0) {
            result = (struct Struct_1_t *)v_8;
            a2 = result->field_10;
            sub_14000ECF0(v11, a2, v5);
        }
        off_140108030();
        return ((__int64 (*)())off_140108038)(result, 0, v_18);
    } else {
        return (__int64)result;
    }
}