// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[120];
    __int64 field_88; // offset 136
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140038A80();
__int64 sub_140028220();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14012D268;
extern __int64 off_14012D270;

__int64 __fastcall sub_140038A70(__int64 *a1, __int64 a2) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_8;
    __int64 v5;
    __int64 result;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *src;

    sub_140038A80();
    v5 = rsp + 64;
    v_8 = -2;
    v_10 = a2;
    v_18 = (int)a1;
    ++off_14012D268;
    if (!((off_14012D268 <= 0))) {
        result = off_14012D270;
        a1 = __readgsqword(88);
        ptr = a1[(__int64)ptr];
        if (ptr->field_88 == 0) {
            ptr += 128;
            *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
            ptr->field_8 = 0;
        }
    }
    sub_140028220(a1);
    v5 = a2 + 64;
    ptr2 = (struct Struct_2_t *)a2;
    result = ptr2->field_0;
    src = (__int64 *)v_18;
    if (result != 0) {
        ((__int64 (*)())result)(src);
    }
    if (ptr2->field_8 != 0) {
        if (ptr2->field_10 >= 17) {
            src = *(src - 8);
        }
        off_140108030();
        off_140108038(result, 0);
    }
    return result;
}