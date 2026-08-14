// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char field_8; // offset 8
    __int64 field_9; // offset 9
};

__int64 sub_140018CEB();
extern __int64 off_140116F20;
extern __int64 off_140110A3A;
extern __int64 off_140117BCE;

__int64 __fastcall sub_140018B70(__int64 *a1, __int64 a2, int a3, __int64 a4) {
    int arg_70;
    struct Struct_2_t *ptr2;
    int v8;
    __int64 v4;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v6;
    __int64 v9;
    __int64 v5;

    ptr2 = (struct Struct_2_t *)a1;
    v8 = 1;
    if (*(a1 + 8) == 0) {
        v4 = a4;
        v7 = arg_70;
        ptr = ptr2->field_0;
        result = ptr2->field_9;
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x140018c32);
        v6 = a2;
        v9 = a3;
        a3 = (int)result;
        a3 ^= 3;
        a1 = &off_140116F20;
        a2 = &off_140110A3A;
        if (result != 0) a2 = a1;
        a1 = ptr->field_0;
        result = ptr->field_8;
        ((__int64 (*)())(*(result + 24)))();
        if (result == 0) {
            a1 = ptr->field_0;
            result = ptr->field_8;
            a2 = v6;
            v5 = v9;
            ((__int64 (*)())(*(result + 24)))();
            if (result == 0) {
                a1 = ptr->field_0;
                result = ptr->field_8;
                a2 = &off_140117BCE;
                ((__int64 (*)())(*(result + 24)))();
                if (result == 0) {
                    ((__int64 (*)())v7)(v4, ptr, 2);
                    return sub_140018CEB();
                }
            }
        }
    }
    ptr2->field_8 = v8;
    ptr2->field_9 = 1;
    result = (__int64 *)ptr2;
    return (__int64)result;
}