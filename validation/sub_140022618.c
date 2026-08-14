// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[1];
    int field_1; // offset 1
    char _pad_1[3];
    __int64 field_8; // offset 8
};

__int64 sub_1400233F1();

__int64 __fastcall sub_140022618(__int64 *a1,struct Struct_1_t *a2, __int64 a3) {
    int v_8;
    int v_f;
    char *str;
    struct Struct_2_t *ptr;
    __int64 i;
    __int64 *v5;
    __int64 *v4;
    __int64 result;

    ptr = (struct Struct_2_t *)a1;
    i = ((__int64 *)a2)[2];
    if (i < a2->field_8) {
        v5 = a2->field_0;
        if (*(v5 + i) != a3) {
            ptr->field_8 = 0;
        } else {
            ++i;
            ((__int64 *)a2)[2] = (__int64)(i);
            v4 = str - 16;
            sub_1400233F1(v4);
            if (*v4 == 0) {
                i = v_8;
                if (i == -1) JUMPOUT(0x140022683);
                ++i;
                ptr->field_8 = i;
                result = 0;
            } else {
                result = v_f;
                ptr->field_1 = result;
                result = 1;
            }
            *(__int64 *)ptr = (__int64)(result);
            return result;
        }
        return result;
    }
    return result;
}