// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();

__int64 __fastcall sub_140058520(int *a1, __int64 a2, __int64 a3) {
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v1;

    if (a3 < 0) {
        sub_1400F3360();
    }
    v3 = a3;
    ptr = (struct Struct_1_t *)a1;
    if (!((0 /* unresolved: flags == */))) {
        v2 = a2;
        sub_14002EDF0(0, v3);
        a2 = v2;
        a1 = (int *)v1;
        if (v1 == 0) {
            sub_1400F3326(1, v3);
        }
        *(__int64 *)ptr = (__int64)(v3);
        ptr->field_8 = a1;
        sub_1400F27F0(1, a2, v3);
        ptr->field_10 = v3;
        return (__int64)a1;
    }
    return (__int64)a1;
}