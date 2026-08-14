// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 off_1401081C0();
__int64 off_140108060();
extern __int64 off_140108048;

__int64 __fastcall sub_140038FD0(int *a1, int a2, int a3, __int64 a4) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_8;
    __int64 v10;
    __int64 v4;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v5;
    __int64 v9;
    __int64 v8;

    v10 = rsp + 64;
    v_8 = -2;
    v4 = a3;
    v2 = a2;
    ptr = (struct Struct_1_t *)a1;
    off_1401081C0(0, 1, 1, 0);
    if (result == 0) {
        off_140108060();
        result = (__int64 *)((__int64)(__int64)result << 32);
        result = (__int64 *)((__int64)(__int64)result | 2);
        ptr->field_8 = result;
        *(__int64 *)ptr = (__int64)(3);
        v5 = v2;
        JUMPOUT(off_140108048);
    } else {
        v9 = (__int64)result;
        sub_14002EDF0(8, 32);
        if (result != 0) {
            *(result + 24) = v9;
            *(__int64 *)ptr = (__int64)(0);
            ptr->field_10 = result;
            ptr->field_18 = v4;
            ptr->field_20 = v2;
            ptr->field_28 = v9;
            return (__int64)result;
        }
    }
    v_10 = v9;
    v_18 = v2;
    sub_1400F3340(8, 32);
    v10 = a2 + 64;
    v8 = off_140108048;
    ((__int64 (*)())v8)(a2);
    return ((__int64 (*)())v8)(v_18);
}