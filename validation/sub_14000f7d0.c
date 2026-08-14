// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14000F8A4();
__int64 sub_1400F27F0();

__int64 __fastcall sub_14000F7D0(int *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int v_30;
    __int64 *dst;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v8;
    __int64 v7;
    __int64 v6;
    __int64 v5;
    __int64 v1;

    dst = rsp + 32;
    if (a3 < 0) {
        sub_1400F3360();
    }
    v3 = a3;
    ptr = (struct Struct_1_t *)a1;
    if ((0 /* unresolved: flags == */)) {
        v2 = 1;
    } else {
        v8 = a2;
        sub_14002EDF0(0, v3);
        if (v1 == 0) {
            sub_1400F3326(1, v3);
            dst = rsp + 80;
            *dst = -2;
            if (a3 < 0) {
                sub_1400F3360();
            }
            v7 = a2;
            v_30 = (int)a1;
            if ((0 /* unresolved: flags == */)) JUMPOUT(0x14000f89e);
            v6 = a3;
            sub_14002EDF0(0, a3);
            if (v1 == 0) JUMPOUT(0x14000fae9);
            v5 = v6;
            return sub_14000F8A4();
        } else {
            v2 = v1;
        }
    }
    sub_1400F27F0(v2, v8, v3);
    *(__int64 *)ptr = (__int64)(v3);
    ptr->field_8 = v2;
    ptr->field_10 = v3;
    ptr->field_18 = 0;
    return v2;
}