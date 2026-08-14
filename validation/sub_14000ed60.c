// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14001B350();
__int64 sub_14002EDF0();
__int64 sub_14000EE07();
__int64 sub_1400F3360();
__int64 sub_14000EF21();

__int64 __fastcall sub_14000ED60(__int64 *a1, __int64 a2, __int64 a3) {
    int v_28;
    int v_30;
    int v_38;
    int v_48;
    int v_50;
    char *dst;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v5;
    __int64 v6;
    __int64 v8;
    __int64 v2;
    __int64 v1;

    *dst = -2;
    v7 = a3;
    ptr = (struct Struct_1_t *)a1;
    v_30 = a2;
    v_28 = a3;
    v4 = dst - 80;
    v5 = dst - 48;
    sub_14001B350(v4, v5);
    v6 = v_50;
    if (v6 != 0) {
        v8 = v_48;
        if (v_38 == 0) {
            ptr->field_8 = v6;
            ptr->field_10 = v8;
        } else {
            if (v7 >= 0) {
                if ((0 /* unresolved: flags == */)) JUMPOUT(0x14000ee02);
                sub_14002EDF0(0, v7);
                if (v1 == 0) JUMPOUT(0x14000ef73);
                return sub_14000EE07();
            } else {
                sub_1400F3360();
                ptr->field_8 = 1;
                ptr->field_10 = 0;
            }
        }
        v2 = 0x8000000000000000;
        *(__int64 *)ptr = (__int64)(v2);
        return sub_14000EF21();
    }
    return v2;
}