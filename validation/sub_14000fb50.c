// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14000FC6A();
__int64 sub_1400F27F0();
extern __int64 off_140017D60;
extern __int64 off_140018400;
extern __int64 off_14010FD90;

__int64 __fastcall sub_14000FB50(int *a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int arg_20;
    int arg_21;
    int v_1;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    __int64 v10;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v9;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 v1;

    v10 = rsp + 32;
    if (a3 < 0) {
        sub_1400F3360();
    }
    v3 = a3;
    ptr = (struct Struct_1_t *)a1;
    if ((0 /* unresolved: flags == */)) {
        v2 = 1;
    } else {
        v9 = a2;
        sub_14002EDF0(0, v3);
        if (v1 == 0) {
            sub_1400F3326(1, v3);
            v10 = rsp + 128;
            v5 = a1 + 24;
            if (arg_20 != 1) JUMPOUT(0x14000fc30);
            a1 = (int *)arg_21;
            v_1 = (int)a1;
            a1 = v10 - 1;
            v_28 = (int)a1;
            a1 = &off_140017D60;
            v_20 = (int)a1;
            v_18 = v5;
            v6 = &off_140018400;
            v_10 = v6;
            v7 = &off_14010FD90;
            v_58 = v7;
            v_50 = 2;
            v_38 = 0;
            v8 = v10 - 40;
            v_48 = v8;
            v_40 = 2;
            return sub_14000FC6A();
        } else {
            v2 = v1;
        }
    }
    sub_1400F27F0(v2, v9, v3);
    *(__int64 *)ptr = (__int64)(v3);
    ptr->field_8 = v2;
    ptr->field_10 = v3;
    return v2;
}