// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[25];
    char field_19; // offset 25
    __int16 field_1A; // offset 26
    char _pad_1A[1];
    __int64 field_1D; // offset 29
};

__int64 sub_14002E830();
__int64 sub_1400302C0();
__int64 sub_140030D45();

__int64 __fastcall sub_140030C50(__int64 a1, __int64 a2, __int64 a3) {
    int arg_10;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_40;
    int v_48;
    int str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v9;
    __int64 v5;
    __int64 v7;
    __int64 v4;
    __int64 result;
    __int64 v8;

    arg_10 = -2;
    ptr = (struct Struct_1_t *)a3;
    a1 = str2 - 48;
    sub_14002E830(a1, a1, a2);
    v2 = v_30;
    v9 = v_28;
    v5 = v2;
    v5 = -v5;
    if (!((0 /* overflow check on (-v5) */))) {
        v_18 = v2;
        v_10 = v9;
        str = v_20;
        v7 = str2 - 72;
        v4 = str2 - 24;
        sub_1400302C0(v7, v4, 1);
        v9 = v_40;
        v2 = v_48;
        v2 = -v2;
        if ((0 /* overflow check on (-v2) */)) {
            a2 = ptr->field_19;
            a1 = ptr->field_1A;
            if (a2 == 0) JUMPOUT(0x140030cf2);
            if (a1 != 0) JUMPOUT(0x140030cf6);
            result = ptr->field_1D;
            return sub_140030D45();
        }
    }
    result = 1;
    v8 = v9;
    return result;
}