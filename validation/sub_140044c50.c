// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140017B60();
__int64 sub_140021068();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_140044D6D();

__int64 __fastcall sub_140044C50(int *a1,struct Struct_1_t *a2) {
    int v_10;
    int v_48;
    int v_50;
    int v_58;
    int str;
    char *dst;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 v2;
    __int64 v11;
    __int64 v10;
    __int64 v8;
    __int64 v9;
    __int64 result;
    __int64 v7;
    __int64 v6;

    *dst = -2;
    ptr = (struct Struct_2_t *)a2;
    v3 = *a1;
    v2 = a2->field_20;
    v11 = a2->field_28;
    a1 = dst - 88;
    sub_140017B60(a1, v2, v11);
    if (v_58 == 0) {
        a2 = (struct Struct_1_t *)v_50;
        a1 = dst - 88;
        sub_140021068(a1, a2, v_48);
    }
    if (v11 < 0) {
        sub_1400F3360();
    }
    if (!((0 /* unresolved: flags == */))) {
        sub_14002EDF0(0, v11);
        v10 = result;
        if (result == 0) {
            sub_1400F3326(1, v11);
            v10 = 1;
        }
        sub_1400F27F0(v10, v2, v11);
        v_10 = v10;
        if (!(((*ptr & 1) == 0))) {
            v8 = ptr->field_10;
            v9 = v8 + v8;
            result = (v8 < 0) ? 1 : 0;
            a1 = 0x7FFFFFFFFFFFFFFE;
            a1 = (v9 > a1) ? 1 : 0;
            a1 = (int *)((__int64)(__int64)a1 | result);
            str = v11;
            if ((a1 == 0)) {
                v7 = ptr->field_8;
                if (v9 == 0) JUMPOUT(0x140044d4d);
                sub_14002EDF0(0, v9);
                v6 = result;
                if (result != 0) JUMPOUT(0x140044d56);
                a1 = 2;
            }
            sub_1400F3326(0, v9);
        }
        result = 2;
        return sub_140044D6D();
    }
    return result;
}