// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_1400F71A0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140037360(int a1, __int64 a2, __int64 a3) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_8;
    __int64 v11;
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v2;
    __int64 v9;
    __int64 i;
    __int64 *dst;
    __int64 v10;
    __int64 v5;

    v11 = rsp + 64;
    v_8 = -2;
    v4 = a1 + 32;
    if (a3 < 0) {
        sub_1400F3360();
    }
    ptr = (struct Struct_1_t *)a1;
    if ((0 /* unresolved: flags == */)) {
        result = 1;
    } else {
        v2 = a2;
        v9 = a3;
        sub_14002EDF0(0, a3);
        if (result == 0) {
            sub_1400F3326(1, v9, a3);
            v_10 = v9;
            v11 = v9 + 64;
            if (v_18 != 0) {
                off_140108030();
                off_140108038(result, 0, v_10);
            }
            return v11;
        } else {
        }
    }
    v_10 = result;
    v_18 = a3;
    sub_1400F27F0(result, v2, v9);
    i = ptr->field_30;
    if (i == ptr->field_20) {
        sub_1400F71A0(v4);
    }
    dst = ptr->field_28;
    v10 = i + i*4;
    dst[v10] = 0;
    a2 = v_18;
    *(dst + v10*8 + 8) = a2;
    v5 = v_10;
    *(dst + v10*8 + 16) = v5;
    *(dst + v10*8 + 24) = a2;
    *(dst + v10*8 + 32) = 0;
    ++i;
    ptr->field_30 = i;
    return result;
}