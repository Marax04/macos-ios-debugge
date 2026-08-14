// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14003FAB0();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14003FF60(int *a1) {
    int arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_58;
    int str;
    char *dst;
    __int64 v3;
    __int64 result;
    __int64 v6;
    __int64 v5;
    __int64 v10;
    __int64 v11;
    struct Struct_2_t *ptr2;
    __int64 v9;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 v2;

    v3 = *a1;
    if (v3 == 0) {
        a1 = 0;
        result = 0;
    } else {
        v6 = arg_8;
        result = a1[2];
        v_38 = 0;
        v_30 = v3;
        v_28 = v6;
        v_18 = 0;
        v_10 = v3;
        str = v6;
        a1 = 1;
    }
    v_40 = (int)a1;
    v_20 = (int)a1;
    *dst = result;
    v5 = dst - 64;
    v10 = off_140108030;
    v11 = off_140108038;
    do {
        a1 = dst - 88;
        sub_14003FAB0(a1, v5, v6);
        ptr2 = (struct Struct_2_t *)v_58;
        if (ptr2 == 0) JUMPOUT(0x140040064);
        v9 = v_48;
        v7 = v9 * 56;
        ptr = ptr2 + v7;
        ptr += 360;
        if (*(__int64 *)(ptr2 + v7 + 360) == 0) {
            if (ptr->field_20 == 0) {
                v9 <<= 5;
                ptr2 += v9;
                v2 = ptr2->field_8;
                ((__int64 (*)())v10)();
                ((__int64 (*)())v11)(v7, 0, v2);
            }
            v2 = ptr->field_28;
            ((__int64 (*)())v10)();
            ((__int64 (*)())v11)(v7, 0, v2);
            return v2;
        }
        v2 = ptr->field_8;
        ((__int64 (*)())v10)();
        ((__int64 (*)())v11)(v7, 0, v2);
        return result;
    } while (ptr2->field_0 == 0);
}