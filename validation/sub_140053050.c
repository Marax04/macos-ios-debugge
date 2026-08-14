// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140013110();
__int64 sub_140011760();
extern __int64 off_140115967;
extern __int64 off_14000E2E0;
extern __int64 off_140115988;
extern __int64 off_140116F10;

__int64 __fastcall sub_140053050(int *a1, __int64 *a2) {
    __int64 rsp;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    char *str;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 result;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    result = *a1;
    if (result == 0) {
        a2 = &off_140115967;
        sub_140013110(ptr, a2, 16);
        a1 = (int *)result;
        result = 1;
        if (a1 == 0) {
            result = ptr2->field_10;
            if (result == 0) JUMPOUT(0x14005316d);
            a1 = ptr2->field_18;
            v_28 = result;
            v_30 = (int)a1;
            result = rsp + 40;
            v_38 = result;
            result = &off_14000E2E0;
            v_40 = result;
            result = &off_140115988;
            str = (char *)result;
            v_50 = 1;
            v_68 = 0;
            result = rsp + 56;
            v_58 = result;
            v_60 = 1;
            a1 = ptr->field_0;
            a2 = ptr->field_8;
            return sub_140011760(a1, a2, str);
        }
    } else {
        a1 = ptr2->field_8;
        v_28 = result;
        v_30 = (int)a1;
        result = rsp + 40;
        v_38 = result;
        result = &off_14000E2E0;
        v_40 = result;
        result = &off_140116F10;
        str = (char *)result;
        v_50 = 1;
        v_68 = 0;
        result = rsp + 56;
        v_58 = result;
        v_60 = 1;
        a1 = ptr->field_0;
        a2 = ptr->field_8;
        sub_140011760(a1, a2, str);
        a1 = (int *)result;
        result = 1;
        if (a1 == 0) {
            return result;
        }
    }
    return result;
}