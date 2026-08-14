// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    char field_18; // offset 24
    int field_19; // offset 25
    __int16 field_1D; // offset 29
    char field_1F; // offset 31
    __int64 field_20; // offset 32
};

__int64 sub_140052E40();
__int64 sub_140052A21();
__int64 sub_140011760();
extern __int64 off_140115680;
extern __int64 off_140115748;
extern __int64 off_140013590;
extern __int64 off_140017E10;
extern __int64 off_140115688;
extern __int64 off_1401156B8;

__int64 __fastcall sub_140051DC0(int *a1, __int64 *a2) {
    __int64 rsp;
    int arg_18;
    int arg_2;
    int arg_8;
    int v_20;
    int v_22;
    int v_24;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    __int64 v_58;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    int v_78;
    __int64 v_80;
    char *str;
    __int64 *result;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 v4;

    result = *a1;
    if (*result != 1) {
        a1 = *a2;
        result = (__int64 *)arg_8;
        result = (__int64 *)arg_18;
        a2 = &off_140115680;
        JUMPOUT(result);
        v2 = (__int64)a2;
        ptr = (struct Struct_1_t *)a1;
        v_40 = (int)a2;
        v_48 = v4;
        a1 = rsp + 32;
        a2 = rsp + 64;
        sub_140052E40(a1, a2, 1);
        if (v_30 != 9) JUMPOUT(0x140051f54);
        result = &off_140115748;
        a1 = (int *)result;
        a1 = (int *)((__int64)(__int64)a1 >> 8);
        ptr->field_8 = 0;
        ptr->field_18 = result;
        a2 = result;
        a2 = (__int64 *)((__int64)(__int64)a2 >> 56);
        ptr->field_1F = a2;
        result = (__int64 *)((__int64)(__int64)result >> 40);
        ptr->field_1D = result;
        ptr->field_19 = a1;
        ptr->field_20 = 12;
        return sub_140052A21();
    } else {
        result = (__int64 *)arg_2;
        a1 = (int *)result;
        a1 = (int *)((__int64)(__int64)a1 >> 15);
        a1 =  + (__int64)(__int64)a1*2 + 43;
        v4 = (__int64)result;
        v4 = -v4;
        if (v4 < 0) v4 = result;
        v_24 = (int)a1;
        result = (__int64 *)v4;
        result = (__int64 *)((__int64)(__int64)(__int64)result * 0xFFFF8889);
        result = (__int64 *)((__int64)(__int64)result >> 16);
        result += v4;
        a1 = (int *)result;
        result = (__int64 *)((__int64)(__int64)result >> 15);
        a1 = (int *)((__int64)(__int64)a1 >> 5);
        a1 = (int *)((__int64)a1 + (__int64)result);
        v_20 = (int)a1;
        result = (__int64)(__int64)a1 * 60;
        v4 -= (__int64)result;
        v_22 = v4;
        result = rsp + 36;
        v_58 = (__int64)result;
        result = &off_140013590;
        v_60 = (__int64)result;
        result = rsp + 32;
        v_68 = (__int64)result;
        result = &off_140017E10;
        v_70 = (__int64)result;
        a1 = rsp + 34;
        v_78 = (int)a1;
        v_80 = (__int64)result;
        result = &off_140115688;
        str = (char *)result;
        v_30 = 3;
        result = &off_1401156B8;
        v_48 = (__int64)result;
        v_50 = 3;
        result = rsp + 88;
        v_38 = (__int64)result;
        v_40 = 3;
        a1 = *a2;
        a2 = (__int64 *)arg_8;
        sub_140011760(a1, a2, str);
        return (__int64)result;
    }
}