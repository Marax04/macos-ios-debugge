// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[1];
    int field_1; // offset 1
    char _pad_1[3];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_1400F72F2();
__int64 sub_1400393F0();
__int64 sub_1400F6840();
__int64 off_1401081D0();
extern __int64 off_140108058;
extern __int64 off_140108060;

__int64 __fastcall sub_140039260(int *a1, __int64 *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_8;
    int v_10;
    int v_20;
    int v_28;
    __int64 v12;
    __int64 *dst;
    struct Struct_2_t *ptr2;
    __int64 v10;
    __int64 v11;
    __int64 v9;
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v8;
    __int64 v6;
    __int64 v5;

    v12 = rsp + 80;
    dst = a2;
    if (*a2 != 0) {
        v_28 = 0;
        a2 = v12 - 40;
        sub_1400F72F2(dst, a2, v5);
        v12 = rsp + 48;
        ptr2 = (struct Struct_2_t *)a1;
        dst = v12 - 16;
        v10 = off_140108058;
        v11 = off_140108060;
        v9 = *a1;
        if (v9 == 0) JUMPOUT(0x140039404);
        if (result != 1) JUMPOUT(0x1400393d0);
        a2 = ptr2->field_10;
        v_10 = 0;
        a1 = ptr2->field_20;
        ((__int64 (*)())v10)(a1, a2, dst, 1);
        if (result == 0) JUMPOUT(0x1400393d6);
        result = v_10;
        return sub_1400393F0();
    } else {
        ptr2 = (struct Struct_2_t *)a1;
        ptr = (struct Struct_1_t *)arg_18;
        v7 = ptr->field_0;
        a2 = ptr->field_10;
        if (v7 == a2) {
            a1 = 16;
            result = 1;
            if (v7 == 0) result = a1;
            v_20 = 1;
            sub_1400F6840(ptr, v7, result, 1);
            v7 = ptr->field_0;
            a2 = ptr->field_10;
        }
        v7 -= (__int64)a2;
        a2 += ptr->field_8;
        v8 = arg_10;
        a1 = 0xFFFFFFFF;
        if (v7 >= a1) v7 = a1;
        v_28 = 0;
        a1 = (int *)arg_20;
        v_20 = v8;
        v6 = v12 - 40;
        off_1401081D0(a1, a2, v7, v6);
        if (result == 0) {
            ((__int64 (*)())off_140108060)(2);
            if (result == 109) {
                ptr2->field_1 = 0;
            } else {
                if (result != 997) {
                    v8 <<= 32;
                    v8 |= 2;
                    ptr2->field_8 = v8;
                    result = 1;
                } else {
                    a1 = 1;
                    *dst = a1;
                    arg_8 = v8;
                    ptr2->field_1 = 1;
                    result = 0;
                }
                *(__int64 *)ptr2 = (__int64)(result);
                return result;
            }
            return result;
        } else {
            result = v_28;
            if (v8 != 0) {
                return result;
            } else {
                return result;
            }
            return result;
        }
        return result;
    }
}