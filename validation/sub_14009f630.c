// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14009D9C0();
__int64 sub_14009F7E8();
extern __int64 off_140119AA8;

__int64 __fastcall sub_14009F630(__int64 *a1, __int64 *a2, __int64 a3) {
    __int64 rsp;
    int arg_58;
    int arg_5c;
    int arg_e0;
    int v_40;
    int v_48;
    int v_50;
    int v_51;
    int v_58;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_99;
    __int64 v_a8;
    int v_c0;
    __int64 *dst;
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 v5;
    __int64 v6;
    __int64 v10;
    struct Struct_2_t *ptr2;
    __int64 v9;

    dst = a1;
    if (arg_e0 > 1) {
        result = arg_5c;
        result |= arg_58;
        if (!((result == 0))) {
            v_80 = a3;
            a1 = rsp + 72;
            ptr = (struct Struct_1_t *)a2;
            sub_14009D9C0(a1);
            result = v_48;
            a1 = (__int64 *)result;
            a1 = (__int64 *)(-(__int64)a1);
            if ((0 /* overflow check on (-a1) */)) {
                a1 = (__int64 *)v_50;
                a2 = (__int64 *)v_51;
                v_99 = (int)a2;
                a2 = (__int64 *)v_58;
                v_90 = result;
                v_98 = (int)a1;
                result = v_80;
                v_88 = result;
                a1 = a2;
                if (a1 == 0) JUMPOUT(0x14009fc6d);
                v4 = v_98;
                a1 += (__int64)(__int64)a1*2;
                a1 = (__int64 *)((__int64)(__int64)a1 << 4);
                a1 += v4;
                v_c0 = (int)a1;
                v7 = v4 + 48;
                a3 = ptr->field_20;
                a2 = ptr->field_28;
                v5 = ptr->field_8;
                v_68 = v5;
                v5 = ptr->field_10;
                v_40 = v5;
                a3 -= 28;
                v_78 = a3;
                a3 = a2 + (__int64)(__int64)a2*8;
                a3 += a3*2;
                a3 += (__int64)a2;
                v_70 = a3;
                a3 = 0;
                v6 = 0xCBF29CE484222325;
                ptr = &off_140119AA8;
                v10 = 0x100000001B3;
                a1 = rsp + 72;
                a2 = rsp + 136;
                v5 = 0;
                ptr2 = (struct Struct_2_t *)v4;
                v4 = v7;
                v7 = ptr2->field_28;
                if (v7 == 0) JUMPOUT(0x14009fc4e);
                v9 = ptr2->field_20;
                v7 += v7*4;
                ptr2 =  + v7*8;
                ptr2 += v9;
                v7 = v9 + 40;
                v_a8 = (__int64)ptr2;
                return sub_14009F7E8();
            }
        }
    }
    *dst = 1;
    return result;
}