// inferred from 3 accesses on `a4`
struct Struct_1_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 15 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[2];
    __int64 field_2; // offset 2
    char _pad_2[30];
    char field_28; // offset 40
    char field_29; // offset 41
    char field_2A; // offset 42
    char field_2B; // offset 43
    __int64 field_2C; // offset 44
    int field_34; // offset 52
    char field_38; // offset 56
    char field_39; // offset 57
    __int64 field_3A; // offset 58
    char _pad_3A[6];
    char field_48; // offset 72
    int field_49; // offset 73
    char _pad_49[3];
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    char _pad_58[8];
    __int64 field_68; // offset 104
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400831E0();
__int64 sub_14008390C();
extern __int64 off_1401237FC;

__int64 __fastcall sub_140083510(int *a1, int a2, int *a3,struct Struct_1_t *a4) {
    __int64 rsp;
    int v_20;
    int v_28;
    int v_29;
    int v_2a;
    int v_2b;
    int v_2c;
    int v_34;
    int v_38;
    int v_40;
    int v_48;
    struct Struct_2_t *ptr;
    __int64 v2;
    __int64 result;
    int v9;
    int v4;
    struct Struct_3_t *ptr2;
    __int64 i;
    __int64 *src;
    __int64 v7;

    ptr = (struct Struct_2_t *)a1;
    v2 = a2;
    result = v2 - 164;
    if (result <= 35) {
        a1 = &off_1401237FC;
        switch (result) {
            case 2:
                break;
            case 28:
                v_20 = 0;
                a1 = rsp + 40;
                sub_1400831E0(a1, a3, a4, 0);
                a3 = (int *)v_28;
                a1 = (int *)v_29;
                a2 = v_2a;
                result = v_2b;
                if (a3 != 4) JUMPOUT(0x1400838ba);
                return result;
            default:
                v9 = a2;
                result = a4->field_3;
                result >>= 4;
                a1 = a4->field_0;
                a2 = (int)a1;
                a2 >>= 1;
                if (a4->field_2 != 0) a2 = result;
                a1 = (int *)((__int64)(__int64)a1 & 32);
                result = 0;
                ++result;
                v4 = 3;
                if ((a2 & 1) == 0) v4 = result;
                v_20 = 0;
                a1 = rsp + 40;
                ptr2 = (struct Struct_3_t *)a3;
                sub_1400831E0(a1, a3, a4, v4);
                a3 = (int *)v_28;
                a1 = (int *)v_29;
                a2 = v_2a;
                result = v_2b;
                if (a3 == 4) {
                    return result;
                } else {
                    a4 = (struct Struct_1_t *)v_34;
                    v_48 = (int)a4;
                    a4 = (struct Struct_1_t *)v_2c;
                    v_40 = (int)a4;
                    a4 = (struct Struct_1_t *)v_38;
                    v2 |= 8;
                    if (v2 != 172) {
                        i = 0;
                    } else {
                        i = ptr2->field_10;
                        if (i >= ptr2->field_8) {
                            *(__int64 *)ptr = (__int64)(2);
                            ptr->field_2 = 0;
                            ptr->field_28 = 5;
                            return sub_14008390C();
                        } else {
                            src = ptr2->field_0;
                            src = *(src + i);
                            ++i;
                            ptr2->field_10 = i;
                            i = 2;
                        }
                    }
                    a4 = (struct Struct_1_t *)((__int64)(__int64)a4 & 15);
                    v9 &= 254;
                    v2 = (v9 == 164) ? 1 : 0;
                    v2 ^= 29;
                    v9 = v_48;
                    ptr->field_34 = v9;
                    v7 = v_40;
                    ptr->field_2C = v7;
                    *(__int64 *)ptr = (__int64)(v2);
                    ptr->field_28 = a3;
                    ptr->field_29 = a1;
                    ptr->field_2A = a2;
                    ptr->field_2B = result;
                    ptr->field_38 = 0;
                    ptr->field_39 = v4;
                    ptr->field_3A = a4;
                    ptr->field_48 = i;
                    ptr->field_49 = 256;
                    ptr->field_50 = src;
                    ptr->field_58 = 4;
                    ptr->field_68 = 3;
                    return sub_14008390C();
                }
                break;
        }
    }
    result = a2;
    result &= 248;
    if (result != 200) JUMPOUT(0x1400838a8);
    result = a4->field_3;
    result >>= 4;
    a1 = a4->field_0;
    a3 = a1;
    a3 = (int *)((__int64)(__int64)a3 >> 1);
    if (a4->field_2 == 0) result = a3;
    a1 = (int *)((__int64)(__int64)a1 & 32);
    a4 = 0;
    ++a4;
    a1 = (int *)a4;
    if (a4 == 3) result = a4;
    a3 = (int *)((__int64)(__int64)a3 & 8);
    a2 += (__int64)a3;
    a2 += 56;
    *(__int64 *)ptr = (__int64)(74);
    ptr->field_28 = 0;
    ptr->field_29 = result;
    ptr->field_2A = a2;
    return result;
}