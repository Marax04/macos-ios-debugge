// inferred from 3 accesses on `a4`
struct Struct_1_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 9 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[40];
    char field_28; // offset 40
    char field_29; // offset 41
    char field_2A; // offset 42
    char field_2B; // offset 43
    __int64 field_2C; // offset 44
    int field_34; // offset 52
    __int16 field_38; // offset 56
    int field_3A; // offset 58
    char _pad_3A[2];
    __int64 field_40; // offset 64
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400831E0();
__int64 sub_14008435C();
extern __int64 off_14012388C;
extern __int64 off_1401238A4;
extern __int64 off_1401238CC;

__int64 __fastcall sub_140083A80(int *a1, size_t *a2, size_t *a3,struct Struct_1_t *a4) {
    __int64 rsp;
    int v_20;
    int v_30;
    int v_31;
    int v_32;
    int v_33;
    int v_34;
    int v_3c;
    int v_40;
    int v_48;
    int v_4a;
    int v_5c;
    int v_5e;
    int v_60;
    int v_68;
    int v_80;
    int v_88;
    int *v_0;
    struct Struct_3_t *ptr2;
    int v2;
    struct Struct_2_t *ptr;
    __int64 v7;
    __int64 result;
    int v8;
    __int64 v6;
    int v5;

    ptr2 = (struct Struct_3_t *)a3;
    v2 = (int)a2;
    ptr = (struct Struct_2_t *)a1;
    v7 = (__int64)a2;
    result = v7 - 128;
    if (result <= 5) {
        a1 = &off_14012388C;
        switch (result) {
            case 0:
                v8 = 0;
                return v8;
            case 1:
                result = a4->field_3;
                result >>= 4;
                a1 = a4->field_0;
                a2 = (size_t *)a1;
                a2 = (size_t *)((__int64)(__int64)a2 >> 1);
                if (a4->field_2 != 0) a2 = result;
                a1 = (int *)((__int64)(__int64)a1 & 32);
                result = 0;
                ++result;
                v8 = 3;
                if (((__int64)a2 & 1) == 0) v8 = result;
                v_20 = 0;
                a1 = rsp + 48;
                sub_1400831E0(a1, ptr2, a4, v8);
                result = v_30;
                a1 = (int *)v_31;
                v_48 = (int)a1;
                a1 = (int *)v_33;
                v_4a = (int)a1;
                if (result == 4) {
                    return v_4a;
                } else {
                    a1 = (int *)v_3c;
                    v_88 = (int)a1;
                    a1 = (int *)v_34;
                    v_80 = (int)a1;
                    a1 = (int *)v_40;
                    a2 = (size_t *)v_48;
                    v_5c = (int)a2;
                    a2 = (size_t *)v_4a;
                    v_5e = (int)a2;
                    if (v2 != 128) {
                        if (v7 != 131) {
                            if (v8 != 1) {
                                a2 = ptr2->field_10;
                                if (a2 > -5) JUMPOUT(0x140084932);
                                a3 = a2 + 4;
                                if (a3 > ptr2->field_8) JUMPOUT(0x140084932);
                                a4 = ptr2->field_0;
                                ptr2->field_10 = a3;
                                a2 = *(__int64 *)((__int64)a4 + (__int64)a2);
                            } else {
                                a2 = ptr2->field_10;
                                if (a2 > -3) JUMPOUT(0x140084a7f);
                                a3 = a2 + 2;
                                if (a3 > ptr2->field_8) JUMPOUT(0x140084a7f);
                                a4 = ptr2->field_0;
                                ptr2->field_10 = a3;
                                a2 = *(__int64 *)((__int64)a4 + (__int64)a2);
                            }
                        } else {
                            a3 = ptr2->field_10;
                            if (a3 >= ptr2->field_8) JUMPOUT(0x140084b96);
                            a2 = ptr2->field_0;
                            a2 = *(__int64 *)((__int64)a2 + (__int64)a3);
                            ++a3;
                            ptr2->field_10 = a3;
                        }
                        a1 = (int *)((__int64)(__int64)a1 << 3);
                        a3 = 0xB0A050807060904;
                        a3 = (size_t *)((__int64)(__int64)a3 >> (__int64)a1);
                        a1 = (int *)v_5e;
                        ptr->field_2B = a1;
                        a1 = (int *)v_5c;
                        ptr->field_29 = a1;
                        a1 = (int *)v_80;
                        ptr->field_2C = a1;
                        a1 = (int *)v_88;
                        ptr->field_34 = a1;
                        *(__int64 *)ptr = (__int64)(a3);
                        ptr->field_28 = result;
                        ptr->field_38 = 2;
                        ptr->field_40 = a2;
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                break;
            default:
                result = v7 - 134;
                if (result <= 9) {
                    a1 = &off_1401238A4;
                    switch (result) {
                        case 4:
                            v_20 = 0;
                            a1 = rsp + 48;
                            sub_1400831E0(a1, ptr2, a4, 0);
                            a3 = (size_t *)v_30;
                            a1 = (int *)v_31;
                            a2 = (size_t *)v_32;
                            result = v_33;
                            if (a3 != 4) JUMPOUT(0x140084252);
                            return result;
                        case 6:
                            break;
                        default:
                            v_20 = 0;
                            a1 = rsp + 48;
                            sub_1400831E0(a1, ptr2, a4, 0);
                            a3 = (size_t *)v_30;
                            a1 = (int *)v_31;
                            a2 = (size_t *)v_32;
                            result = v_33;
                            if (a3 == 4) {
                                return result;
                            } else {
                                a4 = (struct Struct_1_t *)v_3c;
                                v_68 = (int)a4;
                                v6 = v_34;
                                v_60 = v6;
                                v5 = v_40;
                                v5 &= 15;
                                ptr->field_34 = a4;
                                ptr->field_2C = v6;
                                *(__int64 *)ptr = (__int64)(31);
                                ptr->field_28 = a3;
                                ptr->field_29 = a1;
                                ptr->field_2A = a2;
                                ptr->field_2B = result;
                                ptr->field_38 = 0;
                                ptr->field_3A = v5;
                                return v5;
                            }
                            return v5;
                    }
                }
                result = v7 - 144;
                if (result > 15) JUMPOUT(0x1400842a9);
                a1 = &off_1401238CC;
                result = v_0[result];
                result += (__int64)a1;
                JUMPOUT(result);
                *(__int64 *)ptr = (__int64)(55);
                return sub_14008435C();
        }
        return result;
    }
    return result;
}