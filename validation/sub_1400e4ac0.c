// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[20];
    __int64 field_34; // offset 52
};

__int64 sub_1400E6900();
__int64 sub_1400E4180();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F3869();
__int64 sub_1400D5BD0();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_1400E4530();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140124D1C;
extern __int64 off_14011D368;
extern __int64 off_140120C84;

__int64 __fastcall sub_1400E4AC0(size_t *a1, size_t a2, size_t a3) {
    __int64 rsp;
    int v_20;
    int v_38;
    __int64 v_40;
    int v_48;
    int *v_0;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v2;
    __int64 v5;
    __int64 v6;
    __int64 v7;

    ptr2 = (struct Struct_2_t *)a3;
    ptr = (struct Struct_1_t *)a1;
    result = (__int64 *)a2;
    result += 0xFFFFFF3E;
    a1 = &off_140124D1C;
    result = v_0[(__int64)result];
    result = (__int64 *)((__int64)result + (__int64)a1);
    JUMPOUT(result);
    sub_1400E6900(ptr, 3);
    a2 = ptr2->field_10;
    sub_1400E4180(ptr, a2, 0);
    v2 = ptr2->field_18;
    sub_14002EDF0(0, 8);
    if (result == 0) {
        sub_1400F3326(1, 8);
        a3 = &off_14011D368;
        sub_1400F3869(v6, result, a3);
        --a2;
        ptr2 = (struct Struct_2_t *)a2;
        result = 39;
        if ((a2 >= 0)) JUMPOUT(0x1400e6a93);
        ptr = (struct Struct_1_t *)a1;
        a1 =  + (__int64)(__int64)ptr2*8;
        v2 = 0x3400001C140C;
        v2 >>= (__int64)a1;
        a1 = ptr->field_0;
        a2 = ptr->field_10;
        result = (__int64 *)a1;
        result -= a2;
        if (result <= 4) JUMPOUT(0x1400e69f0);
        result = ptr->field_8;
        *(result + a2) = 0xF43;
        *(result + a2 + 2) = 182;
        *(result + a2 + 3) = v2;
        *(result + a2 + 4) = 55;
        a2 += 5;
        ptr->field_10 = a2;
        a1 -= a2;
        if (a1 <= 2) JUMPOUT(0x1400e6a19);
        *(result + a2 + 2) = 198;
        *(result + a2) = 0xFF49;
        a2 += 3;
        ptr->field_10 = a2;
        a1 = 39;
        if ((a2 >= 0)) JUMPOUT(0x1400e6aca);
        a1 = &off_140120C84;
        ptr2 = v_0[(__int64)ptr2];
        a1 = ptr->field_0;
        a1 -= a2;
        if (a1 <= 3) JUMPOUT(0x1400e6a43);
        a1 = (size_t *)ptr2;
        a1 = (size_t *)((__int64)(__int64)a1 | 0xF008348);
        *(result + a2) = a1;
        a2 += 4;
        ptr->field_10 = a2;
        result = ptr->field_0;
        result -= a2;
        if (result <= 3) JUMPOUT(0x1400e6a6d);
        result = ptr->field_8;
        ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 | 0x400C148);
        *(result + a2) = ptr2;
        a2 += 4;
        ptr->field_10 = a2;
        return a2;
    } else {
        v_38 = 8;
        v_40 = (__int64)result;
        *result = 0x8B48;
        v_48 = 2;
        v_20 = v2;
        a1 = rsp + 56;
        sub_1400D5BD0(a1, 2, 0, 3);
        v5 = v_38;
        v2 = v_40;
        v6 = v_48;
        result = ptr->field_0;
        v7 = ptr->field_10;
        result -= v7;
        if (v6 > result) {
            v_20 = 1;
            sub_1400F2D20(ptr, v7, v6, 1);
            v7 = ptr->field_10;
        }
        a1 = ptr->field_8;
        a1 += v7;
        sub_1400F27F0(a1, v2, v6);
        v7 += v6;
        ptr->field_10 = v7;
        if (v5 != 0) {
            off_140108030();
            off_140108038(result, 0, v2);
        }
        sub_1400E4530(ptr, 1);
        result = ptr->field_0;
        a2 = ptr->field_10;
        result -= a2;
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr, a2, 3, 1);
            a2 = ptr->field_10;
        }
        result = ptr->field_8;
        *(result + a2 + 2) = 202;
        *(result + a2) = 328;
        a2 += 3;
        ptr->field_10 = a2;
        result = ptr->field_0;
        result -= a2;
        if (result <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr, a2, 4, 1);
            a2 = ptr->field_10;
        }
        result = ptr->field_8;
        *(result + a2) = 0x26F0FF3;
        a2 += 4;
        ptr->field_10 = a2;
        ptr2 = ptr2->field_34;
        result = ptr->field_0;
        a1 = (size_t *)result;
        a1 -= a2;
        if (a1 <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr, a2, 5, 1);
            result = ptr->field_0;
            a2 = ptr->field_10;
        }
        a1 = ptr->field_8;
        *(a1 + a2) = 0x847F0FF3;
        *(a1 + a2 + 4) = 28;
        a2 += 5;
        ptr->field_10 = a2;
        result -= a2;
        if (result <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr, a2, 4, 1);
            a1 = ptr->field_8;
            a2 = ptr->field_10;
        }
        *(a1 + a2) = ptr2;
        a2 += 4;
        ptr->field_10 = a2;
        return (__int64)result;
    }
}