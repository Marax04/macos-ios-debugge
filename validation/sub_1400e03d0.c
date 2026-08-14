// inferred from 4 accesses on `a4`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[4];
    __int64 field_1C; // offset 28
    char _pad_1C[8];
    int field_2C; // offset 44
    __int64 field_30; // offset 48
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
    char _pad_2[22];
    __int64 field_20; // offset 32
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    __int16 field_0; // offset 0
    int field_2; // offset 2
    char _pad_2[2];
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
};

// inferred from 5 accesses on `i`
struct Struct_4_t {
    char _pad_start[24];
    int field_18; // offset 24
    __int64 field_1C; // offset 28
    int field_24; // offset 36
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
};

// inferred from 3 accesses on `ptr2`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr3`
struct Struct_6_t {
    __int16 field_0; // offset 0
    int field_2; // offset 2
    char _pad_2[2];
    __int64 field_8; // offset 8
};

__int64 sub_1400E3F00();
__int64 sub_1400E4180();
__int64 sub_14002EDF0();
__int64 sub_1400D5BD0();
__int64 sub_1400F27F0();
__int64 sub_1400E43D0();
__int64 sub_1400E4530();
__int64 sub_1400FAE80();
__int64 sub_1400F2D20();
__int64 sub_1400E4630();
__int64 sub_1400E4040();
extern __int64 off_1401249F0;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400E03D0(size_t *a1, int *a2, int a3,struct Struct_1_t *a4) {
    __int64 rsp;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    int v_5f;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    __int64 v_80;
    struct Struct_3_t *ptr;
    struct Struct_5_t *ptr2;
    __int64 v6;
    struct Struct_4_t *i;
    struct Struct_2_t *result;
    __int64 v5;
    struct Struct_6_t *ptr3;
    __int64 v8;
    __int64 v9;

    ptr = (struct Struct_3_t *)a3;
    ptr2 = (struct Struct_5_t *)a2;
    v6 = (__int64)a1;
    v_5f = a3;
    v_60 = 0;
    v_68 = 8;
    v_70 = 0;
    i = (struct Struct_4_t *)a3;
    result = i - 16;
    if (result <= 177) {
        a1 = &off_1401249F0;
        switch ((__int64)result) {
            case 0:
                i = (struct Struct_4_t *)a4;
                sub_1400E3F00(ptr2, 0);
                a3 = a4->field_1C;
                a1 = (size_t *)ptr2;
                a2 = 0;
                return (__int64)a2;
            case 1:
                a2 = a4->field_10;
                ptr = (struct Struct_3_t *)a4;
                sub_1400E4180(ptr2, a2, 0);
                i = (struct Struct_4_t *)ptr;
                ptr = ptr->field_18;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8B48);
                v_38 = 2;
                v_20 = (__int64)ptr;
                a1 = rsp + 40;
                sub_1400D5BD0(a1, 1, 0, 3);
                v5 = v_28;
                ptr = (struct Struct_3_t *)v_30;
                ptr3 = (struct Struct_6_t *)v_38;
                result = ptr2->field_0;
                v8 = ptr2->field_10;
                result -= v8;
                if (ptr3 > result) JUMPOUT(0x1400e3589);
                a1 = ptr2->field_8;
                a1 += v8;
                sub_1400F27F0(a1, ptr, ptr3);
                v8 += (__int64)ptr3;
                ptr2->field_10 = v8;
                if (v5 != 0) {
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, ptr);
                }
                a3 = i->field_1C;
                a1 = (size_t *)ptr2;
                a2 = 1;
                return (__int64)a2;
            case 2:
                a2 = a4->field_10;
                i = (struct Struct_4_t *)a4;
                sub_1400E4180(ptr2, a2, 0);
                a3 = i->field_1C;
                sub_1400E43D0(ptr2, 1, a3);
                i = i->field_18;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8948);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                a2 = 1;
                a3 = 0;
                return a3;
            case 4:
                ptr = a4->field_1C;
                sub_1400E43D0(ptr2, 0, ptr);
                sub_1400E43D0(ptr2, 1, ptr);
                return (__int64)ptr;
            case 16:
                a2 = a4->field_10;
                i = (struct Struct_4_t *)a4;
                sub_1400E4180(ptr2, a2, 1);
                sub_1400E3F00(ptr2, 0);
                i = i->field_18;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8948);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                a2 = 0;
                return (__int64)a2;
            case 17:
                ptr = a4->field_10;
                i = (struct Struct_4_t *)a4;
                sub_1400E4180(ptr2, ptr, 1);
                sub_1400E4180(ptr2, ptr, 0);
                i = i->field_18;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8B48);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                sub_1400D5BD0(a1, 1, 0, 3);
                v5 = v_28;
                ptr = (struct Struct_3_t *)v_30;
                ptr3 = (struct Struct_6_t *)v_38;
                result = ptr2->field_0;
                v8 = ptr2->field_10;
                result -= v8;
                if (ptr3 > result) JUMPOUT(0x1400e35af);
                a1 = ptr2->field_8;
                a1 += v8;
                sub_1400F27F0(a1, ptr, ptr3);
                v8 += (__int64)ptr3;
                ptr2->field_10 = v8;
                if (v5 != 0) {
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, ptr);
                }
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8948);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                return (__int64)a1;
            case 54:
                ptr = a4->field_10;
                i = (struct Struct_4_t *)a4;
                sub_1400E4180(ptr2, ptr, 1);
                sub_1400E4180(ptr2, ptr, 0);
                i = i->field_18;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8B48);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                sub_1400D5BD0(a1, 1, 0, 3);
                v5 = v_28;
                ptr = (struct Struct_3_t *)v_30;
                ptr3 = (struct Struct_6_t *)v_38;
                result = ptr2->field_0;
                v8 = ptr2->field_10;
                result -= v8;
                if (ptr3 > result) JUMPOUT(0x1400e3563);
                a1 = ptr2->field_8;
                a1 += v8;
                sub_1400F27F0(a1, ptr, ptr3);
                v8 += (__int64)ptr3;
                ptr2->field_10 = v8;
                if (v5 != 0) {
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, ptr);
                }
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8B48);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                sub_1400D5BD0(a1, 6, 3, 3);
                v5 = v_28;
                ptr = (struct Struct_3_t *)v_30;
                ptr3 = (struct Struct_6_t *)v_38;
                result = ptr2->field_0;
                v8 = ptr2->field_10;
                result -= v8;
                if (ptr3 > result) JUMPOUT(0x1400e36ee);
                a1 = ptr2->field_8;
                a1 += v8;
                sub_1400F27F0(a1, ptr, ptr3);
                v8 += (__int64)ptr3;
                ptr2->field_10 = v8;
                if (v5 != 0) {
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, ptr);
                }
                result = (struct Struct_2_t *)i;
                if (i != i) {
                    return (__int64)result;
                } else {
                    result = ptr2->field_0;
                    a2 = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 4) JUMPOUT(0x1400e38ee);
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x24548B48;
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = i;
                    a2 += 5;
                    ptr2->field_10 = a2;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) JUMPOUT(0x1400e3914);
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 210;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x8548;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 3) JUMPOUT(0x1400e393a);
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0xF1450F48;
                    a2 += 4;
                    ptr2->field_10 = a2;
                    sub_14002EDF0(0, 8);
                    if (result == 0) JUMPOUT(0x1400e3e28);
                    v_28 = 8;
                    v_30 = (__int64)result;
                    *(__int64 *)result = (__int64)(0x8948);
                    v_38 = 2;
                    v_20 = (__int64)i;
                    a1 = rsp + 40;
                    a2 = 6;
                    return (__int64)a2;
                }
                return (__int64)a2;
            case 67:
                i = (struct Struct_4_t *)a4;
                sub_1400E4530(ptr2, 3);
                i = i->field_28;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x894E);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                sub_1400D5BD0(a1, 6, 4, 3);
                i = (struct Struct_4_t *)v_28;
                ptr3 = (struct Struct_6_t *)v_30;
                v8 = v_38;
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (v8 > result) JUMPOUT(0x1400e35d5);
                a1 = ptr2->field_8;
                a1 = (size_t *)((__int64)a1 + (__int64)ptr);
                sub_1400F27F0(a1, ptr3, v8);
                ptr += v8;
                ptr2->field_10 = ptr;
                if (i != 0) {
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, ptr3);
                    ptr = ptr2->field_10;
                }
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e35fb);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 196;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0xFF49;
                ptr += 3;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e3624);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 222;
                *(__int64 *)((__int64)result + (__int64)ptr) = 329;
                ptr += 3;
                ptr2->field_10 = ptr;
                break;
            case 68:
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e3b8a);
                i = (struct Struct_4_t *)a4;
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 228;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x854D;
                ptr += 3;
                ptr2->field_10 = ptr;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr);
                result = (struct Struct_2_t *)ptr;
                if (a1 <= 5) JUMPOUT(0x1400e3bb9);
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
                *(__int64 *)((__int64)a1 + (__int64)result) = 0x840F;
                result += 6;
                ptr2->field_10 = result;
                a1 = rsp + 96;
                sub_1400FAE80(a1);
                result = (struct Struct_2_t *)v_68;
                *(__int64 *)result = (__int64)(ptr);
                v_70 = 1;
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) JUMPOUT(0x1400e3be2);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 204;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xFF49;
                a2 += 3;
                ptr2->field_10 = a2;
                i = i->field_28;
                sub_14002EDF0(0, 8);
                if (result == 0) JUMPOUT(0x1400e3e28);
                v_28 = 8;
                v_30 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8B4E);
                v_38 = 2;
                v_20 = (__int64)i;
                a1 = rsp + 40;
                a2 = 6;
                sub_1400D5BD0(a1, 1, 3, 3);
                i = (struct Struct_4_t *)v_28;
                ptr = (struct Struct_3_t *)v_30;
                ptr3 = (struct Struct_6_t *)v_38;
                result = ptr2->field_0;
                v8 = ptr2->field_10;
                result -= v8;
                if (ptr3 > result) {
                    return (__int64)result;
                }
                return (__int64)result;
            case 112:
                sub_1400E3F00(ptr2, 0);
                break;
            case 128:
                a3 = a4->field_1C;
                sub_1400E43D0(ptr2, 0, a3);
                sub_14002EDF0(0, 7);
                if (result == 0) JUMPOUT(0x1400e3ea8);
                ptr = (struct Struct_3_t *)result;
                *(__int64 *)result = (__int64)(0x8C68349);
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) JUMPOUT(0x1400e353d);
                result = ptr2->field_8;
                a1 = ptr->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 4;
                ptr2->field_10 = a2;
                ((__int64 (*)())off_140108030)();
                ((__int64 (*)())off_140108038)(result, 0, ptr);
                break;
            case 129:
                i = a4->field_2C;
                result = a4->field_30;
                v_80 = (__int64)result;
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) JUMPOUT(0x1400e3459);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 0x37048B4F;
                a2 += 4;
                ptr2->field_10 = a2;
                sub_14002EDF0(0, 7);
                if (result == 0) JUMPOUT(0x1400e3ea8);
                ptr = (struct Struct_3_t *)result;
                *(__int64 *)result = (__int64)(0x8C68349);
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) JUMPOUT(0x1400e364d);
                result = ptr2->field_8;
                a1 = ptr->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 4;
                ptr2->field_10 = a2;
                ((__int64 (*)())off_140108030)(a1, a2);
                ((__int64 (*)())off_140108038)(result, 0, ptr);
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e3673);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 241;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x894D;
                ptr += 3;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 3) JUMPOUT(0x1400e369c);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x248C894C;
                ptr += 4;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 3) JUMPOUT(0x1400e36c5);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = i;
                ptr += 4;
                ptr2->field_10 = ptr;
                sub_14002EDF0(0, 10);
                if (result == 0) JUMPOUT(0x1400e3a6a);
                ptr3 = (struct Struct_6_t *)result;
                *(__int64 *)result = (__int64)(0xBE48);
                result = 0x9E3779B97F4A7C15;
                ptr3->field_2 = result;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 9) JUMPOUT(0x1400e3714);
                result = ptr2->field_8;
                a1 = ptr3->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                a1 = ptr3->field_0;
                *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                ptr += 10;
                ptr2->field_10 = ptr;
                ((__int64 (*)())off_140108030)(a1);
                ((__int64 (*)())off_140108038)(result, 0, ptr3);
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e373d);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 192;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x894C;
                ptr += 3;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 3) JUMPOUT(0x1400e3766);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0xC6AF0F48;
                ptr += 4;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                v_78 = v6;
                if (result <= 2) JUMPOUT(0x1400e378f);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 194;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x8949;
                ptr += 3;
                ptr2->field_10 = ptr;
                result = 1;
                v5 = 0;
                v9 = off_140108030;
                v6 = off_140108038;
                i = 0;
                do {
                    v8 = (__int64)result;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr, 3, 1);
                    ptr = ptr2->field_10;
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 192;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x894C;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    sub_14002EDF0(0, 10);
                    if (result == 0) JUMPOUT(0x1400e3a6a);
                    ptr3 = (struct Struct_6_t *)result;
                    *(__int64 *)result = (__int64)(0xBE48);
                    result = 0x736F6D6570736575;
                    ptr3->field_2 = result;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 9) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 10, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    a1 = ptr3->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                    ptr += 10;
                    ptr2->field_10 = ptr;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr3);
                    result = ptr2->field_0;
                    ptr = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 240;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 209;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x894C;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    sub_14002EDF0(0, 10);
                    if (result == 0) JUMPOUT(0x1400e3a6a);
                    ptr3 = (struct Struct_6_t *)result;
                    *(__int64 *)result = (__int64)(0xBE48);
                    result = 0x646F72616E646F6D;
                    ptr3->field_2 = result;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 9) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 10, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    a1 = ptr3->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                    ptr += 10;
                    ptr2->field_10 = ptr;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr3);
                    result = ptr2->field_0;
                    ptr = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 241;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 194;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x894C;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    sub_14002EDF0(0, 10);
                    if (result == 0) JUMPOUT(0x1400e3a6a);
                    ptr3 = (struct Struct_6_t *)result;
                    *(__int64 *)result = (__int64)(0xBE48);
                    result = 0x6C7967656E657261;
                    ptr3->field_2 = result;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 9) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 10, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    a1 = ptr3->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                    ptr += 10;
                    ptr2->field_10 = ptr;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr3);
                    result = ptr2->field_0;
                    ptr = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 242;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 211;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x894C;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    sub_14002EDF0(0, 10);
                    if (result == 0) JUMPOUT(0x1400e3a6a);
                    ptr3 = (struct Struct_6_t *)result;
                    *(__int64 *)result = (__int64)(0xBE48);
                    result = 0x7465646279746573;
                    ptr3->field_2 = result;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 9) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 10, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    a1 = ptr3->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                    ptr += 10;
                    ptr2->field_10 = ptr;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr3);
                    result = ptr2->field_0;
                    a2 = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 243;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 206;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x894C;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 243;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    sub_1400E4630(ptr2, a2);
                    sub_1400E4630(ptr2);
                    result = ptr2->field_0;
                    ptr = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 240;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    sub_14002EDF0(0, 10);
                    if (result == 0) JUMPOUT(0x1400e3a6a);
                    ptr3 = (struct Struct_6_t *)result;
                    *(__int64 *)result = (__int64)(0xBE48);
                    result->field_2 = i;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 9) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 10, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    a1 = ptr3->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                    ptr += 10;
                    ptr2->field_10 = ptr;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr3);
                    result = ptr2->field_0;
                    a2 = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 243;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    sub_1400E4630(ptr2, a2);
                    sub_1400E4630(ptr2);
                    result = ptr2->field_0;
                    ptr = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 240;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    sub_14002EDF0(0, 10);
                    if (result == 0) JUMPOUT(0x1400e3a6a);
                    ptr3 = (struct Struct_6_t *)result;
                    *(__int64 *)result = (__int64)(0xBE48);
                    result = 0x1000000000000000;
                    ptr3->field_2 = result;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 9) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 10, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    a1 = ptr3->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 8) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                    ptr += 10;
                    ptr2->field_10 = ptr;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v6)(result, 0, ptr3);
                    result = ptr2->field_0;
                    a2 = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 243;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    sub_1400E4630(ptr2, a2);
                    sub_1400E4630(ptr2);
                    result = ptr2->field_0;
                    a2 = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 240;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                    a2 += 3;
                    ptr2->field_10 = a2;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                    if (result <= 6) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 7, 1);
                        a2 = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)a2 + 3) = 255;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0xFFF28148;
                    a2 += 7;
                    ptr2->field_10 = a2;
                    sub_1400E4630(ptr2, a2);
                    sub_1400E4630(ptr2);
                    sub_1400E4630(ptr2);
                    sub_1400E4630(ptr2);
                    result = ptr2->field_0;
                    ptr = ptr2->field_10;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 200;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 208;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 216;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 3) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 4, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x24848948;
                    ptr += 4;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 3) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 4, 1);
                        ptr = ptr2->field_10;
                    }
                    result = (struct Struct_2_t *)v_80;
                    result += (__int64)(__int64)i*8;
                    a1 = ptr2->field_8;
                    *(__int64 *)((__int64)a1 + (__int64)ptr) = result;
                    ptr += 4;
                    ptr2->field_10 = ptr;
                    result = 2;
                    i = (struct Struct_4_t *)v8;
                    v5 = 1;
                } while (((v5 & 1) == 0));
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e37b8);
                v6 = v_78;
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 254;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x894C;
                ptr += 3;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e37e1);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 206;
                *(__int64 *)((__int64)result + (__int64)ptr) = 332;
                ptr += 3;
                ptr2->field_10 = ptr;
                i = 0;
                do {
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr, 3, 1);
                    ptr = ptr2->field_10;
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 36;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x848A;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 3) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 4, 1);
                        ptr = ptr2->field_10;
                    }
                    result = (struct Struct_2_t *)v_80;
                    result = (struct Struct_2_t *)((__int64)result + (__int64)i);
                    a1 = ptr2->field_8;
                    *(__int64 *)((__int64)a1 + (__int64)ptr) = result;
                    ptr += 4;
                    ptr2->field_10 = ptr;
                    result = ptr2->field_0;
                    result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                    if (result <= 2) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, ptr, 3, 1);
                        ptr = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)ptr) = 0x4630;
                    *(__int64 *)((__int64)result + (__int64)ptr + 2) = i;
                    ptr += 3;
                    ptr2->field_10 = ptr;
                    ++i;
                } while (i != 16);
                break;
            case 160:
                ptr = a4->field_1C;
                sub_1400E43D0(ptr2, 1, ptr);
                sub_1400E43D0(ptr2, 2, ptr);
                sub_1400E43D0(ptr2, 0, ptr);
                a1 = (size_t *)ptr2;
                a2 = 2;
                return (__int64)a2;
            case 161:
                ptr = a4->field_1C;
                sub_1400E43D0(ptr2, 1, ptr);
                sub_1400E43D0(ptr2, 0, ptr);
                sub_1400E4040(ptr2, 0, ptr);
                sub_1400E4040(ptr2, 1, ptr);
                return (__int64)ptr;
            case 162:
                ptr = a4->field_1C;
                sub_1400E43D0(ptr2, 1, ptr);
                sub_1400E43D0(ptr2, 0, ptr);
                sub_1400E4040(ptr2, 1, ptr);
                sub_1400E4040(ptr2, 0, ptr);
                return (__int64)ptr;
            case 163:
                ptr = a4->field_1C;
                sub_1400E43D0(ptr2, 1, ptr);
                sub_1400E43D0(ptr2, 0, ptr);
                a1 = (size_t *)ptr2;
                a2 = 1;
                sub_1400E4040(ptr2, 0, ptr);
                break;
            case 176:
                sub_1400E3F00(ptr2, 1, 4);
                sub_14002EDF0(0, 10);
                if (result == 0) JUMPOUT(0x1400e3a6a);
                ptr = (struct Struct_3_t *)result;
                *(__int64 *)result = (__int64)(0xB848);
                result = 0xCBF29CE484222325;
                ptr->field_2 = result;
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 9) JUMPOUT(0x1400e3c08);
                result = ptr2->field_8;
                a1 = ptr->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                a1 = ptr->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 10;
                ptr2->field_10 = a2;
                ((__int64 (*)())off_140108030)(a1, a2);
                ((__int64 (*)())off_140108038)(result, 0, ptr);
                sub_14002EDF0(0, 10);
                if (result == 0) JUMPOUT(0x1400e3a6a);
                ptr = (struct Struct_3_t *)result;
                *(__int64 *)result = (__int64)(0xBE48);
                result = 0x100000001B3;
                ptr->field_2 = result;
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 9) JUMPOUT(0x1400e3c2e);
                result = ptr2->field_8;
                a1 = ptr->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 8) = a1;
                a1 = ptr->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 10;
                ptr2->field_10 = a2;
                ((__int64 (*)())off_140108030)(a1, a2);
                ((__int64 (*)())off_140108038)(result, 0, ptr);
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) JUMPOUT(0x1400e3c54);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 242;
                *(__int64 *)((__int64)result + (__int64)a2) = 0x894C;
                a2 += 3;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) JUMPOUT(0x1400e3c7a);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 243;
                *(__int64 *)((__int64)result + (__int64)a2) = 0x894C;
                a2 += 3;
                ptr2->field_10 = a2;
                sub_14002EDF0(0, 7);
                if (result == 0) JUMPOUT(0x1400e3ea8);
                ptr = (struct Struct_3_t *)result;
                *(__int64 *)result = (__int64)(0x20C38348);
                result = ptr2->field_0;
                a2 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) JUMPOUT(0x1400e3ca0);
                result = ptr2->field_8;
                a1 = ptr->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 4;
                ptr2->field_10 = a2;
                ((__int64 (*)())off_140108030)(a1, a2);
                ((__int64 (*)())off_140108038)(result, 0, ptr);
                result = ptr2->field_0;
                ptr3 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr3);
                ptr = (struct Struct_3_t *)ptr3;
                if (result <= 2) JUMPOUT(0x1400e3cc6);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 218;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x3948;
                a2 = ptr + 3;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 1) JUMPOUT(0x1400e3cef);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 115;
                a2 += 2;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 4) JUMPOUT(0x1400e3d15);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 4) = 23;
                *(__int64 *)((__int64)result + (__int64)a2) = 0x3CB60F41;
                a2 += 5;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) JUMPOUT(0x1400e3d3b);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 248;
                *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
                a2 += 3;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) JUMPOUT(0x1400e3d61);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xC6AF0F48;
                a2 += 4;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) JUMPOUT(0x1400e3d87);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 194;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xFF48;
                result = a2 + 3;
                ptr2->field_10 = result;
                a2 += 5;
                if ((a2 < 0)) JUMPOUT(0x1400e3e7f);
                ptr3 = (struct Struct_6_t *)((__int64)ptr3 - (__int64)a2);
                a1 = (size_t *)ptr3;
                if (ptr3 != ptr3) JUMPOUT(0x1400e3dad);
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)result);
                if (a1 <= 1) JUMPOUT(0x1400e3dd6);
                a1 = ptr2->field_8;
                ptr3 = (struct Struct_6_t *)((__int64)(__int64)ptr3 << 8);
                ptr3 = (struct Struct_6_t *)((__int64)(__int64)ptr3 | 235);
                *(__int64 *)((__int64)a1 + (__int64)result) = ptr3;
                result += 2;
                ptr2->field_10 = result;
                a2 = (int *)ptr;
                a2 += 5;
                if ((a2 < 0)) JUMPOUT(0x1400e3e7f);
                a1 = (size_t *)result;
                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                if (a1 != a1) JUMPOUT(0x1400e3dff);
                ptr += 4;
                if (ptr >= result) JUMPOUT(0x1400e3ee0);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = a1;
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                return (__int64)ptr;
            case 177:
                i = (struct Struct_4_t *)a4;
                sub_1400E3F00(ptr2, 1);
                result = ptr2->field_0;
                ptr = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 3) JUMPOUT(0x1400e3b38);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x24848B48;
                ptr += 4;
                ptr2->field_10 = ptr;
                i = i->field_38;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 3) JUMPOUT(0x1400e3b61);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr) = i;
                ptr += 4;
                ptr2->field_10 = ptr;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr);
                if (result <= 2) JUMPOUT(0x1400e3ae6);
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)ptr + 2) = 200;
                *(__int64 *)((__int64)result + (__int64)ptr) = 0x3948;
                ptr += 3;
                ptr2->field_10 = ptr;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr);
                result = (struct Struct_2_t *)ptr;
                if (a1 <= 5) JUMPOUT(0x1400e3b0f);
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
                *(__int64 *)((__int64)a1 + (__int64)result) = 0x850F;
                result += 6;
                ptr2->field_10 = result;
                a1 = rsp + 96;
                sub_1400FAE80(a1, a1);
                result = (struct Struct_2_t *)v_68;
                *(__int64 *)result = (__int64)(ptr);
                v_70 = 1;
                break;
            default:
                i = (struct Struct_4_t *)a4;
                sub_1400E4530(ptr2, 3);
                result = ptr2->field_0;
                ptr3 = ptr2->field_10;
                result = (struct Struct_2_t *)((__int64)result - (__int64)ptr3);
                if (result <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 4, 1);
                    ptr3 = ptr2->field_10;
                }
                result = (struct Struct_2_t *)i;
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = 0x248CB60F;
                ptr3 += 4;
                ptr2->field_10 = ptr3;
                v9 = i->field_24;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                if (a1 <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 4, 1);
                    result = (struct Struct_2_t *)i;
                    ptr3 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = v9;
                ptr3 += 4;
                ptr2->field_10 = ptr3;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                if (a1 <= 4) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 5, 1);
                    result = (struct Struct_2_t *)i;
                    ptr3 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3 + 4) = 0;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = 0xBB8;
                ptr3 += 5;
                ptr2->field_10 = ptr3;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                if (a1 <= 2) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 3, 1);
                    result = (struct Struct_2_t *)i;
                    ptr3 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3 + 2) = 10;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = 0xF983;
                ptr3 += 3;
                ptr2->field_10 = ptr3;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                if (a1 <= 2) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 3, 1);
                    result = (struct Struct_2_t *)i;
                    ptr3 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3 + 2) = 200;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = 0x470F;
                ptr3 += 3;
                ptr2->field_10 = ptr3;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                if (a1 <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 4, 1);
                    result = (struct Struct_2_t *)i;
                    ptr3 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = 0x2494B60F;
                ptr3 += 4;
                ptr2->field_10 = ptr3;
                v9 = result->field_20;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)ptr3);
                if (a1 <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, ptr3, 4, 1);
                    result = (struct Struct_2_t *)i;
                    ptr3 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)ptr3) = v9;
                a2 = ptr3 + 4;
                ptr2->field_10 = a2;
                a1 = ptr2->field_0;
                a1 = (size_t *)((__int64)a1 - (__int64)a2);
                if (a1 <= 2) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 3, 1);
                    result = (struct Struct_2_t *)i;
                    a2 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                *(__int64 *)((__int64)a1 + (__int64)a2 + 2) = 53;
                *(__int64 *)((__int64)a1 + (__int64)a2) = 0x8D48;
                a2 += 3;
                ptr2->field_10 = a2;
                i = result->field_0;
                if (i < 0) JUMPOUT(0x1400e3e7f);
                ptr3 += 11;
                if ((ptr3 < 0)) JUMPOUT(0x1400e3e7f);
                i = (struct Struct_4_t *)((__int64)i - (__int64)ptr3);
                result = (struct Struct_2_t *)i;
                if (i != i) JUMPOUT(0x1400e3eb7);
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 4, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = i;
                a2 += 4;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 3) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 4, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 0x4E04B70F;
                a2 += 4;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 2, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xD189;
                a2 += 2;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 2, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xE8D3;
                a2 += 2;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 3, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 1;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xE083;
                a2 += 3;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 2, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 0xC084;
                a2 += 2;
                ptr2->field_10 = a2;
                i = 0;
                i = (ptr == 81) ? 1 : 0;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                i = (struct Struct_4_t *)((__int64)(__int64)i ^ 885);
                if (result <= 1) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 2, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = i;
                a2 += 2;
                ptr2->field_10 = a2;
                result = ptr2->field_0;
                result = (struct Struct_2_t *)((__int64)result - (__int64)a2);
                if (result <= 2) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, a2, 3, 1);
                    a2 = ptr2->field_10;
                }
                result = ptr2->field_8;
                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 222;
                *(__int64 *)((__int64)result + (__int64)a2) = 329;
                a2 += 3;
                ptr2->field_10 = a2;
                break;
        }
        return (__int64)a2;
    }
    return (__int64)result;
}