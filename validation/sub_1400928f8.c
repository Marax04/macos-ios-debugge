// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    char field_8; // offset 8
    __int64 field_9; // offset 9
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[40];
    __int64 field_28; // offset 40
    char _pad_28[16];
    __int64 field_40; // offset 64
};

// inferred from 44 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[10];
    int field_A; // offset 10
    char _pad_A[2];
    __int64 field_10; // offset 16
    char field_18; // offset 24
    __int64 field_19; // offset 25
    char _pad_19[15];
    __int64 field_30; // offset 48
    char field_38; // offset 56
    char field_39; // offset 57
    int field_3A; // offset 58
    char _pad_3A[2];
    __int64 field_40; // offset 64
    char field_48; // offset 72
    __int64 field_49; // offset 73
    char _pad_49[15];
    __int64 field_60; // offset 96
    char field_68; // offset 104
    __int64 field_69; // offset 105
    char _pad_69[7];
    char field_78; // offset 120
    __int64 field_79; // offset 121
    char _pad_79[7];
    char field_88; // offset 136
    char field_89; // offset 137
    int field_8A; // offset 138
    char _pad_8A[2];
    __int64 field_90; // offset 144
    char field_98; // offset 152
    __int64 field_99; // offset 153
    char _pad_99[7];
    char field_A8; // offset 168
    __int64 field_A9; // offset 169
    char _pad_A9[15];
    __int64 field_C0; // offset 192
    char field_C8; // offset 200
    char field_C9; // offset 201
    int field_CA; // offset 202
    char _pad_CA[2];
    __int64 field_D0; // offset 208
    char field_D8; // offset 216
    char field_D9; // offset 217
    int field_DA; // offset 218
    char _pad_DA[2];
    __int64 field_E0; // offset 224
    char field_E8; // offset 232
    char field_E9; // offset 233
    int field_EA; // offset 234
    char _pad_EA[2];
    __int64 field_F0; // offset 240
    char field_F8; // offset 248
    __int64 field_F9; // offset 249
    char _pad_F9[7];
    char field_108; // offset 264
    __int64 field_109; // offset 265
    char _pad_109[7];
    char field_118; // offset 280
    char field_119; // offset 281
    __int64 field_11A; // offset 282
};

__int64 sub_1400FAE10();
__int64 sub_140094CC0();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3869();
__int64 sub_1400F3C10();
__int64 sub_140095C90();
__int64 sub_1400940E0();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_140090414();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140119068;

__int64 __fastcall sub_1400928F8(size_t *a1, size_t *a2, size_t a3, size_t a4) {
    __int64 rsp;
    int v_108;
    int v_10e;
    int v_118;
    int v_11e;
    int v_128;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_70;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_c0;
    int v_cc;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    int v_f0;
    int v_f8;
    __int64 v10;
    __int64 v7;
    __int64 v9;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v5;
    struct Struct_3_t *ptr3;
    __int64 v6;
    __int64 v11;
    struct Struct_2_t *ptr2;
    __int64 v2;

    *(a1 + (__int64)(__int64)a1*4 - 6) = *(a1 + (__int64)(__int64)a1*4 - 6) + a1;
    v10 = (__int64)ptr;
    if (v3 == v9) {
        a1 = rsp + 144;
        sub_1400FAE10(a1);
        a2 = (size_t *)v_98;
    }
    *(a2 + v7 + 3) = v10;
    v7 += 4;
    v9 = (__int64)a2;
    sub_140094CC0(ptr2, a2, v7);
    v3 = (__int64)ptr;
    sub_14002EDF0(0, 288);
    if (ptr == 0) {
        sub_1400F3340(8, 288, v2);
        a3 = &off_140119068;
        sub_1400F3869(v11, v11, a3);
        sub_1400F3C10();
        a2 = (size_t *)v_f8;
        sub_140095C90(v7, a2);
        v_80 = v3;
        v_128 = v7;
        a1 = 0xAAAAAAAAAAAAAAAB;
        ptr = (struct Struct_1_t *)v_f8;
        ptr = (struct Struct_1_t *)((__int64)(__int64)(__int64)ptr * (__int64)a1); /* unsigned; high half in a2 */;
        a2 = (size_t *)((__int64)(__int64)a2 >> 1);
        ptr = 2;
        if (a2 >= 3) ptr = a2;
        v3 = 8;
        if (ptr < 8) v3 = ptr;
        v7 =  + v3*8;
        sub_14002EDF0(0, v7);
        if (ptr == 0) JUMPOUT(0x140094c76);
        v_40 = v3;
        v_48 = (__int64)ptr;
        v_50 = 0;
        v10 = 1;
        a1 = 0;
        v7 = 0;
        a4 = v_c0;
        v5 = v_38;
        a2 = (size_t *)v3;
        v_f0 = v3;
        return sub_1400940E0();
    } else {
        ptr3 = (struct Struct_3_t *)ptr;
        *(__int64 *)ptr = (__int64)(a3);
        a2 = (size_t *)v_88;
        ptr->field_8 = a2;
        v6 = v_30;
        ptr->field_9 = v6;
        ptr = (struct Struct_1_t *)v_108;
        a1 = (size_t *)v_10e;
        ptr3->field_A = ptr;
        ptr3->field_10 = a1;
        ptr3->field_18 = 1;
        ptr3->field_19 = v11;
        ptr3->field_30 = a3;
        v5 = v_28;
        ptr3->field_38 = v5;
        a4 = v_38;
        ptr3->field_39 = a4;
        ptr = (struct Struct_1_t *)v_118;
        a1 = (size_t *)v_11e;
        ptr3->field_3A = ptr;
        ptr3->field_40 = a1;
        ptr3->field_48 = 1;
        a1 = (size_t *)v_128;
        ptr3->field_49 = a1;
        ptr = 0x8000000000000001;
        ptr3->field_60 = ptr;
        v7 = v11;
        v11 = (__int64)ptr;
        ptr3->field_68 = 0;
        ptr3->field_69 = v7;
        ptr3->field_78 = 0;
        ptr3->field_79 = a1;
        ptr = (struct Struct_1_t *)v_cc;
        ptr3->field_88 = ptr;
        ptr3->field_89 = 7;
        v7 = v_d0;
        ptr3->field_8A = v7;
        ptr3->field_90 = a3;
        ptr3->field_98 = 0;
        ptr3->field_99 = ptr;
        ptr3->field_A8 = 1;
        ptr3->field_A9 = v10;
        ptr3->field_C0 = v11;
        ptr3->field_C8 = a2;
        ptr3->field_C9 = v6;
        ptr = (struct Struct_1_t *)v_108;
        a1 = (size_t *)v_10e;
        ptr3->field_D0 = a1;
        ptr3->field_CA = ptr;
        ptr3->field_D8 = v5;
        ptr3->field_D9 = a4;
        ptr = (struct Struct_1_t *)v_118;
        a1 = (size_t *)v_11e;
        ptr3->field_DA = ptr;
        ptr3->field_E0 = a1;
        ptr3->field_E8 = v3;
        ptr3->field_E9 = 7;
        ptr3->field_EA = v7;
        ptr3->field_F0 = v11;
        ptr3->field_F8 = 0;
        ptr3->field_F9 = v10;
        ptr3->field_108 = 0;
        ptr3->field_109 = v3;
        ptr = (struct Struct_1_t *)v_70;
        ptr3->field_118 = ptr;
        ptr3->field_119 = 1;
        ptr3->field_11A = v7;
        v3 = 6;
        if (v_90 != 0) {
            off_140108030(a1, a2, 0x8000000000000002, a4);
            off_140108038(ptr, 0, v9);
        }
        v10 = 1;
        ptr = (struct Struct_1_t *)v_d8;
        v11 = v_e8;
        ptr -= v11;
        if (v3 > ptr) {
            v_20 = 48;
            a1 = rsp + 216;
            sub_1400F2D20(a1, v11, v3, 8);
            v11 = v_e8;
        }
        ptr = (struct Struct_1_t *)v3;
        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 4);
        a3 = ptr + (__int64)(__int64)ptr*2;
        v9 = v_e0;
        a1 =  + v11*2;
        a1 += v11;
        a1 = (size_t *)((__int64)(__int64)a1 << 4);
        a1 += v9;
        sub_1400F27F0(a1, ptr3, a3);
        v11 += v3;
        v_e8 = v11;
        off_140108030();
        off_140108038(ptr, 0, ptr3);
        if (v10 != 0) {
            ptr2->field_40 = ptr2->field_40 + 1;
            ptr2->field_28 = ptr2->field_28 + 1;
        }
        v10 = 0x8000000000000000;
        v6 = 0xE38E38E38E38E38F;
        if ((v_40 - 0) < 0) JUMPOUT(0x140090414);
        if (v_40 != 0) {
            v3 = v_48;
            off_140108030();
            off_140108038(ptr, 0, v3);
            v6 = 0xE38E38E38E38E38F;
        }
        if (v_58 == 0) JUMPOUT(0x140090414);
        v3 = v_60;
        off_140108030();
        off_140108038(ptr, 0, v3);
        v6 = 0xE38E38E38E38E38F;
        return sub_140090414();
    }
}