// inferred from 11 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    char _pad_50[32];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    char _pad_80[8];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140045A80();
__int64 sub_140045D80();
__int64 sub_1400F27F0();
__int64 sub_140046040();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400462A0(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v6;
    struct Struct_2_t *ptr2;
    __int64 v5;
    __int64 result;
    __int64 v9;
    __int64 v7;
    __int64 v2;
    __int64 v8;

    ptr = (struct Struct_1_t *)a1;
    v6 = *a1;
    a1 = v6 - 8;
    if (a1 >= 1) v6 = a1;
    if (v6 != 0) {
        if (v6 == 1) {
            a1 = (__int64 *)ptr;
            return sub_140045A80();
        } else {
            if (v6 != 2) {
                ptr2 = ptr->field_28;
                a2 = ptr->field_30;
                sub_140045D80(ptr2, a2);
                if (ptr->field_20 != 0) {
                    off_140108030();
                    a1 = (__int64 *)v6;
                    v5 = (__int64)ptr2;
                    JUMPOUT(off_140108038);
                    ptr = (struct Struct_1_t *)v5;
                    ptr2 = (struct Struct_2_t *)a1;
                    result = *a1;
                    v9 = a1[2];
                    result -= v9;
                    if (v5 > result) JUMPOUT(0x140046410);
                    a1 = ptr2->field_8;
                    a1 += v9;
                    sub_1400F27F0(a1, 0, ptr);
                    v9 += (__int64)ptr;
                    ptr2->field_10 = v9;
                    result = 0;
                    return result;
                }
            } else {
                v7 = ptr->field_78;
                v2 = 0x8000000000000003;
                if (v7 != v2) {
                    if (v7 > 0) {
                        ptr2 = ptr->field_80;
                        off_140108030(a1);
                        ((__int64 (*)())off_140108038)(v7, 0, ptr2);
                    }
                }
                v8 = ptr->field_90;
                if (v8 != v2) {
                    if (v8 > 0) {
                        ptr2 = ptr->field_98;
                        off_140108030();
                        ((__int64 (*)())off_140108038)(v8, 0, ptr2);
                    }
                }
                v6 = ptr->field_50;
                if (v6 != 0) {
                    ptr2 = ptr->field_48;
                    v6 =  + v6*8 + 23;
                    v6 &= -16;
                    ptr2 -= v6;
                    off_140108030();
                    ((__int64 (*)())off_140108038)(v6, 0, ptr2);
                }
                ptr2 = ptr->field_38;
                a2 = ptr->field_40;
                sub_140046040(ptr2, a2);
                if (ptr->field_30 != 0) {
                    return a2;
                }
            }
        }
    }
    return result;
}