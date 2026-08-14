// inferred from 10 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[40];
    __int64 field_68; // offset 104
    char _pad_68[8];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    char _pad_80[8];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 sub_140046190();
__int64 sub_140053180();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400640F0(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    __int64 v8;
    __int64 result;
    __int64 v10;
    __int64 v9;
    __int64 v5;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    if (a1[12] > 0) {
        v4 = ptr->field_68;
        off_140108030();
        ((__int64 (*)())off_140108038)(v6, 0, v4);
    }
    v7 = ptr->field_78;
    v2 = 0x8000000000000003;
    if (v7 != v2) {
        if (v7 > 0) {
            v4 = ptr->field_80;
            off_140108030();
            ((__int64 (*)())off_140108038)(v7, 0, v4);
        }
    }
    v8 = ptr->field_90;
    if (v8 != v2) {
        if (v8 > 0) {
            v4 = ptr->field_98;
            off_140108030();
            ((__int64 (*)())off_140108038)(v8, 0, v4);
        }
    }
    result = ptr->field_38;
    if (result != 0) {
        v4 = ptr->field_30;
        result =  + result*8 + 23;
        result &= -16;
        v4 -= result;
        off_140108030();
        ((__int64 (*)())off_140108038)(result, 0, v4);
    }
    v4 = ptr->field_20;
    v10 = ptr->field_28;
    if (v10 != 0) {
        v9 = v4;
        do {
            a1 = v9 + 176;
            sub_140046190(a1);
            sub_140053180(v9);
            v9 += 328;
            --v10;
        } while ((v10 != 0));
    }
    if (ptr->field_18 != 0) {
        off_140108030();
        a1 = (__int64 *)result;
        a2 = 0;
        v5 = v4;
        JUMPOUT(off_140108038);
    }
    return result;
}