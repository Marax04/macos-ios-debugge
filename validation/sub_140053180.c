// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[24];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 11 accesses on `ptr`
struct Struct_2_t {
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

__int64 sub_1400533A0();
__int64 sub_140053A40();
__int64 sub_140046190();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140053180(struct Struct_1_t *a1, __int64 a2) {
    struct Struct_2_t *ptr;
    __int64 result;
    __int64 *v4;
    __int64 v6;
    __int64 v10;
    __int64 *src;
    __int64 v5;
    __int64 v7;
    __int64 v8;
    __int64 v9;

    ptr = (struct Struct_2_t *)a1;
    result = a1->field_0;
    a1 = result - 8;
    if (a1 >= 1) result = a1;
    if (result != 0) {
        if (result == 1) {
            a1 = (struct Struct_1_t *)ptr;
            return sub_1400533A0();
        } else {
            if (result != 2) {
                v4 = ptr->field_28;
                v6 = ptr->field_30;
                if (v6 != 0) {
                    v10 = 1;
                    src = v4;
                    do {
                        a1 = *src;
                        result = a1 - 8;
                        if (a1 < 8) result = v10;
                        src += 176;
                        --v6;
                    } while (!((v6 == 0)));
                }
                if (ptr->field_20 != 0) {
                    off_140108030();
                    a1 = (struct Struct_1_t *)result;
                    a2 = 0;
                    JUMPOUT(off_140108038);
                    v4 = (__int64 *)a1;
                    ptr = a1->field_20;
                    a2 = a1->field_28;
                    sub_140053A40(ptr, a2, v4);
                    if (*(v4 + 24) != 0) {
                        off_140108030();
                        a1 = (struct Struct_1_t *)result;
                        a2 = 0;
                        v5 = (__int64)ptr;
                        JUMPOUT(off_140108038);
                    }
                    return v5;
                }
            } else {
                v7 = ptr->field_78;
                src = 0x8000000000000003;
                if (v7 != src) {
                    if (v7 > 0) {
                        v4 = ptr->field_80;
                        off_140108030(a1);
                        ((__int64 (*)())off_140108038)(v7, 0, v4);
                    }
                }
                v8 = ptr->field_90;
                if (v8 != src) {
                    if (v8 > 0) {
                        v4 = ptr->field_98;
                        off_140108030();
                        ((__int64 (*)())off_140108038)(v8, 0, v4);
                    }
                }
                result = ptr->field_50;
                if (result != 0) {
                    v4 = ptr->field_48;
                    result =  + result*8 + 23;
                    result &= -16;
                    v4 -= result;
                    off_140108030();
                    ((__int64 (*)())off_140108038)(result, 0, v4);
                }
                v4 = ptr->field_38;
                v9 = ptr->field_40;
                if (v9 != 0) {
                    src = v4;
                    do {
                        a1 = src + 176;
                        sub_140046190(a1);
                        sub_140053180(src, a2);
                        src += 328;
                        --v9;
                    } while ((v9 != 0));
                }
                if (ptr->field_30 != 0) {
                    return v9;
                }
            }
        }
    }
    return result;
}