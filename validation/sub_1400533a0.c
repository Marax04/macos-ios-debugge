// inferred from 14 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[8];
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    char _pad_58[8];
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    char _pad_80[8];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 sub_140046190();
__int64 sub_140053180();
extern __int64 off_140121ECC;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400533A0(int *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v4;
    __int64 *src;
    __int64 v8;
    __int64 v6;
    __int64 v7;
    __int64 v9;
    __int64 v5;

    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    a1 = result - 2;
    if (a1 >= 6) result = a1;
    if (result <= 5) {
        a1 = &off_140121ECC;
        switch (result) {
            default:
                if (ptr->field_38 > 0) {
                    v4 = ptr->field_40;
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, v4);
                }
                result = ptr->field_50;
                src = 0x8000000000000003;
                if (result != src) {
                    if (result > 0) {
                        v4 = ptr->field_58;
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, v4);
                    }
                }
                result = ptr->field_68;
                if (result != src) {
                    if (result > 0) {
                        v4 = ptr->field_70;
                        ((__int64 (*)())off_140108030)();
                        ((__int64 (*)())off_140108038)(result, 0, v4);
                    }
                }
                v4 = ptr->field_28;
                v8 = ptr->field_30;
                if (v8 != 0) {
                    v6 = 1;
                    v7 = off_140108030;
                    v9 = off_140108038;
                    src = (__int64 *)v4;
                    do {
                        a1 = *src;
                        result = a1 - 8;
                        if (a1 < 8) result = v6;
                        src += 176;
                        --v8;
                    } while (!((v8 == 0)));
                }
                if (ptr->field_20 != 0) {
                    ((__int64 (*)())off_140108030)();
                    JUMPOUT(off_140108038);
                }
                return v8;
        }
        result = ptr->field_78;
        src = 0x8000000000000003;
        if (result == src) {
            result = ptr->field_90;
            if (result == src) {
                result = ptr->field_38;
                if (result == 0) {
                    v4 = ptr->field_20;
                    v5 = ptr->field_28;
                    if (v5 == 0) {
                        if (ptr->field_18 != 0) {
                            return v5;
                        }
                        return v5;
                    }
                    src = (__int64 *)v4;
                    do {
                        a1 = src + 176;
                        sub_140046190(a1);
                        sub_140053180(src);
                        src += 328;
                        --v5;
                    } while ((v5 != 0));
                    return v5;
                }
                v4 = ptr->field_30;
                result =  + result*8 + 23;
                result &= -16;
                v4 -= result;
                ((__int64 (*)())off_140108030)();
                ((__int64 (*)())off_140108038)(result, 0, v4);
                return v4;
            }
            if (result <= 0) {
                return v4;
            }
            v4 = ptr->field_98;
            ((__int64 (*)())off_140108030)();
            ((__int64 (*)())off_140108038)(result, 0, v4);
            return v4;
        }
        if (result <= 0) {
            return v4;
        }
        v4 = ptr->field_80;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(result, 0, v4);
        return v4;
    }
    return result;
}