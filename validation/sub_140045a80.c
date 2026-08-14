// inferred from 13 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[8];
    __int64 field_50; // offset 80
    char _pad_50[32];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    char _pad_80[8];
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 sub_140046190();
__int64 sub_1400462A0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140121CE0;

__int64 __fastcall sub_140045A80(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v4;
    __int64 v2;
    __int64 v5;

    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    a1 = result - 2;
    if (a1 >= 6) result = a1;
    if (result <= 5) {
        a1 = &off_140121CE0;
        switch (result) {
            default:
                if (ptr->field_8 != 0) {
                    v4 = ptr->field_10;
                    off_140108030();
                    off_140108038(result, 0, v4);
                }
                result = ptr->field_20;
                v2 = 0x8000000000000003;
                if (result != v2) {
                    if (result > 0) {
                        v4 = ptr->field_28;
                        off_140108030();
                        off_140108038(result, 0, v4);
                    }
                }
                result = ptr->field_38;
                if (result != v2) {
                    if (result > 0) {
                        v4 = ptr->field_40;
                        off_140108030();
                        off_140108038(result, 0, v4);
                    }
                }
                result = ptr->field_50;
                if (result != v2) {
                    if (result > 0) {
                        ptr += 88;
                        return (__int64)ptr;
                    }
                }
                return (__int64)ptr;
        }
        result = ptr->field_78;
        v2 = 0x8000000000000003;
        if (result == v2) {
            result = ptr->field_90;
            if (result == v2) {
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
                    v2 = v4;
                    do {
                        a1 = v2 + 176;
                        sub_140046190(a1);
                        sub_1400462A0(v2);
                        v2 += 328;
                        --v5;
                    } while ((v5 != 0));
                    return v5;
                }
                v4 = ptr->field_30;
                result =  + result*8 + 23;
                result &= -16;
                v4 -= result;
                off_140108030();
                off_140108038(result, 0, v4);
                return v4;
            }
            if (result <= 0) {
                return v4;
            }
            v4 = ptr->field_98;
            off_140108030();
            off_140108038(result, 0, v4);
            return v4;
        }
        if (result <= 0) {
            return v4;
        }
        v4 = ptr->field_80;
        off_140108030();
        off_140108038(result, 0, v4);
        return v4;
    }
    return result;
}