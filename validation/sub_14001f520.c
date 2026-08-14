// inferred from 11 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[16];
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    char _pad_48[8];
    __int64 field_58; // offset 88
    char _pad_58[8];
    __int64 field_68; // offset 104
    char _pad_68[24];
    __int64 field_88; // offset 136
};

__int64 sub_14002E220();
__int64 sub_14001EDC0();
__int64 sub_14001F160();
__int64 sub_1400377D0();
__int64 sub_140037910();
__int64 sub_140041110();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14001F520(__int64 *a1, __int64 a2) {
    int arg_10;
    int arg_8;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v4;
    __int64 v7;
    __int64 *src;
    __int64 v5;
    __int64 v6;
    __int64 *src2;
    __int64 *src3;

    ptr = (struct Struct_1_t *)a1;
    result = a1[4];
    *result = *result - 1;
    if ((*result == 0)) {
        a1 = ptr->field_20;
        sub_14002E220(a1);
        result = ptr->field_40;
        result = (__int64 *)((__int64)(__int64)result << 1);
        if (result == 0) {
            result = ptr->field_68;
            *result = *result - 1;
            if ((*result == 0)) {
                a1 = ptr + 104;
                sub_14001EDC0(a1);
                result = ptr->field_58;
                *result = *result - 1;
                if ((*result != 0)) {
                    result = ptr->field_88;
                    *result = *result - 1;
                    if (!((*result != 0))) {
                        a1 = ptr->field_88;
                        sub_14001F160(a1);
                    }
                } else {
                    a1 = ptr + 88;
                    sub_14001EDC0(a1);
                    result = ptr->field_88;
                    *result = *result - 1;
                    if ((*result == 0)) {
                        return (__int64)result;
                    } else {
                    }
                }
                v4 = ptr + 24;
                sub_1400377D0(v4);
                result = ptr->field_18;
                if (result != 0) {
                    *result = *result - 1;
                    if (!((*result != 0))) {
                        sub_140037910(v4);
                    }
                }
                v4 = ptr->field_8;
                v7 = ptr->field_10;
                if (v7 != 0) {
                    src = v4 + 8;
                    v5 = off_140108030;
                    v6 = off_140108038;
                    do {
                        src2 = *(src - 8);
                        src3 = *src;
                        result = *src3;
                        if (arg_8 == 0) {
                            src += 16;
                            --v7;
                            if (ptr->field_0 != 0) {
                                ((__int64 (*)())off_140108030)();
                                ((__int64 (*)())off_140108038)(result, 0, v4);
                            }
                            result = ptr->field_28;
                            *result = *result - 1;
                            if ((*result != 0)) JUMPOUT(0x14001f6c6);
                            a1 = ptr->field_28;
                            return sub_140041110();
                        }
                        if (arg_10 < 17) {
                            ((__int64 (*)())v5)();
                            ((__int64 (*)())v6)(result, 0, src2);
                            return (__int64)a1;
                        }
                        src2 = *(src2 - 8);
                        return (__int64)src2;
                    } while (!((v7 == 0)));
                }
                return (__int64)src2;
            } else {
                result = ptr->field_58;
                *result = *result - 1;
                if ((*result == 0)) {
                    return (__int64)result;
                } else {
                    return (__int64)result;
                }
                return (__int64)result;
            }
            return (__int64)result;
        } else {
            v4 = ptr->field_48;
            ((__int64 (*)())off_140108030)();
            ((__int64 (*)())off_140108038)(result, 0, v4);
            result = ptr->field_68;
            *result = *result - 1;
            if ((*result != 0)) {
                return (__int64)result;
            } else {
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    } else {
        result = ptr->field_40;
        result = (__int64 *)((__int64)(__int64)result << 1);
        if (result != 0) {
            return (__int64)result;
        } else {
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}