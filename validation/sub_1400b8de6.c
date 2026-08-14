// inferred from 11 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[8];
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    char _pad_50[8];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    char _pad_68[8];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400B8DE6(__int64 a1, __int64 a2) {
    __int64 v4;
    __int64 v7;
    __int64 *result;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 *dst;
    __int64 v2;

    *(dst - 125) = *(dst - 125) + a1;
    if ((*(dst - 125) <= 0)) JUMPOUT(0x1400b8e03);
    *(dst + v2 + 72) = *(dst + v2 + 72) + a2;
    v4 = ptr->field_20;
    off_140108030();
    ((__int64 (*)())off_140108038)(dst, 0, v4);
    v7 = ptr->field_30;
    v7 <<= 1;
    if (v7 != 0) {
        v4 = ptr->field_38;
        off_140108030();
        ((__int64 (*)())off_140108038)(v7, 0, v4);
        result = ptr->field_48;
        result = (__int64 *)((__int64)(__int64)result << 1);
        if (result != 0) {
            ptr = ptr->field_50;
            off_140108030();
            JUMPOUT(off_140108038);
            ptr = (struct Struct_1_t *)result;
            if (*result != 0) {
                v4 = ptr->field_8;
                off_140108030(result, 0, ptr);
                ((__int64 (*)())off_140108038)(result, 0, v4);
            }
            if (ptr->field_18 != 0) {
                v4 = ptr->field_20;
                off_140108030();
                ((__int64 (*)())off_140108038)(result, 0, v4);
            }
            if (ptr->field_30 != 0) {
                v4 = ptr->field_38;
                off_140108030();
                ((__int64 (*)())off_140108038)(result, 0, v4);
            }
            if (ptr->field_48 != 0) {
                v4 = ptr->field_50;
                off_140108030();
                ((__int64 (*)())off_140108038)(result, 0, v4);
            }
            if (ptr->field_60 != 0) {
                v4 = ptr->field_68;
                off_140108030();
                ((__int64 (*)())off_140108038)(result, 0, v4);
            }
            if (ptr->field_78 != 0) {
                ptr = ptr->field_80;
                off_140108030();
                a1 = (__int64)result;
                a2 = 0;
                v5 = (__int64)ptr;
                JUMPOUT(off_140108038);
            }
            return v5;
        }
    } else {
        result = ptr->field_48;
        result = (__int64 *)((__int64)(__int64)result << 1);
        if (result != 0) {
            return (__int64)result;
        }
    }
    return (__int64)result;
}