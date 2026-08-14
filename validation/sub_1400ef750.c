// inferred from 8 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
};

extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400EF750(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 result;
    __int64 v8;
    __int64 *src;
    __int64 v6;
    __int64 v7;
    __int64 v4;
    __int64 v5;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 != 0) {
        v3 = ptr->field_8;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(result, 0, v3);
    }
    a1 = ptr->field_50;
    if (a1 != 0) {
        result =  + (__int64)(__int64)a1*8 + 23;
        result &= -16;
        a1 += result;
        if (a1 != -17) {
            v3 = ptr->field_48;
            v3 -= result;
            ((__int64 (*)())off_140108030)(a1);
            ((__int64 (*)())off_140108038)(result, 0, v3);
        }
    }
    if (ptr->field_18 != 0) {
        v3 = ptr->field_20;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(result, 0, v3);
    }
    v3 = ptr->field_38;
    v8 = ptr->field_40;
    if (v8 != 0) {
        src = v3 + 32;
        v6 = off_140108030;
        v7 = off_140108038;
        do {
            if (*(src - 8) == 0) {
                src += 48;
                --v8;
                if (ptr->field_30 != 0) {
                    ((__int64 (*)())off_140108030)();
                    a1 = (__int64 *)result;
                    a2 = 0;
                    v4 = v3;
                    JUMPOUT(off_140108038);
                }
                return v4;
            }
            v5 = *src;
            ((__int64 (*)())v6)();
            ((__int64 (*)())v7)(result, 0, v5);
            return v5;
        } while (!((v8 == 0)));
    }
    return result;
}