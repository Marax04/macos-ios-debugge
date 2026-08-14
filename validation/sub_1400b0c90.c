// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[40];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 sub_1400B0D8E();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400B0C90(__int64 *a1, __int64 a2) {
    int v_20;
    __int64 v4;
    __int64 v3;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 result;
    __int64 v6;
    __int64 v5;
    __int64 v2;

    v4 = *(a1 + 8);
    v_20 = (int)a1;
    v3 = a1[2];
    if (v3 != 0) {
        src = v4 + 56;
        ptr = off_140108030;
        v7 = off_140108038;
        do {
            result = *(src - 32);
            result = -result;
            if ((0 /* overflow check on (-result) */)) {
                src += 0x458;
                --v3;
                ptr = (struct Struct_1_t *)v_20;
                if (ptr->field_0 != 0) {
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, v4);
                }
                v4 = ptr->field_30;
                if (v4 == 0) JUMPOUT(0x1400b1069);
                v3 = ptr->field_38;
                v6 = ptr->field_40;
                if (v6 == 0) JUMPOUT(0x1400b0f8f);
                ptr = off_140108030;
                v5 = off_140108038;
                v2 = v4;
                v4 = 0;
                return sub_1400B0D8E();
            }
            if ((0 /* unresolved: flags >= */)) {
                if (*(src - 8) == 0) {
                    return v4;
                }
                v2 = *src;
                ((__int64 (*)())ptr)();
                ((__int64 (*)())v7)(result, 0, v2);
                return v2;
            }
            v2 = *(src - 24);
            ((__int64 (*)())ptr)();
            ((__int64 (*)())v7)(result, 0, v2);
            return v2;
        } while (!((v3 == 0)));
    }
    return result;
}