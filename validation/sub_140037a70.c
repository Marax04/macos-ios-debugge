// inferred from 2 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140037A70(__int64 *a1, __int64 a2) {
    int v_10;
    __int64 v_18;
    int v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    int v_8;
    __int64 *src;
    __int64 i;
    __int64 v4;
    __int64 v8;
    __int64 *src2;
    __int64 *src3;
    struct Struct_2_t *ptr;
    struct Struct_1_t *result;
    __int64 v10;
    __int64 v5;

    v_8 = -2;
    src = *(a1 + 8);
    v_10 = (int)a1;
    i = a1[3];
    i -= (__int64)src;
    if (!((i == 0))) {
        i >>= 4;
        v_40 = i;
        v4 = i - 1;
        src += 24;
        do {
            v_28 = i;
            v_30 = v4;
            v8 = *(src - 24);
            v_20 = v8;
            v_38 = (__int64)src;
            src2 = *(src - 16);
            v_18 = (__int64)src2;
            src2 = *src2;
            src3 = (__int64 *)v_20;
            ptr = (struct Struct_2_t *)v_18;
            src = (__int64 *)v_38;
            v4 = v_30;
            if (ptr->field_8 == 0) {
                src += 16;
                i = v_28;
                ++i;
                v4 -= 1;
                result = (struct Struct_1_t *)v_10;
                if (result->field_10 != 0) {
                    src = result->field_0;
                    off_140108030();
                    v10 = (__int64)result;
                    a2 = 0;
                    v5 = (__int64)src;
                    JUMPOUT(off_140108038);
                }
                return v5;
            }
            if (ptr->field_10 < 17) {
                off_140108030(1);
                ((__int64 (*)())off_140108038)(ptr, 0, src3);
                return v5;
            }
            src3 = *(src3 - 8);
            return (__int64)src3;
        } while (!((v4 >= 0)));
    }
    return (__int64)result;
}