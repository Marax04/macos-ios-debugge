// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140037C60(__int64 *a1, __int64 a2) {
    __int64 v_10;
    __int64 v_18;
    __int64 v_20;
    __int64 v_28;
    int v_30;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    int v_8;
    struct Struct_1_t *result;
    __int64 v3;
    __int64 *src;
    __int64 *src2;
    __int64 v5;

    v_8 = -2;
    result = *(a1 + 8);
    v_10 = (__int64)result;
    v_30 = (int)a1;
    result = a1[2];
    v_28 = (__int64)result;
    if (result != 0) {
        result = (struct Struct_1_t *)v_28;
        v3 = result - 1;
        result = (struct Struct_1_t *)v_10;
        src = result + 24;
        do {
            v_38 = (__int64)result;
            v_48 = v3;
            result = *(src - 24);
            v_20 = (__int64)result;
            v_40 = (__int64)src;
            result = *(src - 16);
            v_18 = (__int64)result;
            result = result->field_0;
            src2 = (__int64 *)v_20;
            result = (struct Struct_1_t *)v_18;
            v3 = v_48;
            src = (__int64 *)v_40;
            if (result->field_8 == 0) {
                src += 16;
                result = (struct Struct_1_t *)v_38;
                ++result;
                v3 -= 1;
                result = (struct Struct_1_t *)v_30;
                if (result->field_0 != 0) {
                    off_140108030();
                    a1 = (__int64 *)result;
                    a2 = 0;
                    v5 = v_10;
                    JUMPOUT(off_140108038);
                }
                return v5;
            }
            if (result->field_10 < 17) {
                off_140108030(1);
                ((__int64 (*)())off_140108038)(result, 0, src2);
                return v5;
            }
            src2 = *(src2 - 8);
            return (__int64)src2;
        } while (!((v3 >= 0)));
    }
    return (__int64)result;
}