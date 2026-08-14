// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F32C0();
extern __int64 off_14000E2E0;
extern __int64 off_1401098B8;

__int64 __fastcall sub_140003420(__int64 *a1,struct Struct_1_t *a2, int a3, __int64 a4) {
    int v_28;
    int v_38;
    int v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    char *str;
    char *str2;
    char *result;
    __int64 v3;
    __int64 v1;
    __int64 v4;
    __int64 v5;
    __int64 *dst;

    if (a3 == 4) {
        if (a2->field_0 == 0x6574696C) {
            *a1 = 0;
            return 0;
        }
    } else {
        if (a3 != 8) {
            if (a3 == 10) {
                v3 = 0x6973736572676761;
                v3 ^= *a2;
                a4 = a2->field_8;
                a4 ^= 0x6576;
                a4 |= v3;
                if (!((a4 != 0))) {
                    *a1 = 512;
                    return a4;
                }
            }
        } else {
            v1 = 0x6465636E616C6162;
            if (a2->field_0 == v1) {
                *a1 = 256;
                return v1;
            }
        }
    }
    str = (char *)a2;
    v_28 = a3;
    str2 = str;
    v4 = &off_14000E2E0;
    v_38 = v4;
    v5 = &off_1401098B8;
    result = (char *)v5;
    v_48 = 2;
    v_60 = 0;
    v_50 = (__int64)str2;
    v_58 = 1;
    dst = a1;
    sub_1400F32C0(result, a2, a3, a4);
    *(dst + 8) = result;
    *dst = 1;
    return (__int64)result;
}