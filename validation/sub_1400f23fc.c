// inferred from 2 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[52];
    __int64 field_3C; // offset 60
};

__int64 off_140108180();

__int64 __fastcall sub_1400F23FC(int *a1) {
    int v2;
    struct Struct_1_t *result;

    off_140108180(0);
    if (result != 0) {
        a1 = 0x5A4D;
        if (result->field_0 == a1) {
            a1 = result->field_3C;
            if (*(__int64 *)((__int64)a1 + (__int64)result) == 0x4550) {
                v2 = 523;
                if (*(__int64 *)((__int64)a1 + (__int64)result + 24) == v2) {
                    if (*(__int64 *)((__int64)a1 + (__int64)result + 132) <= 14) {
                        result = 0;
                    } else {
                        result = (*(__int64 *)((__int64)a1 + (__int64)result + 248) != 0) ? 1 : 0;
                    }
                    return (__int64)result;
                }
            }
        }
    }
    return (__int64)result;
}