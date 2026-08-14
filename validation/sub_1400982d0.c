// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

__int64 sub_1400F27F0();

__int64 __fastcall sub_1400982D0(__int64 *a1, int a2, __int64 a3, __int64 a4) {
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v5;
    __int64 v2;
    int v4;
    __int64 result;

    ptr = a1[4];
    v6 = a1[5];
    ptr -= 28;
    v5 = v6 + v6*8;
    v5 += v5*2;
    v5 += v6;
    while (v5 != 0) {
        ptr = ptr->field_24;
        v2 = ptr->field_28;
        v6 = ptr->field_2C;
        if (v6 > ptr) ptr = v6;
        ptr += v2;
        if (!((ptr < 0))) {
            ptr += 28;
            v5 -= 28;
            v4 = a2;
            v4 -= v2;
            if (v4 < v6) {
                a2 = ptr->field_14;
                result = v4;
                ptr += a2;
                a2 = a1[2];
                if (ptr < a2) {
                    v2 = (__int64)ptr;
                    v2 += a4;
                    v6 = (v2 < 0) ? 1 : 0;
                    a2 = (v2 > a2) ? 1 : 0;
                    a2 |= v6;
                    if ((a2 == 0)) {
                        ptr += *(a1 + 8);
                        sub_1400F27F0(ptr, a3);
                        result = 13;
                    } else {
                        result = 0;
                    }
                    a2 = 0;
                    return a2;
                }
            }
        }
    }
    return result;
}