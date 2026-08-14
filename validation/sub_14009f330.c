// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 __fastcall sub_14009F330(__int64 *a1,struct Struct_1_t *a2) {
    __int64 i;
    __int64 *result;
    __int64 v5;
    __int64 v3;
    __int64 v7;
    __int64 v2;
    __int64 v4;

    i = a2->field_28;
    if (i != 0) {
        result = a2->field_20;
        v5 = i + i*8;
        v5 += v5*2;
        v5 += i;
        v3 = 0;
        v7 = 0x747865742E;
        i = 0;
        while (*(result + v3) != v7) {
            ++i;
            v3 += 28;
            *(a1 + 2) = 13;
            result = 1;
            *a1 = result;
            return (__int64)result;
        }
        v2 = i + i*8;
        v2 += v2*2;
        v2 += i;
        v3 = *(result + v2 + 16);
        v4 = *(result + v2 + 20);
        result = v3 + v4;
        if (result <= a2->field_10) JUMPOUT(0x14009f3c8);
        *(a1 + 2) = 13;
        return (__int64)result;
    }
    return (__int64)result;
}