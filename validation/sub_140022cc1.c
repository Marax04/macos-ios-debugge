// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_140022CC1(struct Struct_1_t *a1) {
    __int64 result;
    __int64 *src;

    result = ((__int64 *)a1)[2];
    if (result >= a1->field_8) {
        result = 1;
        src = 0;
    } else {
        src = a1->field_0;
        src = *(src + result);
        ++result;
        ((__int64 *)a1)[2] = (__int64)(result);
        result = src - 65;
        if (result >= 26) {
            src += 133;
            a1 = 0;
            result = 0;
            result = (src < 230) ? 1 : 0;
            src = 0x11000000000000;
            if (src < 0) src = a1;
        } else {
            src = (__int64 *)((__int64)(__int64)src << 32);
            result = 0;
        }
    }
    result |= (__int64)src;
    return result;
}