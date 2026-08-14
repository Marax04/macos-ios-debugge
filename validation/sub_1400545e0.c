// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

__int64 sub_1400547A3();
extern __int64 off_140117BB4;
extern __int64 off_140117BB8;
extern __int64 off_1401109F8;
extern __int64 off_140050370;

__int64 __fastcall sub_1400545E0(__int64 *a1, __int64 *a2) {
    __int64 rsp;
    int arg_18;
    int v_30;
    int v_40;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 result;
    int v5;
    __int64 v6;
    __int64 v3;
    __int64 *src;
    __int64 v9;
    int v2;

    ptr = (struct Struct_1_t *)a2;
    v7 = *a1;
    result = 0x8000000000000003;
    if (v7 == result) {
        a1 = ptr->field_0;
        result = ptr->field_8;
        result = arg_18;
        a2 = &off_140117BB4;
        v5 = 4;
        JUMPOUT(result);
    }
    v6 = (__int64)a1;
    v3 = ptr->field_0;
    src = ptr->field_8;
    v9 = *(src + 24);
    a2 = &off_140117BB8;
    ((__int64 (*)())v9)(v3, a2, 4);
    v2 = 1;
    if (result == 0) {
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x1400546d6);
        a2 = &off_1401109F8;
        ptr = 1;
        ((__int64 (*)())v9)(v3, a2, 1);
        if (result == 0) {
            result = 0x8000000000000000;
            result ^= v7;
            if (v7 < 0) ptr = result;
            if (ptr == 0) JUMPOUT(0x14005474d);
            if (ptr != 1) JUMPOUT(0x140054789);
            v_30 = v6;
            result = rsp + 48;
            v_40 = result;
            result = &off_140050370;
            return sub_1400547A3();
        }
    }
    result = v2;
    return result;
}