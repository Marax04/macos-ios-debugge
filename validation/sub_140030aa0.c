// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400F3340();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140114920;

__int64 __fastcall sub_140030AA0(int a1, int a2) {
    __int64 rsp;
    int v_10;
    int v_8;
    __int64 *dst;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v6;
    struct Struct_1_t *result;

    dst = rsp + 48;
    *dst = -2;
    v3 = a2;
    v4 = a1;
    sub_14002EDF0(0);
    if (result != 0) {
        v2 = (__int64)result;
        sub_1400F27F0(result, v4, v3);
        sub_14002EDF0(0, 24);
        if (result == 0) {
            v_8 = v2;
            sub_1400F3340(8, 24);
        } else {
            v7 = (__int64)result;
            *(__int64 *)result = (__int64)(v3);
            result->field_8 = v2;
            result->field_10 = v3;
            sub_14002EDF0(0, 24);
            if (result == 0) {
                v_8 = v7;
                sub_1400F3340(8, 24);
            } else {
                *(__int64 *)result = (__int64)(v7);
                v6 = &off_140114920;
                result->field_8 = v6;
                result->field_10 = 20;
                ++result;
                return (__int64)result;
            }
        }
    }
    sub_1400F3326(1, v3);
    v_10 = a2;
    dst = a2 + 48;
    off_140108030();
    return off_140108038(result, 0, v_8);
}