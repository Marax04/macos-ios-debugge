// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14000ED60();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();

__int64 __fastcall sub_14009E080(int *a1, __int64 *a2, __int64 a3, __int64 a4) {
    int v_28;
    int v_30;
    char *str;
    __int64 i;
    __int64 result;
    __int64 v5;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    __int64 v3;
    __int64 v2;

    if (a4 < a3) {
        i = a4;
        while (*(a2 + i) != 0) {
            ++i;
            result = 0x8000000000000000;
            *a1 = result;
            return result;
        }
        v5 = i;
        v5 -= a4;
        if ((v5 < 0)) JUMPOUT(0x14009e14f);
        ptr = (struct Struct_1_t *)a1;
        a2 += a4;
        sub_14000ED60(str, a2, v5);
        result = (__int64)str;
        v4 = v_28;
        v7 = result;
        v7 = -v7;
        v3 = v_30;
        if (!((0 /* overflow check on (-v7) */))) {
            if (v3 < 0) {
                sub_1400F3360(v7);
            }
            if (!((0 /* unresolved: flags == */))) {
                sub_14002EDF0(0, v3);
                v2 = result;
                if (result == 0) {
                    sub_1400F3326(1, v3);
                    v2 = 1;
                }
                sub_1400F27F0(v2, v4, v3);
                result = v3;
                v4 = v2;
                *(__int64 *)ptr = (__int64)(result);
                ptr->field_8 = v4;
                ptr->field_10 = v3;
                return v4;
            }
            return v4;
        }
        return v4;
    }
    return result;
}