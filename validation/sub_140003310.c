__int64 sub_1400F32C0();
extern __int64 off_140120E2C;
extern __int64 off_14000E2E0;
extern __int64 off_140109730;

__int64 __fastcall sub_140003310(__int64 *a1, __int64 *a2, __int64 a3) {
    int v_28;
    int v_38;
    int v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    char *str;
    char *str2;
    char *result;
    __int64 v1;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    __int64 *dst;

    v1 = a3 - 4;
    if (v1 <= 10) {
        v3 = &off_140120E2C;
        switch (v1) {
            case 2:
                break;
            default:
                if (*a2 == 0x656E6F6E) {
                    *a1 = 0;
                    return v3;
                }
                break;
        }
    }
    str = (char *)a2;
    v_28 = a3;
    str2 = str;
    v4 = &off_14000E2E0;
    v_38 = v4;
    v5 = &off_140109730;
    result = (char *)v5;
    v_48 = 2;
    v_60 = 0;
    v_50 = (__int64)str2;
    v_58 = 1;
    dst = a1;
    sub_1400F32C0(result, a2, a3, v3);
    *(dst + 8) = result;
    *dst = 1;
    return (__int64)result;
}