__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_140095DA0();
__int64 sub_1400F3326();
__int64 sub_140095E2A();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140095C90(int a1, size_t a2) {
    __int64 __rdx_rax;
    int v_20;
    int v_40;
    int v_48;
    int v_78;
    char *str;
    __int64 v5;
    __int64 result;
    __int64 v3;
    __int64 v4;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 v2;

    sub_1400F1D90(0x1030);
    v5 = a2;
    v5 >>= 1;
    result = a2;
    result -= v5;
    v5 = 0x7A120;
    if (a2 < 0x7A120) v5 = a2;
    if (v5 <= result) v5 = result;
    v3 = 48;
    if (v5 >= 49) v3 = v5;
    if (v5 >= 257) {
        v4 = v3;
        v4 <<= 4;
        result >>= 60;
        result = (result == 0) ? 1 : 0;
        v6 = 0x7FFFFFFFFFFFFFF9;
        v5 = (v4 < v6) ? 1 : 0;
        if ((result & v5) == 0) {
            sub_1400F3360(a1, a2, v6);
        }
        v7 = a1;
        v8 = a2;
        sub_14002EDF0(0, v4);
        if (result != 0) {
            v_20 = (v8 < 65) ? 1 : 0;
            sub_140095DA0(v7, v8, result);
            off_140108030();
            a1 = result;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
        sub_1400F3326(8, v4, result);
        v2 = a2;
        v_40 = a1;
        result = 0x4000000000000000;
        a2 = 0;
        result = __rdx_rax / v2; a2 = __rdx_rax % v2; /* unsigned */;
        result += 1;
        v_78 = result;
        result = v2;
        if (v2 >= 0x1001) JUMPOUT(0x140095e00);
        result >>= 1;
        a1 = v2;
        a1 -= result;
        result = 64;
        if (a1 < 64) result = a1;
        v_48 = result;
        return sub_140095E2A();
    } else {
        v_20 = (a2 < 65) ? 1 : 0;
        sub_140095DA0(a1, a2, str, 256);
        return result;
    }
}