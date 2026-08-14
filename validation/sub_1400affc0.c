__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400BB5E0();
__int64 sub_1400F3326();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400AFFC0(int a1, size_t a2) {
    int v_20;
    char *str;
    __int64 v4;
    __int64 result;
    __int64 v2;
    __int64 v3;
    __int64 v5;
    __int64 v7;
    __int64 v8;
    __int64 v6;

    sub_1400F1D90(0x1030);
    v4 = a2;
    v4 >>= 1;
    result = a2;
    result -= v4;
    v4 = 0x7A120;
    if (a2 < 0x7A120) v4 = a2;
    if (v4 <= result) v4 = result;
    v2 = 48;
    if (v4 >= 49) v2 = v4;
    if (v4 >= 257) {
        v3 = v2;
        v3 <<= 4;
        result >>= 60;
        result = (result == 0) ? 1 : 0;
        v5 = 0x7FFFFFFFFFFFFFF9;
        v4 = (v3 < v5) ? 1 : 0;
        if ((result & v4) == 0) {
            sub_1400F3360(a1, a2, v5);
        }
        v7 = a1;
        v8 = a2;
        sub_14002EDF0(0, v3);
        if (result != 0) {
            v_20 = (v8 < 65) ? 1 : 0;
            sub_1400BB5E0(v7, v8, result);
            off_140108030();
            v6 = result;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
        sub_1400F3326(8, v3, result);
        if (v3 >= 2) JUMPOUT(0x1400b00d7);
        return a2;
    } else {
        v_20 = (a2 < 65) ? 1 : 0;
        sub_1400BB5E0(a1, a2, str, 256);
        return result;
    }
}