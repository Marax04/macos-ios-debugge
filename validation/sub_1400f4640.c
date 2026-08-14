__int64 sub_14001FEF0();

__int64 __fastcall sub_1400F4640(int a1, size_t *a2) {
    int v_28;
    int v_48;
    int v_50;
    __int64 result;
    __int64 *src;
    __int64 v4;
    __int64 v3;

    result = *a2;
    if (result != 3) {
        src = (__int64 *)a2;
        v4 = a1;
        v3 = a1 + 312;
        v_50 = (int)a2;
        v_48 = v3;
        v_28 = a1;
        do {
            sub_14001FEF0(v4);
            ((__int64 (*)())result)(a2);
            result = *src;
        } while (result != 3);
    }
    return result;
}