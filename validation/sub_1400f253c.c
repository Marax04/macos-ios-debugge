__int64 sub_1400F2634();
extern __int64 off_14012D0C8;
extern __int64 off_14012D0D0;
extern __int64 off_14012D2E4;

__int64 __fastcall sub_1400F253C(int a1, int a2, int a3, int a4) {
    int v_10;
    int v_18;
    int v_20;
    __int64 result;
    __int64 v5;
    __int64 v2;
    int v4;
    __int64 v3;

    v_10 = v2;
    v_18 = v5;
    v_20 = v3;
    result = 0;
    a1 = 0;
    /* cpuid  */;
    a1 ^= 0x6C65746E;
    a2 ^= 0x49656E69;
    a2 |= a1;
    v5 = result;
    result = 1;
    v2 ^= 0x756E6547;
    a2 |= v2;
    a1 = result - 1;
    /* cpuid  */;
    if (!((a2 != 0))) {
        result &= 0xFFF3FF0;
        off_14012D0C8 = 0x8000;
        off_14012D0D0 = -1;
        if (result != 0x106C0) {
            if (result != 0x20660) {
                if (result != 0x20670) {
                    result += 0xFFFCF9B0;
                    if (result <= 32) {
                        a1 = 0x100010001;
                        if ((!((a1 >> result) & 1))) {
                            a3 = off_14012D2E4;
                        } else {
                            a3 = off_14012D2E4;
                            a3 |= 1;
                            off_14012D2E4 = a3;
                        }
                        a4 = 0;
                        v4 = a4;
                        if (v5 < 7) JUMPOUT(0x1400f262e);
                        a1 = 0;
                        result = a4 + 7;
                        /* cpuid  */;
                        if (!((!((v2 >> 9) & 1)))) {
                            a3 |= 2;
                            off_14012D2E4 = a3;
                        }
                        if (result >= 1) {
                            result = 7;
                            a1 = result - 6;
                            /* cpuid  */;
                            a4 = a2;
                        }
                        result = 36;
                        if (v5 < result) JUMPOUT(0x1400f2634);
                        a1 = 0;
                        /* cpuid  */;
                        v4 = v2;
                        return sub_1400F2634();
                    }
                    return v4;
                }
            }
        }
        return v4;
    }
    return result;
}