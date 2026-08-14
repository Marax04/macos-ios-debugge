__int64 sub_1400F37A0();
__int64 sub_1400F3869();
__int64 sub_1400F1D90();
__int64 sub_1400F2808();
__int64 sub_140032C6B();
__int64 sub_1400F37D0();
__int64 off_140108180();
extern __int64 off_140018400;
extern __int64 off_140114238;
extern __int64 off_140112BD0;
extern __int64 off_140112EA6;
extern __int64 off_140114860;
extern __int64 off_1401148E8;
extern __int64 off_140114280;
extern __int64 off_1401142C0;

__int64 __fastcall sub_140032AB0(int *a1, size_t a2, int *a3, size_t a4) {
    __int64 rsp;
    int arg_102c;
    int arg_1030;
    int arg_8;
    int v_10;
    int v_18;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_8;
    __int64 v7;
    __int64 result;
    __int64 v5;
    __int64 v4;
    __int64 v3;
    int v6;
    __int64 v2;

    v7 = rsp + 112;
    a3 = (int *)arg_8;
    result = a1[2];
    v_18 = a2;
    if (a2 != 0) {
        if (a2 >= result) {
            if (!((0 /* unresolved: flags == */))) {
                result = v7 - 24;
                v_10 = result;
                result = &off_140018400;
                v_8 = result;
                result = &off_140114238;
                v_48 = result;
                v_40 = 2;
                v_28 = 0;
                result = v7 - 16;
                v_38 = result;
                v_30 = 1;
                a2 = &off_140112BD0;
                a1 = v7 - 72;
                sub_1400F37A0(a1, a2);
                v5 = &off_140112BD0;
                sub_1400F3869(a4, result, v5);
                sub_1400F1D90(0x10B8);
                v7 = rsp + 128;
                arg_1030 = -2;
                v4 = a2;
                v3 = (__int64)a1;
                arg_102c = a2;
                v6 = 0;
                v2 = v7 - 64;
                sub_1400F2808(v2, 0, 0x1000);
                a1 = 0x1200;
                if ((v4 & 0x10000000) == 0) JUMPOUT(0x140032c6b);
                a1 = &off_140112EA6;
                off_140108180(a1);
                if (result == 0) JUMPOUT(0x140032c63);
                v4 &= 0xEFFFFFFF;
                arg_102c = v4;
                a1 = 0x1A00;
                return sub_140032C6B();
            }
        } else {
            a4 = *(a3 + a2);
            if (a4 != 237) {
                if (a4 > 191) {
                    if (*(a3 + a2) <= 191) {
                        a1 = &off_140114860;
                        v4 = &off_1401148E8;
                        sub_1400F37D0(a1, 54, v4, a4);
                    } else {
                        if (a2 <= result) {
                            a1[2] = a2;
                        }
                        return v4;
                    }
                }
            } else {
                a4 = a2 + 1;
                if (a4 < result) {
                    if (a2 >= 3) {
                        if (*(a3 + a2 + 1) > 159) {
                            if (*(a3 + a2 - 3) == 237) {
                                if (*(a3 + a2 - 2) < 160) {
                                    return a4;
                                } else {
                                    result = v7 - 24;
                                    v_10 = result;
                                    result = &off_140018400;
                                    v_8 = result;
                                    result = &off_140114280;
                                }
                                return result;
                            }
                        }
                    }
                    return result;
                }
                return result;
            }
            result = v7 - 24;
            v_10 = result;
            result = &off_140018400;
            v_8 = result;
            result = &off_1401142C0;
            return result;
        }
    }
    return result;
}