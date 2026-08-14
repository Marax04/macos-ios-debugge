__int64 sub_1400F253C();
__int64 sub_1400F239C();
__int64 sub_1400F20F9();
extern __int64 off_14012D288;

void __fastcall sub_1400F20C4(int a1) {
    int v1;

    if (a1 == 0) {
        off_14012D288 = 1;
    }
    sub_1400F253C();
    sub_1400F239C();
    if (v1 != 0) {
        sub_1400F239C(0);
        if (v1 != 0) JUMPOUT(0x1400f20f7);
        sub_1400F239C(0);
    }
    sub_1400F20F9();
}