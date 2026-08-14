__int64 sub_140012BE4();
__int64 sub_140012C0B();

__int64 __fastcall sub_140012B70(__int64 *a1, size_t a2, __int64 a3, __int64 a4) {
    int arg_58;
    int arg_60;
    int v_50;
    int v_58;
    __int64 v1;
    int v2;
    int v3;

    v_50 = a3;
    v_58 = a4;
    if (a2 >= 257) {
        v1 = 256;
        do {
            if (*(a1 + v1) > 191) JUMPOUT(0x140012be4);
            if (*(a1 + v1 - 1) > 191) JUMPOUT(0x140012bd5);
            if (*(a1 + v1 - 2) > 191) JUMPOUT(0x140012bda);
            if (*(a1 + v1 - 3) > 191) JUMPOUT(0x140012be0);
            v1 -= 4;
        } while ((v1 != 0));
        v1 = 0;
        return sub_140012BE4();
    } else {
        arg_58 = (int)a1;
        arg_60 = a2;
        v2 = 1;
        v3 = 0;
        return sub_140012C0B();
    }
}