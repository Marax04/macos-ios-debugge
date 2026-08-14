int __fastcall sub_1400123E0(size_t a1) {
    int result;

    if (a1 >= 32) {
        result = 1;
        if (a1 >= 127) JUMPOUT(0x140012408);
    } else {
        result = 0;
    }
    result &= 1;
    return result;
}