__int64 sub_14000FC90();

int __fastcall sub_140009990(__int64 a1, size_t str) {
    int v_25;
    int result;
    int v2;

    str = 0;
    if (str >= 128) {
        result = str;
        result &= 63;
        result |= 128;
        v2 = str;
        v2 >>= 6;
        if (str >= 0x800) JUMPOUT(0x1400099f6);
        v2 |= 192;
        str = v2;
        v_25 = result;
        return sub_14000FC90(a1, str, 2);
    } else {
        sub_14000FC90(a1, str, 1);
        return result;
    }
}