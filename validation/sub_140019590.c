__int64 __fastcall sub_140019590(__int64 *a1, size_t a2, __int64 a3, size_t a4) {
    __int64 result;
    __int64 v4;
    __int64 i;
    __int64 v2;
    __int64 v3;

    a3 = *a1;
    if (a3 != 0) {
        a2 = a1[97];
        if (a2 >= 0) {
            result = -1;
            if (a2 <= 18) {
                if (a2 == 0) {
                    result = 0;
                } else {
                    if (a2 != 1) {
                        v4 = a2;
                        v4 &= 30;
                        result = 0;
                        i = 0;
                        do {
                            a4 = i;
                            result += result;
                            result += result*4;
                            result += result;
                            result += result*4;
                            i = a4 + 1;
                            if (i >= a3) {
                                ++i;
                                a4 += 2;
                                v4 = result + result;
                                v4 += v4*4;
                                if ((a2 & 1) != 0) {
                                    if (a4 < a3) {
                                        result = *(a1 + a4 + 8);
                                        v4 += result;
                                    }
                                    result = v4;
                                }
                                if (a3 > a2) {
                                    a4 = *(a1 + a2 + 8);
                                    v4 = (a4 == 5) ? 1 : 0;
                                    v2 = a2 + 1;
                                    a3 = (v2 == a3) ? 1 : 0;
                                    if ((a3 & v4) == 0) {
                                        if (a4 > 4) {
                                            ++result;
                                        }
                                    } else {
                                        if (a1[97] == 0) {
                                            if (a2 != 0) {
                                                if ((*(a1 + a2 + 7) & 1) != 0) {
                                                    return result;
                                                } else {
                                                }
                                            }
                                            return result;
                                        }
                                        return result;
                                    }
                                }
                                return result;
                            }
                            v3 = *(a1 + a4 + 9);
                            result += v3;
                            return result;
                        } while (i != v4);
                        return result;
                    } else {
                        v4 = 0;
                        a4 = 0;
                        if ((a2 & 1) != 0) {
                            return a4;
                        } else {
                        }
                    }
                }
                return a4;
            }
            return a4;
        }
    }
    result = 0;
    return result;
}