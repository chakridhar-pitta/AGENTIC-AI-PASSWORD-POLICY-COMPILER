import os
import json

# Ensure directories exist
os.makedirs("CODE/datasets", exist_ok=True)
os.makedirs("datasets", exist_ok=True)

# Curated sets for 7 distinct categories
# Global tracker to enforce zero duplicates across all categories
seen = set()

def clean_entry(w):
    return w.strip().lower()

# 1. KEYBOARD PATTERNS (Target: 300)
# QWERTY, AZERTY, QWERTZ, Dvorak, keypad rows, diagonals, zig-zags
keyboard_raw = [
    # Basic rows
    "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwertz", "azerty",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "ytrewq", "jhgfdsa", "bvcxz",
    "qwer", "asdf", "zxcv", "tyui", "ghjk", "bnm,",
    "qwertyu", "asdfghj", "zxcvbn", "wertyu", "sdfghj", "xcvbnm",
    "werty", "ertyu", "rtyui", "tyuio", "yuio", "sdfgh", "dfghj", "fghjk", "ghjkl",
    "xcvbn", "cvbnm", "qazwsx", "edcrfv", "tgbyhn", "ujmikol",
    "zaqwsx", "xswcde", "cdevfr", "vfrbgt", "bgtnhy", "nhyujm", "ujmki",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/",
    "1qaz2wsx", "2wsx3edc", "3edc4rfv", "4rfv5tgb", "5tgb6yhn",
    "1q2w3e4r", "1q2w3e", "2w3e4r", "3e4r5t", "4r5t6y", "5t6y7u", "6y7u8i", "7u8i9o", "8i9o0p",
    "qazxsw", "wsxedc", "edcrfv", "rfvtgb", "tgbyhn", "yhnujm", "ujmik,",
    "zaq12wsx", "xsw23edc", "cde34rfv", "vfr45tgb", "bgt56yhn",
    "qweasd", "asdzxc", "rtyfgh", "fghvbn", "uiophj", "hjklbn",
    "qaz123", "wsx123", "edc123", "rfv123", "tgb123", "yhn123", "ujm123",
    "qwe123", "asd123", "zxc123", "rty123", "fgh123", "vbn123",
    "qazwsxedc", "edcrfvtgb", "yhnujmikol", "zaqxswcde",
    "1qazse4", "plmoknijb", "plmko", "oknijb", "ijnuhb", "uhbygv",
    "q1w2e3r4", "a1s2d3f4", "z1x2c3v4", "q1w2e3", "a1s2d3", "z1x2c3",
    "qwert123", "asdfg123", "zxcvb123", "poiuy123", "lkjhg123", "mnbvc123",
    "qwerasdf", "asdfzxcv", "zxcvasdf", "asdfqwer", "qwertasdf",
    "qweqwe", "asdasd", "zxczxc", "rtyrty", "fghfgh", "vbnvbn",
    "qwerqwer", "asdfasdf", "zxcvzxcv", "tyuityui", "ghjkghjk",
    "1qazxsw2", "wsxedcrf", "3edcvfr4", "5tgbnhy6", "7ujmmko8",
    "0okm9ijn", "8uhb7ygv", "6tfc5rdx", "4esz3waq",
    "qazxswedc", "rfvtgbyhn", "ujmikolp", "plokmijn",
    "uhbygvtfc", "rdxeszwaq", "wsxzaq", "edcxsw", "rfvcde",
    "tgbvfr", "yhnbgt", "ujmnhy", "ikmujm", "olpiko",
    "qscesz", "wdvrfx", "etbtgy", "rynhui", "tujmko",
    "qazwsxedcrfv", "1qaz2wsx3edc", "4rfv5tgb6yhn",
    "qwertzuiop", "asdfghjkl;", "<zxcvbnm", "azertyuiop", "qsdfghjklm", "wxcvbn",
    "poiuztrewq", "mlkjhgfdsq", "nbvcxw", "123qwe", "123asd", "123zxc",
    "456qwe", "456asd", "456zxc", "789qwe", "789asd", "789zxc",
    "qwe456", "asd456", "zxc456", "qwe789", "asd789", "zxc789",
    "q1w2e3r4t5", "a1s2d3f4g5", "z1x2c3v4b5", "1a2s3d4f",
    "qweasd123", "asdzxc123", "qazwsx123", "zaqwsx123",
    "qweasdzxc", "zxcasdqwe", "plmokn123", "oknijb123",
    "ijnuhb123", "uhbygv123", "ygvtfc123", "tfcrdx123",
    "rdxesz123", "eszwaq123", "qazxsw123", "xswcde123",
    "cdevfr123", "vfrbgt123", "bgtnhy123", "nhyujm123",
    "ujmik123", "ikmol123", "olppol", "plmzaq", "zaqplm",
    "qwert12345", "asdfg12345", "zxcvb12345",
    "12345qwert", "12345asdfg", "12345zxcvb",
    "qwerty789", "asdfgh789", "zxcvbn789",
    "789qwerty", "789asdfgh", "789zxcvbn",
    "q1w2e3r4t5y6", "1q2w3e4r5t6y", "a1s2d3f4g5h6",
    "z1x2c3v4b5n6", "m,.-m,.-", "/.,m/.,m",
    "1q2w1q2w", "a1s2a1s2", "z1x2z1x2", "q2w3q2w3",
    "a2s3a2s3", "z2x3z2x3", "qwer1234", "asdf1234", "zxcv1234",
    "1234qwer", "1234asdf", "1234zxcv", "qwer5678", "asdf5678", "zxcv5678",
    "5678qwer", "5678asdf", "5678zxcv", "qwer90-=", "asdfghjkl;'",
    "`1234567890-=", "=-0987654321`", "qwertyuiop[]\\", "\\][poiuytrewq",
    "asdfghjkl;'\\", "';lkjhgfdsa", "zxcvbnm,./", "/.,mnbvcxz",
    "1a2b3c", "3c2b1a", "qwe1asd2", "zxc1asd2", "qaz2wsx3",
    "3edc4rfv5", "5tgb6yhn7", "7ujm8ik,9", "9ol.0p;/=",
    "qsceszwdv", "rfxetbynh", "ujmikoplm", "zaq1xsw2",
    "cde3vfr4", "bgt5nhy6", "ujm7ik8,", "ol9p0;/",
    "qwertyy", "asdfghh", "zxcvbnn", "poiuytt", "lkjhgff",
    "qqwweerr", "aassddff", "zzxxccvv", "11qq22ww", "33ee44rr",
    "55tt66yy", "77uu88ii", "99oo00pp", "qqwweerrtt", "aassddffgg",
    "zzxxccvvbb", "1qaz3edc", "2wsx4rfv", "3edc5tgb", "4rfv6yhn",
    "5tgb7ujm", "6yhn8ik,", "7ujm9ol.", "8ik,0p;/",
    "qawsedrf", "tgbyhnuj", "mikolp;[", "plokmijn", "uhbygvtfc",
    "qazsedcft", "wsxrfvgyh", "edctgbyuj", "rfvyhnmik",
    "tgzujmkol", "yhnikmopl", "zaq3edc", "xsw4rfv", "cde5tgb",
    "vfr6yhn", "bgt7ujm", "nhy8ik,", "ujm9ol.", "ikm0p;/",
    "1qazxsw", "2wsxedc", "3edcrfv", "4rfvtgb", "5tgbyhn",
    "6yhnujm", "7ujmik,", "8ik,ol.", "9ol.p;/",
    "qwerzxcv", "asdfqwer", "zxcvqwer", "poiuljkh",
    "lkjhmnbv", "mnbvlkjh", "qazwsxedcrfvtgb",
    "1qaz2wsx3edc4rfv", "5tgb6yhn7ujm8ik,",
    "qwertypoiuy", "asdfghjkl;'", "zxcvbnm,.-",
    "123456qwerty", "qwerty123456", "asdfgh123456", "123456asdfgh",
    "zxcvbn123456", "123456zxcvbn", "poiuyt123456", "123456poiuyt",
    "lkjhgf123456", "123456lkjhgf", "mnbvcx123456", "123456mnbvcx",
    "qwe123rty", "asd123fgh", "zxc123vbn",
    "qaz123wsx", "edc123rfv", "tgb123yhn", "ujm123iko",
    "1qaz0okm", "2wsx9ijn", "3edc8uhb", "4rfv7ygv", "5tgb6tfc",
    "qwert11", "asdfg22", "zxcvb33", "poiuy44", "lkjhg55",
    "mnbvc66", "qazws77", "edcrf88", "tgbyh99", "ujmik00"
]
print(f"Base keyboard patterns count: {len(keyboard_raw)}")
