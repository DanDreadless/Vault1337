rule test_rule {
    meta:
        author = "Dan Dreadless"
        date_create = "06/07/2024"
        description = "test rule"
    strings:
        $str1 = "192.168.0.56"
        $str2 = "DFVLKJADFVA"
    condition:
        any of them
}