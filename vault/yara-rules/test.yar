rule test_rule {
    meta:
        author = "Dan Dreadless"
        date_create = "06/07/2024"
        description = "test rule"
    strings:
        $str1 = "10.10.10.10"
        $str2 = "DFVLKJADFVA"
    condition:
        any of them
}