rule test_rule {
    meta:
        author = "Dan Dreadless"
        date_create = "06/07/2024"
        description = "test rule"
    strings:
        $str1 = "standalone"
        $str2 = "encoding"
    condition:
        $str1 or $str2
}