rule test_rule2 {
    meta:
        author = "Dan Dreadless"
        date_create = "06/07/2024"
        description = "test rule"
    strings:
        $str1 = "test2@email.com"
        $str2 = "SFDLVASFK"
    condition:
        all of them
}