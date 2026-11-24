from iampath.rules import RULE_KINDS


def test_rule_kinds_match_the_design():
    expected = {number: "grant" for number in range(1, 10)}
    expected.update({number: "reach" for number in range(10, 22)})
    assert RULE_KINDS == expected
