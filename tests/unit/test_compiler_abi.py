import pytest

from aletheia.corpus.abi import parse_abi


def test_optimized_ir_types_attributes_and_variadic_contract():
    ir = """
define dso_local zeroext i1 @flag(ptr noundef %p, i64 noundef %n) local_unnamed_addr #0 {
define internal fastcc void @state(ptr sret(%struct.Context) align 8 %ctx, i8 zeroext %x) #1 {
define dso_local double @number(float %value, ...) #0 {
define dso_local <4 x i32> @vector(<2 x i64> %value) #0 {
"""
    abi = parse_abi(ir)
    assert abi["flag"]["return"] == {"class": "int", "width": 8}
    assert abi["flag"]["params"] == [{"class": "ptr", "width": 64}, {"class": "int", "width": 64}]
    assert abi["flag"]["abi_complex"] is False
    assert abi["state"]["abi_complex"] is True
    assert abi["number"]["variadic"] is True
    assert abi["vector"]["return"] == {"class": "other", "width": 128, "declared": "<4 x i32>"}
    assert abi["vector"]["abi_complex"] is True


def test_duplicate_or_unparseable_definitions_fail_explicitly():
    with pytest.raises(ValueError, match="duplicate"):
        parse_abi("define void @f() {\ndefine i32 @f() {")
    with pytest.raises(ValueError, match="definition"):
        parse_abi("define malformed")
