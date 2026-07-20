from scripts.patch_deepspeed_zero3_dtype import apply_patch, is_patched, restore


def test_deepspeed_patch_is_reversible(tmp_path):
    source = tmp_path / "partition_parameters.py"
    original = """
for psize in partition_sizes:
    x = empty(dtype=param_list[0].ds_tensor.dtype)
for psize in quantize_scale_sizes:
    y = empty(dtype=param_list[0].ds_tensor.ds_quant_scale.dtype)
"""
    source.write_text(original, encoding="utf-8")

    apply_patch(source)
    assert is_patched(source.read_text(encoding="utf-8"))

    restore(source)
    assert source.read_text(encoding="utf-8") == original
