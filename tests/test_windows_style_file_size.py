from xanalyzer.file import FileAnalyzer


def test_windows_style_file_size():
    size_result_list = [
        (0, '0 字节'),
        (1, '1 字节 (1 字节)'),
        (999, '999 字节 (999 字节)'),
        (1023, '1023 字节 (1,023 字节)'),
        (1024, '1.00 KB (1,024 字节)'),
        (1025, '1.00 KB (1,025 字节)'),
        (2000, '1.95 KB (2,000 字节)'),
        (20000, '19.5 KB (20,000 字节)'),
        (200000, '195 KB (200,000 字节)'),
        (2000000, '1.90 MB (2,000,000 字节)'),
        (20000000, '19.0 MB (20,000,000 字节)'),
        (2000000000, '1.86 GB (2,000,000,000 字节)'),
    ]

    for the_size, except_formatted_size in size_result_list:
        the_formatted_size = FileAnalyzer.get_windows_style_file_size(the_size)
        assert the_formatted_size == except_formatted_size
