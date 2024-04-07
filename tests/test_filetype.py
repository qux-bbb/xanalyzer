from pathlib import Path
from xanalyzer.file import FileAnalyzer

cur_dir_path = Path(__file__).parent


def test_common_filetype():
    upxed_path = cur_dir_path / "test_data" / "Hello_upx.exe_"
    file_analyzer = FileAnalyzer(upxed_path)
    assert (
        file_analyzer.file_type
        == "PE32 executable (console) Intel 80386, for MS Windows, UPX compressed"
    )


def test_chinese_name_filetype():
    chinese_name_path = cur_dir_path / "test_data" / "中文名测试.txt"
    file_analyzer = FileAnalyzer(chinese_name_path)
    assert file_analyzer.file_type == "UTF-8 Unicode text, with no line terminators"


def test_wps_docx_filetype():
    chinese_name_path = cur_dir_path / "test_data" / "wps.docx_"
    file_analyzer = FileAnalyzer(chinese_name_path)
    assert file_analyzer.file_type == "Microsoft Word 2007+"


def test_wps_xlsx_filetype():
    chinese_name_path = cur_dir_path / "test_data" / "wps.xlsx_"
    file_analyzer = FileAnalyzer(chinese_name_path)
    assert file_analyzer.file_type == "Microsoft Excel 2007+"


def test_wps_pptx_filetype():
    chinese_name_path = cur_dir_path / "test_data" / "wps.pptx_"
    file_analyzer = FileAnalyzer(chinese_name_path)
    assert file_analyzer.file_type == "Microsoft PowerPoint 2007+"


def test_many_filetypes():
    filenames = [
        # Windows可执行文件
        "Hello64.exe_",
        "Hello64.dll_",
        "Hello64.sys_",
        "Hello32.exe_",
        "Hello32.dll_",
        "Hello32.sys_",
        # 一些Windows程序安装包
        "SetupTest.msi_",
        # 安卓
        "app-debug.apk_",
        # pdf
        "hello.pdf_",
        # 图片
        "hello.png_",
        "hello.jpg_",
        "hello.bmp_",
        "hello.gif_",
        # 音频
        "hello.mp3_",
        # 视频
        "hello.mp4_",
        "hello.flv_",
        "hello.avi_",
        # office文档
        "office.doc_",
        "office.xls_",
        "office.ppt_",
        "office.docx_",
        "office.xlsx_",
        "office.pptx_",
        # WPS创建的office2007+文档
        "wps.docx_",
        "wps.xlsx_",
        "wps.pptx_",
        # 常用压缩包
        "hello.zip_",
        "hello.7z_",
        "hello.rar_",
        # 流量包文件
        "http.pcap_",
        "http.pcapng_",
        # linux shell 脚本文件
        "hello_bash.sh_",
        "hello_sh.sh_",
    ]
    for filename in filenames:
        expect_ext = ["." + filename[:-1].split(".")[1]]
        file_path = cur_dir_path / "test_data" / filename
        file_analyzer = FileAnalyzer(file_path)
        assert file_analyzer.possible_extension_names == expect_ext

    for filename in ["wps.doc_", "wps.wps_"]:
        file_path = cur_dir_path / "test_data" / filename
        file_analyzer = FileAnalyzer(file_path)
        assert file_analyzer.possible_extension_names == [".doc", ".wps"]

    for filename in ["wps.xls_", "wps.et_"]:
        file_path = cur_dir_path / "test_data" / filename
        file_analyzer = FileAnalyzer(file_path)
        assert file_analyzer.possible_extension_names == [".xls", ".et"]

    for filename in ["wps.ppt_", "wps.dps_"]:
        file_path = cur_dir_path / "test_data" / filename
        file_analyzer = FileAnalyzer(file_path)
        assert file_analyzer.possible_extension_names == [".ppt", ".dps"]

    file_path = cur_dir_path / "test_data" / "hello.tar.gz_"
    file_analyzer = FileAnalyzer(file_path)
    assert file_analyzer.possible_extension_names == [".gz", ".tar.gz"]
