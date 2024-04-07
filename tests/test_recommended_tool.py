from pathlib import Path
from xanalyzer.file import FileAnalyzer
from xanalyzer.file_process.pe import PeAnalyzer

cur_dir_path = Path(__file__).parent


def test_recommended_innounp():
    pe_path = cur_dir_path / "test_data" / "Inno_mysetup.exe_"
    file_analyzer = FileAnalyzer(pe_path)
    pe_analyzer = PeAnalyzer(file_analyzer)
    file_analyzer.pe_versioninfo = pe_analyzer.get_versioninfo()
    tool_recommendations = file_analyzer.get_tool_recommendations()
    assert "Innounp: https://innounp.sourceforge.net" in tool_recommendations


def test_recommended_lessmsi():
    msi_path = cur_dir_path / "test_data" / "SetupTest.msi_"
    file_analyzer = FileAnalyzer(msi_path)
    tool_recommendations = file_analyzer.get_tool_recommendations()
    assert "lessmsi: http://lessmsi.activescott.com" in tool_recommendations


def test_recommended_7z_build_nsis():
    pe_path = cur_dir_path / "test_data" / "nsis_example1.exe_"
    file_analyzer = FileAnalyzer(pe_path)
    tool_recommendations = file_analyzer.get_tool_recommendations()
    assert (
        "7z-build-nsis: https://github.com/myfreeer/7z-build-nsis"
        in tool_recommendations
    )
