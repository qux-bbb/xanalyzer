from xanalyzer.utils import log


class JpgAnalyzer:
    file_analyzer = None

    def __init__(self, file_analyzer):
        self.file_analyzer = file_analyzer

    def get_weird_jpg_info(self):
        """
        获取jpg可疑文件尾信息
        """
        weird_jpg_info = {"is_weird": False, "has_ffd9": True}

        the_file = open(self.file_analyzer.file_path, "rb")
        the_content = the_file.read()
        the_file.close()

        if the_content.endswith(b"\xff\xd9"):
            return weird_jpg_info

        weird_jpg_info["is_weird"] = True
        last_ffd9_pos = the_content.rfind(b"\xff\xd9")
        if last_ffd9_pos == -1:
            weird_jpg_info["has_ffd9"] = False
        else:
            possible_jpg_size = last_ffd9_pos + 2
            possible_extra_size = len(the_content) - possible_jpg_size
            tail = the_content[last_ffd9_pos + 2 :]
            if len(tail) < 6:
                extra = tail
            else:
                extra = tail[:6] + b"..."
            weird_jpg_info["possible_jpg_size"] = possible_jpg_size
            weird_jpg_info["possible_extra_size"] = possible_extra_size
            weird_jpg_info["extra"] = extra
        
        return weird_jpg_info

    def jpg_tail_scan(self):
        """
        判断jpg文件结尾是否异常
        """
        weird_jpg_info = self.get_weird_jpg_info()
        if weird_jpg_info.get("is_weird"):
            if not weird_jpg_info.get("has_ffd9"):
                log.warning(f"jpg weird tail not endswith FFD9 and not contain FFD9")
            else:
                possible_jpg_size = weird_jpg_info.get("possible_jpg_size")
                possible_extra_size = weird_jpg_info.get("possible_extra_size")
                extra = weird_jpg_info.get("extra")
                log.warning(
                    f"jpg weird tail not endswith FFD9, possible_jpg_size={possible_jpg_size}, possible_extra_size={possible_extra_size}, extra={extra}"
                )

    def run(self):
        self.jpg_tail_scan()
