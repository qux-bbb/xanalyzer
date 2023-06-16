import "pe"

rule UPX_PE {
    meta:
        description = "Detect common UPX"
        author = "qux"
        date = "2023-06-16"
        hash1 = "d32e87c4b81738b45db582db8293293096637f5d50af7dd5d9a0162a0747498a"
    condition:
        pe.is_pe
        and pe.number_of_sections == 3
        and pe.sections[0].name == "UPX0"
        and pe.sections[1].name == "UPX1"
        and pe.sections[2].name == "UPX2"
}