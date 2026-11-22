"""La demo final es también una prueba de extremo a extremo del sistema."""

import demo_final


def test_demo_final_todas_las_comprobaciones(tmp_path):
    salida = []
    assert demo_final.ejecutar(tmp_path / "demo", imprimir=salida.append) is True
    assert any("Resultado:" in linea for linea in salida)
