"""Actual repository target. The unfixed main branch retains the known defect."""
from pathlib import Path
import pytest
from policy import BASE, valid_source


@pytest.mark.parametrize('subtotal,expected', [(0, 0), (100, 110), (25.5, 28.05)])
def test_invoice_total(subtotal, expected):
    source = Path('src/invoice.py').read_text()
    assert valid_source(source), 'Fail before importing any generated source'
    if source == BASE:
        pytest.xfail('Unfixed baseline: intentionally retains the invoice defect')
    # Only AST-validated arithmetic may reach this import in the isolated CI worker.
    from src.invoice import total
    assert total(subtotal) == pytest.approx(expected)
