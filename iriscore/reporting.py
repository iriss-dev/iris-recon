"""Legacy compatibility shim for iriscore.reporting."""
from inmapcore.reporting import SCRIPT, CSS, esc, table, render_assessment, csv_cell, save_assessment

__all__ = ['SCRIPT', 'CSS', 'esc', 'table', 'render_assessment', 'csv_cell', 'save_assessment']
