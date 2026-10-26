"""Legacy compatibility shim for iriscore.nmapio."""
from inmapcore.nmapio import parse_xml, coverage, compare, network_assessment, render_html, save_report

__all__ = ['parse_xml', 'coverage', 'compare', 'network_assessment', 'render_html', 'save_report']
