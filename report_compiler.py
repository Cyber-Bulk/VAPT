from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
from utils.logger import setup_logger
import logging

setup_logger()

class ReportCompiler:
    def __init__(self, filename):
        self.filename = filename
        self.canvas = canvas.Canvas(self.filename, pagesize=letter)
        self.width, self.height = letter

    def add_title(self, title):
        self.canvas.setFont("Helvetica-Bold", 24)
        self.canvas.drawString(100, self.height - 100, title)
        self.canvas.setFont("Helvetica", 12)

    def add_section(self, title, content):
        self.canvas.drawString(100, self.height - 150, title)
        self.canvas.drawString(100, self.height - 170, content)
        self.canvas.showPage()

    def save(self):
        self.canvas.save()
        logging.info(f"Report saved as {self.filename}")

def compile_report(report_data):
    report_filename = "penetration_test_report.pdf"
    compiler = ReportCompiler(report_filename)
    compiler.add_title("Penetration Test Report")
    
    for section_title, section_content in report_data.items():
        compiler.add_section(section_title, section_content)
    
    compiler.save()