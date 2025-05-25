from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
c = canvas.Canvas("/home/lxcxjxhx/PROJECT/INTEL-SE/docs/test.pdf", pagesize=A4)
c.setFont("Helvetica", 12)
c.drawString(100, 800, "这是一个测试PDF文档，用于RAG查询。")
c.drawString(100, 780, "内容包括信息安全和SQL注入的相关信息。")
c.drawString(100, 760, "SQL注入是一种常见的网络攻击方式，通过在输入字段中插入恶意SQL代码来操纵数据库。")
c.showPage()
c.save()
