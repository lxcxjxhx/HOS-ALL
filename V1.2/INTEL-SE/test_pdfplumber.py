import pdfplumber
with pdfplumber.open('/home/lxcxjxhx/PROJECT/INTEL-SE/docs/test.pdf') as pdf:
    text = ''.join(page.extract_text() or '' for page in pdf.pages)
    print(text)
