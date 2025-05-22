import os
import faiss
import numpy as np
from transformers import AutoTokenizer, AutoModel
import pdfplumber
from docx import Document
import torch

class DocProcessor:
    def __init__(self, app):
        self.app = app
        self.doc_path = self.app.config_manager.get_config().get("doc_path", "/home/lxcxjxhx/PROJECT/INTEL-SE/docs")
        self.cache_dir = os.getenv("HF_HOME", "/home/lxcxjxhx/PROJECT/INTEL-SE/cache")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased", cache_dir=self.cache_dir, token=None, local_files_only=True)
            self.model = AutoModel.from_pretrained("distilbert-base-uncased", cache_dir=self.cache_dir, token=None, local_files_only=True)
            self.index = faiss.IndexFlatL2(768)
            self.doc_texts = []
            self.doc_names = []
            self.app.log_event("DOC_INIT", "DocProcessor 初始化成功")
        except Exception as e:
            self.app.log_event("DOC_ERROR", f"DocProcessor 初始化失败：{str(e)}")
            raise

    def update_doc_path(self, doc_path):
        self.doc_path = doc_path
        self.doc_texts = []
        self.doc_names = []
        self.index = faiss.IndexFlatL2(768)
        self.app.log_event("CONFIG_UPDATE", f"RAG文档路径更新为：{doc_path}")

    def process_docs(self):
        self.doc_texts = []
        self.doc_names = []
        self.index = faiss.IndexFlatL2(768)
        for filename in os.listdir(self.doc_path):
            file_path = os.path.join(self.doc_path, filename)
            try:
                if filename.endswith(".pdf"):
                    with pdfplumber.open(file_path) as pdf:
                        text = "".join(page.extract_text() or "" for page in pdf.pages)
                elif filename.endswith(".docx"):
                    doc = Document(file_path)
                    text = " ".join(paragraph.text for paragraph in doc.paragraphs)
                else:
                    continue
                self.doc_texts.append(text)
                self.doc_names.append(filename)
                embedding = self.get_embedding(text)
                self.index.add(np.array([embedding]))
                self.app.log_event("DOC_PROCESS", f"文档已处理：{filename}")
            except Exception as e:
                self.app.log_event("DOC_ERROR", f"处理文档 {filename} 失败：{str(e)}")
        return f"已处理 {len(self.doc_texts)} 个文档"

    def get_embedding(self, text):
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True, clean_up_tokenization_spaces=True)
        with torch.no_grad():
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1).squeeze().numpy()

    def rag_query(self, query):
        try:
            query_embedding = self.get_embedding(query)
            distances, indices = self.index.search(np.array([query_embedding]), 1)
            if indices[0][0] != -1:
                doc_name = self.doc_names[indices[0][0]]
                doc_text = self.doc_texts[indices[0][0]]
                snippet = doc_text[:200] + "..." if len(doc_text) > 200 else doc_text
                return f"文档：{doc_name}\n内容片段：{snippet}"
            return "未找到相关文档"
        except Exception as e:
            self.app.log_event("RAG_ERROR", f"RAG查询失败：{str(e)}")
            return f"RAG查询错误：{str(e)}"
