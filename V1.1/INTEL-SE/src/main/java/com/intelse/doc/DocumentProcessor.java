package com.intelse.doc;

import com.intelse.config.ConfigManager;
import com.intelse.log.LogManager;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DocumentProcessor {
    private final String docDir;

    public DocumentProcessor() {
        this.docDir = ConfigManager.getInstance().getDocDir();
    }

    public String processDocuments() {
        try {
            File dir = new File(docDir);
            if (!dir.exists() || !dir.isDirectory()) {
                String error = "Document directory not found: " + docDir;
                LogManager.logEvent("LOG_ERROR", error);
                return error;
            }

            StringBuilder result = new StringBuilder();
            for (File file : dir.listFiles((d, name) -> name.endsWith(".pdf") || name.endsWith(".docx"))) {
                String text = extractText(file);
                result.append("Processed ").append(file.getName()).append(": ").append(text.length()).append(" chars\n");
                LogManager.logEvent("ATTACK_RESULT", "Processed document: " + file.getName());
            }
            return result.length() > 0 ? result.toString() : "No documents found";
        } catch (Exception e) {
            String error = "Document processing error: " + e.getMessage();
            LogManager.logEvent("LOG_ERROR", error);
            return error;
        }
    }

    private String extractText(File file) throws Exception {
        if (file.getName().endsWith(".pdf")) {
            try (PDDocument document = PDDocument.load(file)) {
                PDFTextStripper stripper = new PDFTextStripper();
                return stripper.getText(document);
            }
        } else if (file.getName().endsWith(".docx")) {
            try (FileInputStream fis = new FileInputStream(file);
                 XWPFDocument document = new XWPFDocument(fis)) {
                XWPFWordExtractor extractor = new XWPFWordExtractor(document);
                return extractor.getText();
            }
        }
        return "";
    }
}
