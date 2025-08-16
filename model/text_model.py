from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re

class TextThreatClassifier:
    def __init__(self, model_name="unitary/toxic-bert"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self.labels = ["Safe", "Threat"]  # toxic-bert is binary: 0=non-toxic, 1=toxic

    def predict(self, text):
        # Money keyword detection
        money_keywords = [r"\$\d+", r"₹\d+", r"rs\.?\s*\d+", r"transfer", r"payment", r"account", r"bank"]
        for kw in money_keywords:
            if re.search(kw, text, re.IGNORECASE):
                return "Offensive", "❗"
        # Threat keyword detection (fallback)
        threat_keywords = [r"\bkill\b", r"\battack\b", r"\bbomb\b", r"\bshoot\b", r"\bdie\b", r"\bmurder\b", r"\bthreat\b", r"\bharm\b"]
        for kw in threat_keywords:
            if re.search(kw, text, re.IGNORECASE):
                return "Threat", "⚠"
        # Model prediction
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True)
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.sigmoid(outputs.logits).cpu().numpy()[0]
            # toxic-bert: output is probability of toxicity
            if probs[0] > 0.5:
                return "Threat", "⚠"
            else:
                return "Safe", "✅"