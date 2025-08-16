Cyber Watch - Emotion-Aware Cybersecurity

Cyber Watch is a desktop application that combines text, email, chat, file, face, and voice analysis to detect potential threats and offensive content. It leverages machine learning models, natural language processing, and user interaction monitoring to provide an advanced cybersecurity solution with a modern UI built in Tkinter.

🚀 Features
🔹 Text Analyzer

Analyze typed text for safe / offensive / threat content.

Detect monetary amounts and verify authenticity with user confirmation.

🔹 Gmail Threat Scanner

Connects with Google Gmail API to scan your emails.

Flags suspicious content in subject, sender, and body.

Supports filtering (all / read / unread) and customizable scan limits.

🔹 Chat Monitor

Analyze chat conversations line by line.

Classifies each message as Safe, Offensive, or Threat.

Highlights results in different colors for easy interpretation.

🔹 File Scanner

Supports .txt, .pdf, .docx files.

Extracts text and classifies it as Safe / Offensive / Threat.

Highlights suspicious keywords like transfer, payment, bank, ₹, $.

Option to export flagged content to a text/CSV file.

🔹 Face Analyzer

Captures image via webcam.

Detects faces using OpenCV Haar Cascades.

Simulates emotion detection (Happy, Sad, Angry, Neutral, Surprise).

🔹 Voice Analyzer (Prototype)

Records 5 seconds of audio from your microphone.

Simulates classification (Safe, Offensive, Threat).

Future scope: integrate with speech recognition / deep learning models.

🛠️ Tech Stack

Language: Python 3.x

UI Framework: Tkinter (with modern theming)

Libraries:

opencv-python (Face detection)

Pillow (Image handling)

sounddevice, scipy (Voice recording)

google-api-python-client, google-auth-oauthlib, pickle (Gmail API)

winsound (Audio alerts, Windows only)

Custom: model.text_model.TextThreatClassifier, utils.file_utils.extract_text_from_file
