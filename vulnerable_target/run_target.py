from app import app # type: ignore

if __name__ == '__main__':
    print("[+] Vulnerable Flask Chatbot running on http://localhost:5001")
    print("[+] Chat endpoint: POST http://localhost:5001/chat")
    print("[+] Body: { \"message\": \"your prompt here\" }")
    app.run(host='0.0.0.0', port=5001, debug=False)