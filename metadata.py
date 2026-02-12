from email import policy
from email.parser import BytesParser
import sys
sys.stdout.reconfigure(encoding='utf-8')


def extract_domain(email_header):
    if email_header and "@" in email_header:
        return email_header.split("@")[-1].replace(">", "").strip()
    return None


# 1️⃣ Load email
def load_email(file):
    with open(file, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


# 2️⃣ Extract metadata
def extract_metadata(msg):
    from_header = msg.get("From")
    return_path = msg.get("Return-Path")

    metadata = {
        "from": from_header,
        "to": msg.get("To"),
        "cc": msg.get("Cc"),
        "bcc": msg.get("Bcc"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "return_path": return_path,
        "reply_to": msg.get("Reply-To"),
        "message_id": msg.get("Message-ID"),
        "authentication_results": msg.get("Authentication-Results"),
        "received": msg.get_all("Received") or [],
        "content_type": msg.get("Content-Type"),
        "mime_version": msg.get("MIME-Version"),
        "x_mailer": msg.get("X-Mailer"),
        "x_originating_ip": msg.get("X-Originating-IP")
    }

    # Extract domains (useful for phishing detection)
    metadata["from_domain"] = extract_domain(from_header)
    metadata["return_path_domain"] = extract_domain(return_path)

    # Detect From vs Reply-To mismatch
    metadata["reply_to_mismatch"] = (
        metadata["reply_to"] is not None
        and metadata["reply_to"] != from_header
    )

    return metadata


# 3️⃣ Decode body
def decode_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                return part.get_content()
    else:
        return msg.get_content()

    return ""


# 4️⃣ Master function
def analyze_email(file):
    msg = load_email(file)

    metadata = extract_metadata(msg)
    body = decode_body(msg)

    return {
        "metadata": metadata,
        "body": body
    }


if __name__ == "__main__":
    result = analyze_email("sample.eml")

    print("=== METADATA ===")
    for key, value in result["metadata"].items():
        print(f"{key}: {value}")

    print("\n=== BODY ===")
    print(result["body"])
