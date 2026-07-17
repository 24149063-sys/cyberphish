"""
train_model.py
--------------
Trains a phishing-URL detection model.

Pipeline:
  1. Build (or load) a labeled dataset of URLs -> {phishing, legitimate}
  2. Convert URLs into character n-gram TF-IDF features
  3. Train a Logistic Regression classifier
  4. Persist the fitted vectorizer and model as model.pkl / vectorizer.pkl
     in the project root, so app.py can load them at runtime.

Run:
    python models/train_model.py
"""

import os
import random
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

RANDOM_STATE = 42
random.seed(RANDOM_STATE)

# ---------------------------------------------------------------------------
# 1. Dataset
# ---------------------------------------------------------------------------
# In a real deployment you would load a large labeled dataset (e.g. PhishTank
# + Tranco/Alexa top sites) from database/phishing.sql or a CSV. Here we
# generate a representative synthetic dataset so the project runs end-to-end
# out of the box. Swap `load_dataset()` for a real data source when available.

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "nytimes.com", "bbc.co.uk", "linkedin.com", "stackoverflow.com",
    "python.org", "mozilla.org", "cloudflare.com", "reddit.com", "spotify.com",
    "netflix.com", "dropbox.com", "adobe.com", "yahoo.com", "twitter.com",
]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/products", "/login", "/account",
    "/search?q=news", "/docs/reference", "/blog/2024/update", "/help/faq",
]

PHISH_KEYWORDS = [
    "secure", "account", "update", "verify", "login", "signin", "confirm",
    "banking", "wallet", "support", "alert", "suspend", "reset-password",
]

PHISH_BRANDS = [
    "paypal", "apple", "amazon", "microsoft", "netflix", "bankofamerica",
    "wellsfargo", "chase", "google", "facebook", "instagram", "irs",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    return f"{scheme}://www.{domain}{path}"


def make_phishing_url():
    brand = random.choice(PHISH_BRANDS)
    keyword = random.choice(PHISH_KEYWORDS)
    pattern = random.choice([1, 2, 3, 4, 5])

    if pattern == 1:
        # Brand name stuffed into a suspicious free-domain
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{brand}-{keyword}{tld}/{keyword}/login.php"
    elif pattern == 2:
        # Raw IP address host
        return f"http://{random_ip()}/{brand}/{keyword}-account.html"
    elif pattern == 3:
        # Long, hyphen-heavy subdomain trying to impersonate the brand
        return f"http://{brand}.{keyword}-{keyword}-secure.com/{keyword}"
    elif pattern == 4:
        # Extra subdomains + suspicious keyword before the real-looking path
        return f"http://{keyword}.{brand}.{random.choice(['info','support-center'])}.com/verify"
    else:
        # @ symbol trick (browser ignores everything before @)
        return f"http://{brand}.com@{keyword}-{random.randint(100,999)}.net/login"


def load_dataset(n_per_class=600):
    urls, labels = [], []
    for _ in range(n_per_class):
        urls.append(make_legit_url())
        labels.append(0)  # 0 = legitimate
        urls.append(make_phishing_url())
        labels.append(1)  # 1 = phishing
    return urls, labels


def main():
    print("[1/4] Building dataset ...")
    urls, labels = load_dataset()
    print(f"      total samples: {len(urls)}")

    X_train, X_test, y_train, y_test = train_test_split(
        urls, labels, test_size=0.2, random_state=RANDOM_STATE, stratify=labels
    )

    print("[2/4] Vectorizing URLs (character n-grams, TF-IDF) ...")
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=5000,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("[3/4] Training classifier (Logistic Regression) ...")
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)
    print("\n--- Evaluation on held-out test set ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    print("[4/4] Saving model.pkl and vectorizer.pkl to project root ...")
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(project_root, "model.pkl"), "wb") as f:
        pickle.dump(model, f)
    with open(os.path.join(project_root, "vectorizer.pkl"), "wb") as f:
        pickle.dump(vectorizer, f)

    print("Done. Artifacts written:")
    print(f"  - {os.path.join(project_root, 'model.pkl')}")
    print(f"  - {os.path.join(project_root, 'vectorizer.pkl')}")


if __name__ == "__main__":
    main()
