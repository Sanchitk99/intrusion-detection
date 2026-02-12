import pandas as pd
import joblib
import os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
df = pd.read_csv(os.path.join(BASE_DIR, "data", "nsl_kdd.csv"))

attack_map = {
    'neptune':'DoS','smurf':'DoS','back':'DoS','teardrop':'DoS','pod':'DoS',
    'land':'DoS','apache2':'DoS','udpstorm':'DoS','mailbomb':'DoS',
    'processtable':'DoS',

    'satan':'Probe','ipsweep':'Probe','nmap':'Probe','portsweep':'Probe',
    'mscan':'Probe','saint':'Probe',

    'guess_passwd':'R2L','ftp_write':'R2L','imap':'R2L','phf':'R2L',
    'multihop':'R2L','warezmaster':'R2L','warezclient':'R2L',
    'spy':'R2L','xlock':'R2L','xsnoop':'R2L',

    'buffer_overflow':'U2R','loadmodule':'U2R','rootkit':'U2R',
    'perl':'U2R','sqlattack':'U2R','xterm':'U2R'
}

def map_label(x):
    if x == "normal":
        return "Normal"
    return attack_map.get(x, "Other")

df["attack_type"] = df["label"].apply(map_label)
df.drop(columns=["label"], inplace=True)

cat_cols = ["protocol_type", "service", "flag"]
encoders = {}

for col in cat_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

attack_encoder = LabelEncoder()
y = attack_encoder.fit_transform(df["attack_type"])
X = df.drop(columns=["attack_type"])

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

print(classification_report(y_test, model.predict(X_test)))

joblib.dump(model, os.path.join(BASE_DIR, "model.pkl"))
joblib.dump(scaler, os.path.join(BASE_DIR, "scaler.pkl"))
joblib.dump(encoders, os.path.join(BASE_DIR, "encoders.pkl"))
joblib.dump(attack_encoder, os.path.join(BASE_DIR, "attack_encoder.pkl"))

print("Training complete. All files saved.")
