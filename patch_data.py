with open("shared/data_access.py", "r") as f:
    text = f.read()

# Fix infinite memory growth
if "self.alerts.append(alert)" in text and "len(self.alerts) > 1000" not in text:
    text = text.replace("self.alerts.append(alert)", "self.alerts.append(alert)\n            if len(self.alerts) > 1000: self.alerts = self.alerts[-1000:]")

with open("shared/data_access.py", "w") as f:
    f.write(text)
